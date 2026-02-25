#include "lsa/DpapiWalker.h"

#include "lsa/LsaReaderUtils.h"

#include <algorithm>
#include <iomanip>
#include <set>
#include <sstream>
#include <vector>

namespace KvcForensic::lsa {

DpapiWalker::DpapiWalker(
    const core::VirtualMemory& vmem,
    const minidump::MinidumpMetadata& metadata,
    security::LsaSecretsExtractor* extractor,
    const templates::DpapiTemplateSpec* tmpl)
    : vmem_(vmem), metadata_(metadata), extractor_(extractor), tmpl_(tmpl) {}

void DpapiWalker::Walk(std::vector<LogonSession>& sessions) {
    if (tmpl_ == nullptr || tmpl_->signature.empty()) return;

    const auto& sig = tmpl_->signature;
    const int feo   = tmpl_->first_entry_offset;

    // Collect all occurrences of sig within a module's mapped VA ranges.
    auto collect_in_module = [&](const std::wstring& module_name,
                                  std::vector<std::uint64_t>& out) {
        const minidump::ModuleInfo* mod = nullptr;
        for (const auto& m : metadata_.modules) {
            std::wstring nl = m.name, sl = module_name;
            std::transform(nl.begin(), nl.end(), nl.begin(), ::towlower);
            std::transform(sl.begin(), sl.end(), sl.begin(), ::towlower);
            if (nl.find(sl) != std::wstring::npos) { mod = &m; break; }
        }
        if (!mod) return;
        for (const auto& range : metadata_.memory_ranges) {
            const std::uint64_t start = (std::max)(range.start_vva,
                static_cast<std::uint64_t>(mod->base_address));
            const std::uint64_t end = (std::min)(range.start_vva + range.size,
                static_cast<std::uint64_t>(mod->base_address + mod->size));
            if (start >= end || (end - start) < sig.size()) continue;
            std::vector<std::byte> chunk(end - start);
            if (!vmem_.ReadBytes(start, chunk.size(), chunk)) continue;
            for (std::size_t i = 0; i + sig.size() <= chunk.size(); ++i) {
                if (std::memcmp(chunk.data() + i, sig.data(), sig.size()) == 0)
                    out.push_back(start + i);
            }
        }
    };

    std::vector<std::uint64_t> all_candidates;
    collect_in_module(L"lsasrv.dll",  all_candidates);
    collect_in_module(L"dpapisrv.dll", all_candidates);
    collect_in_module(L"lsass.exe",    all_candidates);

    if (all_candidates.empty()) {
        constexpr std::size_t kMaxFallbackRangeBytes = 64u * 1024 * 1024;
        for (const auto& range : metadata_.memory_ranges) {
            if (range.size < sig.size() || range.size > kMaxFallbackRangeBytes) continue;
            std::vector<std::byte> chunk(range.size);
            if (!vmem_.ReadBytes(range.start_vva, chunk.size(), chunk)) continue;
            for (std::size_t i = 0; i + sig.size() <= chunk.size(); ++i) {
                if (std::memcmp(chunk.data() + i, sig.data(), sig.size()) == 0)
                    all_candidates.push_back(range.start_vva + i);
            }
        }
    }

    if (all_candidates.empty()) return;

    std::set<std::uint64_t> visited_entries;

    auto walk_one_list = [&](const std::uint64_t sentinel, const std::uint64_t first) {
        std::uint64_t current = first;
        int safety = 0;
        while (current != sentinel && current != 0 && safety++ < 4096) {
            if (visited_entries.count(current)) break;
            visited_entries.insert(current);

            // KIWI_MASTERKEY_CACHE_ENTRY:
            // Flink(8)+Blink(8)+LogonId(8 @+16)+KeyUid(16 @+24)+insertTime(8 @+40)+keySize(4 @+48)+key(@+52)
            std::uint64_t luid = 0;
            if (!vmem_.ReadStruct(current + 16, &luid)) break;

            std::vector<std::byte> guid_bytes(16);
            if (!vmem_.ReadBytes(current + 24, 16, guid_bytes)) break;

            std::uint32_t data1 = 0; std::uint16_t data2 = 0, data3 = 0;
            std::memcpy(&data1, guid_bytes.data(),     4);
            std::memcpy(&data2, guid_bytes.data() + 4, 2);
            std::memcpy(&data3, guid_bytes.data() + 6, 2);
            std::stringstream guid_ss;
            guid_ss << std::hex << std::setfill('0')
                    << std::setw(8) << data1 << "-"
                    << std::setw(4) << data2 << "-"
                    << std::setw(4) << data3 << "-";
            for (int i = 8; i < 16; ++i) {
                guid_ss << std::setw(2) << static_cast<int>(static_cast<unsigned char>(guid_bytes[i]));
                if (i == 9) guid_ss << "-";
            }
            const std::string key_guid = guid_ss.str();

            std::uint32_t key_size = 0;
            if (!vmem_.ReadStruct(current + 48, &key_size)) break;

            std::vector<std::byte> masterkey_encrypted;
            if (key_size > 0 && key_size < 512) {
                masterkey_encrypted.resize(key_size);
                if (!vmem_.ReadBytes(current + 52, key_size, masterkey_encrypted))
                    masterkey_encrypted.clear();
            }

            std::vector<std::byte> masterkey_decrypted;
            std::string sha1_masterkey;
            if (!masterkey_encrypted.empty() && extractor_ && extractor_->IsInitialized()) {
                masterkey_decrypted = extractor_->Decrypt(masterkey_encrypted);
                if (!masterkey_decrypted.empty())
                    sha1_masterkey = ComputeSha1(masterkey_decrypted);
            }

            if (luid != 0) {
                for (auto& s : sessions) {
                    if (s.authentication_id == luid) {
                        security::DpapiCredential cred;
                        cred.luid           = luid;
                        cred.key_guid       = key_guid;
                        cred.masterkey      = masterkey_decrypted.empty()
                                                ? masterkey_encrypted : masterkey_decrypted;
                        cred.sha1_masterkey = sha1_masterkey;
                        s.dpapi_credentials.push_back(cred);
                        break;
                    }
                }
            }

            std::uint64_t next = 0;
            if (!vmem_.ReadStruct(current, &next)) break;
            current = next;
        }
    };

    std::set<std::uint64_t> visited_sentinels;
    for (const std::uint64_t sp : all_candidates) {
        const std::uint64_t erl = sp + static_cast<std::int64_t>(feo);
        std::int32_t rel = 0;
        if (!vmem_.ReadStruct(erl, &rel)) continue;
        const std::uint64_t sentinel = erl + 4 + static_cast<std::int64_t>(rel);
        if (visited_sentinels.count(sentinel)) continue;
        visited_sentinels.insert(sentinel);
        std::uint64_t first = 0;
        if (!vmem_.ReadStruct(sentinel, &first)) continue;
        if (first == 0 || first == sentinel) continue;
        walk_one_list(sentinel, first);
    }
}

} // namespace KvcForensic::lsa
