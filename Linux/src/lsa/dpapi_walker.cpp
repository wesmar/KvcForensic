#include "lsa/dpapi_walker.h"

#include "core/crypto_backend.h"
#include "core/signature_scanner.h"

#include <cstring>
#include <iomanip>
#include <set>
#include <sstream>

namespace kvc::lsa {

DpapiWalker::DpapiWalker(const core::VirtualMemory& vmem,
                         const core::ModuleIndex& modules,
                         const security::LsaSecretsExtractor* extractor,
                         const templates::DpapiTemplateSpec* tmpl)
    : vmem_(vmem), modules_(modules), extractor_(extractor), tmpl_(tmpl) {}

void DpapiWalker::walk(std::vector<LogonSession>& sessions) const {
    if (!tmpl_ || tmpl_->signature.empty()) return;
    const auto& sig = tmpl_->signature;
    const int feo = tmpl_->first_entry_offset;

    std::vector<std::uint64_t> candidates;
    auto collect = [&](const char* name) {
        if (const auto* m = modules_.find(name)) {
            auto v = core::scan_module(vmem_, *m,
                std::span<const std::uint8_t>(sig.data(), sig.size()));
            candidates.insert(candidates.end(), v.begin(), v.end());
        }
    };
    collect("lsasrv.dll");
    collect("dpapisrv.dll");
    collect("lsass.exe");
    if (candidates.empty()) return;

    std::set<std::uint64_t> visited_entries;
    auto walk_list = [&](std::uint64_t sentinel, std::uint64_t first) {
        std::uint64_t current = first;
        for (int safety = 0; current != sentinel && current != 0 && safety < 4096; ++safety) {
            if (!visited_entries.insert(current).second) break;

            const std::uint64_t luid = vmem_.read_u64(current + 16).value_or(0);
            std::vector<std::byte> guid(16);
            if (!vmem_.read_bytes(current + 24, 16, guid)) break;

            std::uint32_t d1 = 0; std::uint16_t d2 = 0, d3 = 0;
            std::memcpy(&d1, guid.data(), 4);
            std::memcpy(&d2, guid.data() + 4, 2);
            std::memcpy(&d3, guid.data() + 6, 2);
            std::ostringstream ss;
            ss << std::hex << std::setfill('0')
               << std::setw(8) << d1 << "-"
               << std::setw(4) << d2 << "-"
               << std::setw(4) << d3 << "-";
            for (int i = 8; i < 16; ++i) {
                ss << std::setw(2) << static_cast<int>(static_cast<unsigned char>(guid[i]));
                if (i == 9) ss << "-";
            }
            const std::string key_guid = ss.str();

            const std::uint32_t key_size = vmem_.read_u32(current + 48).value_or(0);
            std::vector<std::byte> mk_enc;
            if (key_size > 0 && key_size < 512) {
                mk_enc.resize(key_size);
                if (!vmem_.read_bytes(current + 52, key_size, mk_enc)) mk_enc.clear();
            }

            std::vector<std::byte> mk_dec;
            std::string sha1_hex;
            if (!mk_enc.empty() && extractor_ && extractor_->is_initialized()) {
                mk_dec = extractor_->decrypt(mk_enc);
                if (!mk_dec.empty()) sha1_hex = core::CryptoBackend::sha1_hex(mk_dec);
            }

            if (luid != 0) {
                for (auto& s : sessions) {
                    if (s.authentication_id == luid) {
                        DpapiCredential c;
                        c.luid = luid;
                        c.key_guid = key_guid;
                        c.masterkey = mk_dec.empty() ? mk_enc : mk_dec;
                        c.sha1_masterkey = sha1_hex;
                        s.dpapi_credentials.push_back(std::move(c));
                        break;
                    }
                }
            }

            auto next = vmem_.read_u64(current);
            if (!next) break;
            current = *next;
        }
    };

    std::set<std::uint64_t> visited_sentinels;
    for (const std::uint64_t sp : candidates) {
        const std::uint64_t erl = sp + static_cast<std::int64_t>(feo);
        std::int32_t rel = 0;
        if (!vmem_.read_struct(erl, &rel)) continue;
        const std::uint64_t sentinel = erl + 4 + static_cast<std::int64_t>(rel);
        if (!visited_sentinels.insert(sentinel).second) continue;
        auto first = vmem_.read_u64(sentinel);
        if (!first || *first == 0 || *first == sentinel) continue;
        walk_list(sentinel, *first);
    }
}

} // namespace kvc::lsa
