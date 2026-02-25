#include "lsa/WdigestWalker.h"

#include "lsa/LsaReaderUtils.h"

#include <set>
#include <vector>

namespace KvcForensic::lsa {

WdigestWalker::WdigestWalker(
    const core::VirtualMemory& vmem,
    const minidump::MinidumpMetadata& metadata,
    security::LsaSecretsExtractor* extractor,
    const templates::WdigestTemplateSpec* tmpl)
    : vmem_(vmem), metadata_(metadata), extractor_(extractor), tmpl_(tmpl) {}

void WdigestWalker::Walk(std::vector<LogonSession>& sessions) {
    if (tmpl_ == nullptr || tmpl_->signature.empty()) return;

    const std::uint64_t sig_pos = FindSignatureInModule(
        vmem_, metadata_, L"wdigest.dll", tmpl_->signature);
    if (sig_pos == 0) return;

    const std::uint64_t entry_ref_loc =
        sig_pos + static_cast<std::int64_t>(tmpl_->first_entry_offset);
    std::int32_t rel_offset = 0;
    if (!vmem_.ReadStruct(entry_ref_loc, &rel_offset)) return;
    const std::uint64_t sentinel = entry_ref_loc + 4 + static_cast<std::int64_t>(rel_offset);

    std::set<std::uint64_t> processed_entries;
    const std::vector<std::uint64_t> sentinel_candidates = {
        sentinel, sentinel + 8, sentinel + 16, sentinel + 24
    };

    for (const std::uint64_t list_sentinel : sentinel_candidates) {
        std::uint64_t current = 0;
        if (!vmem_.ReadStruct(list_sentinel, &current)) continue;
        if (current == 0 || current == list_sentinel) continue;

        int safety = 0;
        while (current != list_sentinel && safety++ < 4096) {
            if (processed_entries.count(current) != 0) {
                std::uint64_t next = 0;
                if (!vmem_.ReadStruct(current, &next)) break;
                current = next;
                continue;
            }
            processed_entries.insert(current);

            std::uint64_t entry_luid = 0;
            vmem_.ReadStruct(current + 32, &entry_luid);

            const std::size_t po = tmpl_->primary_offset;
            const std::wstring username   = ReadUnicodeString(vmem_, current + po);
            const std::wstring domainname = ReadUnicodeString(vmem_, current + po + 16);

            std::uint16_t pwd_len = 0, pwd_max_len = 0;
            std::uint64_t pwd_buffer = 0;
            vmem_.ReadStruct(current + po + 32, &pwd_len);
            vmem_.ReadStruct(current + po + 34, &pwd_max_len);
            vmem_.ReadStruct(current + po + 40, &pwd_buffer);

            std::wstring password;
            std::wstring password_hex;
            if (pwd_max_len > 0 && pwd_buffer != 0 &&
                extractor_ && extractor_->IsInitialized()) {
                std::vector<std::byte> enc_bytes(pwd_max_len);
                if (vmem_.ReadBytes(pwd_buffer, pwd_max_len, enc_bytes)) {
                    auto dec = extractor_->Decrypt(enc_bytes);
                    DecodePasswordCandidate(dec, pwd_len, password, password_hex);
                }
            }

            if (entry_luid != 0) {
                for (auto& s : sessions) {
                    if (s.authentication_id == entry_luid) {
                        security::WdigestCredential cred;
                        cred.luid         = entry_luid;
                        cred.username     = username;
                        cred.domainname   = domainname;
                        cred.password     = password;
                        cred.password_hex = password_hex;
                        s.wdigest_credentials.push_back(cred);
                        break;
                    }
                }
            }

            std::uint64_t next = 0;
            if (!vmem_.ReadStruct(current, &next)) break;
            current = next;
        }
    }
}

} // namespace KvcForensic::lsa
