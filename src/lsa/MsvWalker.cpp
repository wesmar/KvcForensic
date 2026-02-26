#include "lsa/MsvWalker.h"

#include "lsa/LsaReaderUtils.h"

#include <cstring>
#include <unordered_set>
#include <vector>

namespace KvcForensic::lsa {

namespace {

// ---------------------------------------------------------------------------
// KIWI_MSV1_0_CREDENTIAL_LIST (x64)
//   Flink            @ +0   (8 B)
//   AuthPackageId    @ +8   (4 B)
//   [padding]        @ +12  (4 B)
//   PrimaryCredentials @ +16 (8 B, pointer to list head)
// ---------------------------------------------------------------------------
constexpr std::size_t kCredListAuthPkgOffset     = 8;
constexpr std::size_t kCredListPrimaryPtrOffset  = 16;

// ---------------------------------------------------------------------------
// KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC (x64)
//   Flink            @ +0   (8 B)
//   [padding]        @ +8   (16 B)
//   EncryptedCredentials (LSA_UNICODE_STRING x64):
//     Length         @ +24  (2 B)
//     MaximumLength  @ +26  (2 B)
//     [padding]      @ +28  (4 B)
//     Buffer         @ +32  (8 B)
// ---------------------------------------------------------------------------
constexpr std::size_t kPrimaryEncLenOffset    = 24;
constexpr std::size_t kPrimaryEncMaxLenOffset = 26;
constexpr std::size_t kPrimaryEncBufOffset    = 32;

// ---------------------------------------------------------------------------
// KIWI_CREDMAN_SET_LIST_ENTRY (x64) — pointed to by session @ session_credman_ptr_offset
//   Flink            @ +0   (8 B)
//   Blink            @ +8   (8 B)
//   unk0             @ +16  (4 B)
//   [padding]        @ +20  (4 B)
//   List1            @ +24  (8 B, pointer to KIWI_CREDMAN_LIST_STARTER)
// ---------------------------------------------------------------------------
// Note: the session-level pointer offset (0x168 on 24H2/25H2) is read from the
// JSON template as session_credman_ptr_offset. 0 means CredMan not supported.
constexpr std::size_t kCredManSetList1Offset    = 24;    // list1 ptr in SET_LIST_ENTRY

// ---------------------------------------------------------------------------
// KIWI_CREDMAN_LIST_STARTER (x64)
//   unk0             @ +0   (4 B)
//   [padding]        @ +4   (4 B)
//   Start            @ +8   (8 B, Flink of first KIWI_CREDMAN_LIST_ENTRY)
// ---------------------------------------------------------------------------
constexpr std::size_t kCredManStarterSentinelOffset = 8; // &Start = sentinel

// ---------------------------------------------------------------------------
// KIWI_CREDMAN_LIST_ENTRY (x64) — entry_start = current_flink - kCredManEntryFlinkOffset
//   cbEncPassword    @ entry_start +0   (4 B)
//   [padding]        @ entry_start +4   (4 B)
//   encPassword      @ entry_start +8   (8 B, pointer)
//   ...
//   user  (LSA_UNICODE_STRING) @ entry_start +168
//   server2 (LSA_UNICODE_STRING) @ entry_start +192
//   ...
//   Flink            @ entry_start +56  (so entry_start = flink_ptr - 56)
// ---------------------------------------------------------------------------
constexpr std::size_t kCredManEntryFlinkOffset    = 56;
constexpr std::size_t kCredManEntryCbEncPwdOffset  = 0;
constexpr std::size_t kCredManEntryEncPwdPtrOffset = 8;
constexpr std::size_t kCredManEntryUserOffset      = 168;
constexpr std::size_t kCredManEntryServer2Offset   = 192;

// ---------------------------------------------------------------------------
// MSV1_0_PRIMARY_CREDENTIAL_11_H24_DEC (x64, decrypted payload, build 26100+)
//
//   domain   (LSA_UNICODE_STRING):
//     Length         @ +0   (2 B)
//     [pad+MaxLen]   @ +2
//     Buffer         @ +8   (8 B)
//   username (LSA_UNICODE_STRING):
//     Length         @ +16  (2 B)
//     [pad+MaxLen]   @ +18
//     Buffer         @ +24  (8 B)
//
//   Flags:
//     isDPAPIProtected @ +40  — format discriminator: 0=A, 1=B
//     isNtOwfPassword  @ +41
//     isLmOwfPassword  @ +42
//     isShaOwfPassword @ +43
//     isDPAPILimitedKey@ +44
//
//   Format A (isDPAPIProtected == 0):
//     DPAPILimitedKey  [+50 .. +69]  (20 B)
//     NtOwfPassword    [+70 .. +85]  (16 B)
//     LmOwfPassword    [+86 .. +101] (16 B, usually zeroed)
//     ShaOwfPassword   [+102 .. +121](20 B)
//
//   Format B (isDPAPIProtected == 1):
//     NtOwfPassword    [+50 .. +65]  (16 B)
//     ShaOwfPassword   [+102 .. +121](20 B)
//     DPAPILimitedKey  [+122 .. +141](20 B)
// ---------------------------------------------------------------------------
constexpr std::size_t kDecDomainLenOffset      = 0;
constexpr std::size_t kDecDomainBufOffset      = 8;
constexpr std::size_t kDecUserLenOffset        = 16;
constexpr std::size_t kDecUserBufOffset        = 24;
constexpr std::size_t kDecFlagDpapiProtected   = 40;
constexpr std::size_t kDecFlagIsNt             = 41;
constexpr std::size_t kDecFlagIsSha            = 43;
constexpr std::size_t kDecFlagIsDpapi          = 44;
constexpr std::size_t kDecMinSize              = 88; // minimum to safely read flags

// Format A field ranges
constexpr std::size_t kDecA_DpapiStart  = 50;
constexpr std::size_t kDecA_DpapiEnd    = 70;
constexpr std::size_t kDecA_NtStart     = 70;
constexpr std::size_t kDecA_NtEnd       = 86;
constexpr std::size_t kDecA_ShaStart    = 102;
constexpr std::size_t kDecA_ShaEnd      = 122;

// Format B field ranges
constexpr std::size_t kDecB_NtStart     = 50;
constexpr std::size_t kDecB_NtEnd       = 66;
constexpr std::size_t kDecB_ShaStart    = 102;
constexpr std::size_t kDecB_ShaEnd      = 122;
constexpr std::size_t kDecB_DpapiStart  = 122;
constexpr std::size_t kDecB_DpapiEnd    = 142;
constexpr std::uint32_t kMaxCredentialsListNodes = 4096;
constexpr std::uint32_t kMaxPrimaryCredentialsNodes = 4096;

} // namespace

// ---------------------------------------------------------------------------

MsvWalker::MsvWalker(
    const core::VirtualMemory& vmem,
    security::LsaSecretsExtractor* extractor,
    const templates::MsvTemplateSpec* tmpl,
    const std::size_t credentials_ptr_offset)
    : vmem_(vmem)
    , extractor_(extractor)
    , tmpl_(tmpl)
    , credentials_ptr_offset_(credentials_ptr_offset) {}

void MsvWalker::ExtractCredentials(LogonSession& session) {
    if (session.credentials_list_ptr == 0) return;
    const std::uint64_t sentinel = session.address + credentials_ptr_offset_;
    WalkCredentialsList(session.credentials_list_ptr, sentinel, session.msv_credentials);
}

void MsvWalker::ExtractCredmanCredentials(LogonSession& session) {
    if (tmpl_ == nullptr || tmpl_->session_credman_ptr_offset == 0) return;
    std::uint64_t cred_manager_ptr = 0;
    if (!vmem_.ReadStruct(session.address + tmpl_->session_credman_ptr_offset, &cred_manager_ptr)) return;
    if (cred_manager_ptr == 0) return;

    std::uint64_t list1_ptr = 0;
    if (!vmem_.ReadStruct(cred_manager_ptr + kCredManSetList1Offset, &list1_ptr)) return;
    if (list1_ptr == 0) return;

    const std::uint64_t sentinel = list1_ptr + kCredManStarterSentinelOffset;
    std::uint64_t current_flink = 0;
    if (!vmem_.ReadStruct(sentinel, &current_flink)) return;
    if (current_flink == sentinel) return;

    int safety = 0;
    while (current_flink != sentinel && safety++ < 255) {
        const std::uint64_t entry_start = current_flink - kCredManEntryFlinkOffset;

        std::uint32_t cb_enc_password = 0;
        vmem_.ReadStruct(entry_start + kCredManEntryCbEncPwdOffset, &cb_enc_password);

        std::uint64_t enc_password_ptr = 0;
        vmem_.ReadStruct(entry_start + kCredManEntryEncPwdPtrOffset, &enc_password_ptr);

        const std::wstring username   = ReadUnicodeString(vmem_, entry_start + kCredManEntryUserOffset);
        const std::wstring domainname = ReadUnicodeString(vmem_, entry_start + kCredManEntryServer2Offset);

        std::wstring password;
        std::wstring password_hex;
        if (cb_enc_password > 0 && enc_password_ptr != 0 &&
            extractor_ && extractor_->IsInitialized()) {
            std::vector<std::byte> enc_bytes(cb_enc_password);
            if (vmem_.ReadBytes(enc_password_ptr, cb_enc_password, enc_bytes)) {
                auto dec = extractor_->Decrypt(enc_bytes);
                DecodePasswordCandidate(dec, 0, password, password_hex);
            }
        }

        if (!username.empty() || !domainname.empty() || !password.empty() || !password_hex.empty()) {
            security::CredmanCredential cred;
            cred.username     = username;
            cred.domainname   = domainname;
            cred.password     = password;
            cred.password_hex = password_hex;
            session.credman_credentials.push_back(cred);
        }

        std::uint64_t next = 0;
        if (!vmem_.ReadStruct(current_flink, &next)) break;
        current_flink = next;
    }
}

void MsvWalker::WalkCredentialsList(
    const std::uint64_t credentials_list_ptr,
    const std::uint64_t sentinel,
    std::vector<security::MsvCredential>& creds) {

    if (credentials_list_ptr == 0) return;

    std::unordered_set<std::uint64_t> visited;
    visited.insert(sentinel);
    std::uint64_t current = credentials_list_ptr;

    std::uint32_t safety = 0;
    while (current != 0 && current != sentinel && safety++ < kMaxCredentialsListNodes) {
        if (!vmem_.VaToRva(current, 24).has_value()) break;
        if (!visited.insert(current).second) break;

        std::uint64_t flink = 0;
        std::uint32_t auth_pkg_id = 0;
        if (!vmem_.ReadStruct(current, &flink)) break;
        if (!vmem_.ReadStruct(current + kCredListAuthPkgOffset, &auth_pkg_id)) break;

        std::uint64_t primary_ptr = 0;
        if (!vmem_.ReadStruct(current + kCredListPrimaryPtrOffset, &primary_ptr)) break;

        if (primary_ptr != 0)
            WalkPrimaryCredentials(primary_ptr, current + kCredListPrimaryPtrOffset, creds);

        current = flink;
    }
}

void MsvWalker::WalkPrimaryCredentials(
    const std::uint64_t primary_ptr,
    const std::uint64_t sentinel,
    std::vector<security::MsvCredential>& creds) {

    if (primary_ptr == 0) return;

    std::unordered_set<std::uint64_t> visited;
    visited.insert(sentinel);
    std::uint64_t current = primary_ptr;

    std::uint32_t safety = 0;
    while (current != 0 && current != sentinel && safety++ < kMaxPrimaryCredentialsNodes) {
        if (!vmem_.VaToRva(current, 40).has_value()) break;
        if (!visited.insert(current).second) break;

        std::uint64_t flink = 0;
        std::uint16_t enc_len = 0, enc_max_len = 0;
        std::uint64_t enc_buffer = 0;

        if (!vmem_.ReadStruct(current, &flink)) break;
        if (!vmem_.ReadStruct(current + kPrimaryEncLenOffset,    &enc_len))     break;
        if (!vmem_.ReadStruct(current + kPrimaryEncMaxLenOffset, &enc_max_len)) break;
        if (!vmem_.ReadStruct(current + kPrimaryEncBufOffset,    &enc_buffer))  break;

        if (enc_max_len != 0 && enc_len > enc_max_len) { current = flink; continue; }

        if (enc_len > 0 && enc_buffer != 0) {
            std::vector<std::byte> encrypted_data(enc_len);
            if (vmem_.ReadBytes(enc_buffer, enc_len, encrypted_data)) {
                auto cred = DecryptPrimaryCredential(encrypted_data);
                if (!cred.username.empty() || !cred.nt_hash.empty() || !cred.dpapi.empty())
                    creds.push_back(cred);
            }
        }

        current = flink;
    }
}

security::MsvCredential MsvWalker::DecryptPrimaryCredential(
    std::span<const std::byte> encrypted_data) {

    security::MsvCredential cred;
    if (encrypted_data.empty()) return cred;

    if (extractor_ && extractor_->IsInitialized()) {
        auto decrypted = extractor_->Decrypt(encrypted_data);
        if (!decrypted.empty() && decrypted.size() >= kDecMinSize) {
            std::uint16_t username_len = 0, domain_len = 0;
            std::uint64_t username_buffer = 0, domain_buffer = 0;

            std::memcpy(&domain_len,      decrypted.data() + kDecDomainLenOffset, 2);
            std::memcpy(&domain_buffer,   decrypted.data() + kDecDomainBufOffset, 8);
            std::memcpy(&username_len,    decrypted.data() + kDecUserLenOffset,   2);
            std::memcpy(&username_buffer, decrypted.data() + kDecUserBufOffset,   8);

            const auto is_dpapi_protected = static_cast<std::uint8_t>(decrypted[kDecFlagDpapiProtected]);
            const auto is_nt    = static_cast<std::uint8_t>(decrypted[kDecFlagIsNt]);
            const auto is_sha   = static_cast<std::uint8_t>(decrypted[kDecFlagIsSha]);
            const auto is_dpapi = static_cast<std::uint8_t>(decrypted[kDecFlagIsDpapi]);

            if (username_len > 0 && username_buffer != 0) {
                std::vector<std::byte> bytes(username_len);
                if (vmem_.ReadBytes(username_buffer, username_len, bytes))
                    cred.username = Utf16ToWString(bytes);
            }
            if (domain_len > 0 && domain_buffer != 0) {
                std::vector<std::byte> bytes(domain_len);
                if (vmem_.ReadBytes(domain_buffer, domain_len, bytes))
                    cred.domainname = Utf16ToWString(bytes);
            }

            if (is_dpapi_protected == 0) {
                // Format A: DPAPILimitedKey, NT, LM, SHA
                if (is_dpapi && decrypted.size() >= kDecA_DpapiEnd)
                    cred.dpapi.assign(decrypted.begin() + kDecA_DpapiStart,
                                      decrypted.begin() + kDecA_DpapiEnd);
                if (is_nt && decrypted.size() >= kDecA_NtEnd)
                    cred.nt_hash.assign(decrypted.begin() + kDecA_NtStart,
                                        decrypted.begin() + kDecA_NtEnd);
                if (is_sha && decrypted.size() >= kDecA_ShaEnd)
                    cred.sha1_hash.assign(decrypted.begin() + kDecA_ShaStart,
                                          decrypted.begin() + kDecA_ShaEnd);
            } else {
                // Format B: NT, SHA, DPAPILimitedKey
                if (is_nt && decrypted.size() >= kDecB_NtEnd)
                    cred.nt_hash.assign(decrypted.begin() + kDecB_NtStart,
                                        decrypted.begin() + kDecB_NtEnd);
                if (is_sha && decrypted.size() >= kDecB_ShaEnd)
                    cred.sha1_hash.assign(decrypted.begin() + kDecB_ShaStart,
                                          decrypted.begin() + kDecB_ShaEnd);
                if (is_dpapi && decrypted.size() >= kDecB_DpapiEnd)
                    cred.dpapi.assign(decrypted.begin() + kDecB_DpapiStart,
                                      decrypted.begin() + kDecB_DpapiEnd);
            }
            return cred;
        } else if (!decrypted.empty()) {
            cred.dpapi.assign(encrypted_data.begin(), encrypted_data.end());
            return cred;
        }
    }

    cred.dpapi.assign(encrypted_data.begin(), encrypted_data.end());
    return cred;
}

} // namespace KvcForensic::lsa
