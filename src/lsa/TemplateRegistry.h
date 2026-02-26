#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace KvcForensic::lsa::templates {

struct MsvTemplateSpec {
    std::wstring name;
    std::uint32_t min_build = 0;
    std::uint32_t max_build = 0;
    std::vector<std::uint8_t> signature;
    int first_entry_offset = 0;
    int offset2 = 0;
    int first_entry_offset_correction = 0;

    // Session layout offsets (only valid when parser_support is true).
    std::size_t session_luid_offset = 0;
    std::size_t session_username_offset = 0;
    std::size_t session_domain_offset = 0;
    std::size_t session_sid_ptr_offset = 0;
    std::size_t session_credentials_ptr_offset = 0;
    // Offset of the CredMan pointer inside MSLSA_LOGON_SESSION. 0 = not supported.
    std::size_t session_credman_ptr_offset = 0;

    bool parser_support = false;
};

struct WdigestTemplateSpec {
    std::wstring name;
    std::uint32_t min_build = 0;
    std::uint32_t max_build = 0;
    std::vector<std::uint8_t> signature;
    int first_entry_offset = 0;
    std::size_t primary_offset = 0;
};

struct KerberosTemplateSpec {
    std::wstring name;
    std::uint32_t min_build = 0;
    std::uint32_t max_build = 0;
    std::vector<std::uint8_t> signature;
    int first_entry_offset = 0;

    // Session field offsets inside KIWI_KERBEROS_LOGON_SESSION variant.
    std::size_t session_luid_offset = 0;
    std::size_t session_username_offset = 0;
    std::size_t session_domain_offset = 0;
    std::size_t session_password_ustr_offset = 0;
    std::vector<std::size_t> session_luid_fallback_offsets;

    // Ticket list head offsets in the session struct.
    std::vector<std::size_t> ticket_list_offsets;

    // Internal ticket field offsets.
    std::size_t ticket_service_name_offset = 0;
    std::size_t ticket_target_name_offset = 0;
    std::size_t ticket_client_name_offset = 0;
    std::size_t ticket_flags_offset = 0;
    std::size_t ticket_key_type_offset = 0;
    std::size_t ticket_enc_type_offset = 0;
    std::size_t ticket_kvno_offset = 0;
    std::size_t ticket_buffer_len_offset = 0;
    std::size_t ticket_buffer_ptr_offset = 0;
    std::size_t external_name_first_string_offset = 0;
};

struct DpapiTemplateSpec {
    std::wstring name;
    std::uint32_t min_build = 0;
    std::uint32_t max_build = 0;
    std::vector<std::uint8_t> signature;
    int first_entry_offset = 0;
};

// KIWI_TSPKG_LIST_ENTRY x64 layout:
//   +0  LIST_ENTRY (Flink/Blink, 16 bytes)
//   +16 LUID (8 bytes)
//   +24 UNICODE_STRING encrypted credentials (16 bytes)
// After decryption the blob is an inline MSV1_0_INTERACTIVE_LOGON / KERB_INTERACTIVE_LOGON:
//   [optional DWORD MessageType + 4 pad] then 3 × UNICODE_STRING headers
//   followed by raw UTF-16 string data (domain, username, password).
struct TspkgTemplateSpec {
    std::wstring name;
    std::uint32_t min_build = 0;
    std::uint32_t max_build = 0;
    std::vector<std::uint8_t> signature;
    int first_entry_offset = 0;

    // Offset in list entry to LUID (uint64).
    std::size_t luid_offset = 16;
    // Offset in list entry to the encrypted UNICODE_STRING.
    std::size_t primary_offset = 24;
    // Number of bytes before the first UNICODE_STRING header in the decrypted blob.
    // 0 for bare MSV1_0 layout, 8 when MessageType DWORD + 4-byte pad precedes.
    std::size_t blob_header_skip = 0;
};

struct LsaSecretsTemplateSpec {
    std::wstring name;
    std::uint32_t min_build = 0;
    std::uint32_t max_build = 0;
    std::vector<std::uint8_t> signature;
    int offset_to_iv_ptr = 0;
    int offset_to_aes_key_ptr = 0;
    int offset_to_des_key_ptr = 0;
    std::size_t iv_length = 16;

    // KIWI_BCRYPT_HANDLE_KEY / KIWI_BCRYPT_KEY* layout offsets.
    std::size_t handle_ptr_key_offset = 16;
    std::size_t key_cb_secret_offset = 56;
    std::size_t key_data_offset = 60;
};

bool InitializeRegistry(const std::wstring& json_path);
const wchar_t* GetRegistryInitError();

const MsvTemplateSpec* SelectMsvTemplateX64(std::uint32_t build_number);
std::vector<const MsvTemplateSpec*> SelectMsvTemplateCandidatesX64(std::uint32_t build_number);
const WdigestTemplateSpec* SelectWdigestTemplateX64(std::uint32_t build_number);
const KerberosTemplateSpec* SelectKerberosTemplateX64(std::uint32_t build_number);
const DpapiTemplateSpec* SelectDpapiTemplateX64(std::uint32_t build_number);
const LsaSecretsTemplateSpec* SelectLsaSecretsTemplateX64(std::uint32_t build_number);
const TspkgTemplateSpec* SelectTspkgTemplateX64(std::uint32_t build_number);

} // namespace KvcForensic::lsa::templates
