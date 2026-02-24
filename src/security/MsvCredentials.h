#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <optional>

namespace KvcForensic::security {

struct MsvCredential {
    std::wstring username;
    std::wstring domainname;
    std::vector<std::byte> nt_hash;      // 16 bytes
    std::vector<std::byte> lm_hash;      // 16 bytes
    std::vector<std::byte> sha1_hash;    // 20 bytes
    std::vector<std::byte> dpapi;        // 20 bytes (DPAPI protected)
    bool is_iso_protected = false;
    
    std::wstring to_wstring() const;
};

struct MsvCredentialsList {
    std::uint64_t flink = 0;  // PKIWI_MSV1_0_CREDENTIAL_LIST
    std::uint32_t auth_package_id = 0;
    std::uint64_t primary_credentials_ptr = 0;  // PKIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC
};

struct MsvPrimaryCredentialEnc {
    std::uint64_t flink = 0;  // PKIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC
    std::vector<std::byte> primary;  // ANSI_STRING
    std::uint16_t primary_length = 0;
    std::uint16_t primary_max_length = 0;
    std::uint64_t primary_buffer = 0;
    std::vector<std::byte> encrypted_credentials;  // LSA_UNICODE_STRING
    std::uint16_t enc_cred_length = 0;
    std::uint16_t enc_cred_max_length = 0;
    std::uint64_t enc_cred_buffer = 0;
};

// Decrypted credential structure for Windows 11 24H2+ (MSV1_0_PRIMARY_CREDENTIAL_11_H24_DEC)
struct MsvPrimaryCredentialDec {
    // LSA_UNICODE_STRING LogonDomainName (16 bytes)
    std::uint16_t domain_length = 0;
    std::uint16_t domain_max_length = 0;
    std::uint32_t domain_padding = 0;
    std::uint64_t domain_buffer = 0;
    
    // LSA_UNICODE_STRING UserName (16 bytes)
    std::uint16_t username_length = 0;
    std::uint16_t username_max_length = 0;
    std::uint32_t username_padding = 0;
    std::uint64_t username_buffer = 0;
    
    std::uint64_t p_ntlm_cred_iso_in_proc = 0;  // PVOID (8 bytes)
    std::uint8_t is_iso = 0;                     // BOOLEAN (1 byte)
    std::uint8_t is_nt_owf_password = 0;         // BOOLEAN (1 byte)
    std::uint8_t is_lm_owf_password = 0;         // BOOLEAN (1 byte)
    std::uint8_t is_sha_owf_password = 0;        // BOOLEAN (1 byte)
    std::uint8_t is_dpapi_protected = 0;         // BOOLEAN (1 byte)
    std::uint8_t align0 = 0;                     // BYTE (1 byte)
    std::uint8_t align1 = 0;                     // BYTE (1 byte)
    std::uint8_t align2 = 0;                     // BYTE (1 byte)
    // DWORD credKeyType removed in 11_H24
    std::uint16_t iso_size = 0;                  // WORD (2 bytes)
    std::vector<std::byte> dpapi_protected;      // 20 bytes
    
    // Variable length (if not ISO):
    std::vector<std::byte> nt_owf_password;      // 16 bytes
    std::vector<std::byte> lm_owf_password;      // 16 bytes
    std::vector<std::byte> sha_owf_password;     // 20 bytes
    
    // Variable length (if ISO):
    std::vector<std::byte> encrypted_blob;
};

struct CredmanCredential {
    std::wstring username;
    std::wstring domainname;
    std::wstring password;
    std::wstring password_hex;
    std::wstring to_wstring() const;
};

struct WdigestCredential {
    std::uint64_t luid = 0;
    std::wstring username;
    std::wstring domainname;
    std::wstring password;
    std::wstring password_hex;
    std::wstring to_wstring() const;
};

struct KerberosTicket {
    std::wstring service_name;
    std::wstring target_name;
    std::wstring client_name;
    std::uint32_t flags     = 0;
    std::uint32_t enc_type  = 0;
    std::uint32_t kvno      = 0;
    std::vector<std::byte> data;
};

struct KerberosCredential {
    std::uint64_t luid = 0;
    std::wstring username;
    std::wstring domainname;
    std::wstring password;
    std::wstring password_hex;
    std::vector<KerberosTicket> tickets;

    std::wstring to_wstring() const;
};

// DPAPI MasterKey cache entry (KIWI_MASTERKEY_CACHE_ENTRY)
struct DpapiCredential {
    std::uint64_t luid = 0;          // LogonId from LUID
    std::string key_guid;            // GUID string (e.g., "8fa87aef-9636-454d-8593-15160261559e")
    std::vector<std::byte> masterkey; // Decrypted masterkey bytes
    std::string sha1_masterkey;      // SHA1 hash of decrypted masterkey (hex string)

    std::wstring to_wstring() const;
};

} // namespace KvcForensic::security
