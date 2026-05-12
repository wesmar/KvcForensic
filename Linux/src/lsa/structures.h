#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace kvc::lsa {

struct LUID64 {
    std::uint32_t LowPart = 0;
    std::int32_t HighPart = 0;
};

struct LIST_ENTRY64 {
    std::uint64_t Flink = 0;
    std::uint64_t Blink = 0;
};

// On-wire layout matches LSA_UNICODE_STRING with 32-bit padding on x64.
struct UNICODE_STRING64 {
    std::uint16_t Length = 0;
    std::uint16_t MaximumLength = 0;
    std::uint32_t Padding = 0;
    std::uint64_t Buffer = 0;
};

static_assert(sizeof(LUID64) == 8);
static_assert(sizeof(LIST_ENTRY64) == 16);
static_assert(sizeof(UNICODE_STRING64) == 16);

// In-memory credential models shared by all walkers.
// All strings are UTF-8.

struct MsvCredential {
    std::string username;
    std::string domainname;
    std::vector<std::byte> nt_hash;     // 16 bytes
    std::vector<std::byte> lm_hash;     // 16 bytes
    std::vector<std::byte> sha1_hash;   // 20 bytes
    std::vector<std::byte> dpapi;       // 20 bytes
    bool is_iso_protected = false;
};

struct CredmanCredential {
    std::string username;
    std::string domainname;
    std::string password;
    std::string password_hex;
};

struct WdigestCredential {
    std::uint64_t luid = 0;
    std::string username;
    std::string domainname;
    std::string password;
    std::string password_hex;
};

struct TspkgCredential {
    std::uint64_t luid = 0;
    std::string username;
    std::string domainname;
    std::string password;
    std::string password_hex;
};

struct KerberosTicket {
    std::string service_name;
    std::string target_name;
    std::string client_name;
    std::uint32_t flags = 0;
    std::uint32_t enc_type = 0;
    std::uint32_t kvno = 0;
    std::vector<std::byte> data;
};

struct KerberosCredential {
    std::uint64_t luid = 0;
    std::string username;
    std::string domainname;
    std::string password;
    std::string password_hex;
    std::vector<KerberosTicket> tickets;
};

struct DpapiCredential {
    std::uint64_t luid = 0;
    std::string key_guid;
    std::vector<std::byte> masterkey;
    std::string sha1_masterkey;
};

struct LogonSession {
    std::uint64_t authentication_id = 0; // LUID
    std::uint32_t session_id = 0;
    std::string username;
    std::string domainname;
    std::string logon_server;
    std::uint64_t logon_time = 0;
    std::string sid;

    std::uint64_t address = 0;
    std::uint64_t credentials_list_ptr = 0;

    std::vector<MsvCredential> msv_credentials;
    std::vector<CredmanCredential> credman_credentials;
    std::vector<WdigestCredential> wdigest_credentials;
    std::vector<TspkgCredential> tspkg_credentials;
    std::vector<KerberosCredential> kerberos_credentials;
    std::vector<DpapiCredential> dpapi_credentials;
};

} // namespace kvc::lsa
