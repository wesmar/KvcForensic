#pragma once

#include "core/VirtualMemory.h"
#include "minidump/MinidumpParser.h"
#include "lsa/TemplateRegistry.h"
#include "security/MsvCredentials.h"
#include "security/LsaSecretsExtractor.h"

#include <string>
#include <vector>
#include <set>
#include <cstdint>
#include <memory>

namespace KvcForensic::lsa {

struct LogonSession {
    std::uint64_t authentication_id; // LUID
    std::uint32_t session_id;
    std::wstring username;
    std::wstring domainname;
    std::wstring logon_server;
    std::uint64_t logon_time;
    std::string sid;

    std::uint64_t address;
    std::uint64_t credentials_list_ptr = 0;  // For credential extraction
    std::vector<security::MsvCredential> msv_credentials;
    std::vector<security::CredmanCredential> credman_credentials;
    std::vector<security::WdigestCredential> wdigest_credentials;
    std::vector<security::KerberosCredential> kerberos_credentials;
    std::vector<security::DpapiCredential> dpapi_credentials;
};

class LogonSessionWalker {
public:
    LogonSessionWalker(const core::VirtualMemory& vmem, const minidump::MinidumpMetadata& metadata);

    bool Initialize(std::uint32_t build_number);
    std::vector<LogonSession> Walk();
    
    // Credential extraction
    void ExtractCredentials(LogonSession& session);
    void ExtractCredmanCredentials(LogonSession& session);

    // Package-level credential walks (match sessions by LUID)
    void WalkWdigestList(std::vector<LogonSession>& sessions);
    void WalkKerberosAvl(std::vector<LogonSession>& sessions);
    void WalkKerberosTickets(std::uint64_t session_ptr, security::KerberosCredential& cred);
    void WalkDpapiList(std::vector<LogonSession>& sessions);

    // Debug access
    const security::LsaSecretsExtractor* GetSecretsExtractor() const { return secrets_extractor_.get(); }

private:
    struct SessionFieldLayout {
        std::size_t luid_offset = 0;
        std::size_t username_offset = 0;
        std::size_t domain_offset = 0;
        std::size_t sid_ptr_offset = 0;
        std::size_t credentials_ptr_offset = 0;
    };

    std::uint64_t FindMsvLogonList();
    SessionFieldLayout DetectSessionFieldLayout();
    std::wstring ReadUnicodeString(std::uint64_t string_va);
    std::string ReadSid(std::uint64_t sid_va);
    std::wstring ReadAnsiString(std::uint64_t buffer_va, std::uint16_t length);
    
    // Credential walking (MSV)
    void WalkCredentialsList(std::uint64_t credentials_list_ptr, std::uint64_t sentinel, std::vector<security::MsvCredential>& creds);
    void WalkPrimaryCredentials(std::uint64_t primary_ptr, std::uint64_t sentinel, std::vector<security::MsvCredential>& creds);
    security::MsvCredential DecryptPrimaryCredential(std::span<const std::byte> encrypted_data);

    // Find byte signature within a named module's memory ranges
    std::uint64_t FindSignatureInModule(const std::wstring& module_name, const std::vector<std::uint8_t>& sig);

    // Recursive AVL tree walk for Kerberos
    void WalkAvlNode(std::uint64_t node_addr, std::uint64_t table_addr,
                     std::vector<LogonSession>& sessions, std::set<std::uint64_t>& visited);

    const core::VirtualMemory& vmem_;
    const minidump::MinidumpMetadata& metadata_;

    std::unique_ptr<security::LsaSecretsExtractor> secrets_extractor_;
    const templates::MsvTemplateSpec* msv_template_ = nullptr;
    const templates::WdigestTemplateSpec* wdigest_template_ = nullptr;
    const templates::KerberosTemplateSpec* kerberos_template_ = nullptr;
    const templates::DpapiTemplateSpec* dpapi_template_ = nullptr;
    SessionFieldLayout session_layout_{};

    std::uint64_t logon_list_va_ = 0;
    std::uint32_t session_count_ = 1;
    std::uint64_t ptr_entry_loc_ = 0;
};

} // namespace KvcForensic::lsa
