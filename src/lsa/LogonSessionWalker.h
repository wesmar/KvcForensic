#pragma once

#include "core/VirtualMemory.h"
#include "minidump/MinidumpParser.h"
#include "lsa/TemplateRegistry.h"
#include "security/MsvCredentials.h"
#include "security/LsaSecretsExtractor.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace KvcForensic::lsa {

struct LogonSession {
    std::uint64_t authentication_id = 0; // LUID
    std::uint32_t session_id        = 0;
    std::wstring  username;
    std::wstring  domainname;
    std::wstring  logon_server;
    std::uint64_t logon_time  = 0;
    std::string   sid;

    std::uint64_t address              = 0;
    std::uint64_t credentials_list_ptr = 0;

    std::vector<security::MsvCredential>      msv_credentials;
    std::vector<security::CredmanCredential>  credman_credentials;
    std::vector<security::WdigestCredential>  wdigest_credentials;
    std::vector<security::TspkgCredential>    tspkg_credentials;
    std::vector<security::KerberosCredential> kerberos_credentials;
    std::vector<security::DpapiCredential>    dpapi_credentials;
};

class LogonSessionWalker {
public:
    LogonSessionWalker(const core::VirtualMemory& vmem,
                       const minidump::MinidumpMetadata& metadata);

    bool Initialize(std::uint32_t build_number);

    // Walk the MSV logon list, extract all credential packages, and return
    // fully populated sessions. Combines session enumeration with per-package
    // walks (MSV, CredMan, WDigest, Kerberos, DPAPI).
    std::vector<LogonSession> Walk();

    const security::LsaSecretsExtractor* GetSecretsExtractor() const {
        return secrets_extractor_.get();
    }

    const std::wstring& GetTemplateName() const {
        static const std::wstring kEmpty;
        return msv_template_ ? msv_template_->name : kEmpty;
    }

    std::uint32_t GetTemplateMinBuild() const {
        return msv_template_ ? msv_template_->min_build : 0;
    }

private:
    struct SessionFieldLayout {
        std::size_t luid_offset             = 0;
        std::size_t username_offset         = 0;
        std::size_t domain_offset           = 0;
        std::size_t sid_ptr_offset          = 0;
        std::size_t credentials_ptr_offset  = 0;
    };

    std::uint64_t       FindMsvLogonList();
    SessionFieldLayout  DetectSessionFieldLayout();
    std::vector<LogonSession> EnumerateSessionsWithLayout(const SessionFieldLayout& layout) const;
    bool IsReadablePointer(std::uint64_t va, std::size_t size = 1) const;
    static bool IsLikelyLuid(std::uint64_t luid);
    int ScoreSessionFieldLayout(
        const SessionFieldLayout& layout,
        std::uint64_t ptr_entry_loc,
        std::uint32_t session_count) const;
    bool ConfigureBestMsvTemplateAndLayout(std::uint32_t build_number);

    const core::VirtualMemory&          vmem_;
    const minidump::MinidumpMetadata&   metadata_;

    std::unique_ptr<security::LsaSecretsExtractor> secrets_extractor_;

    std::vector<const templates::MsvTemplateSpec*> msv_template_candidates_;
    const templates::MsvTemplateSpec*      msv_template_      = nullptr;
    templates::MsvTemplateSpec             active_msv_template_{};
    const templates::WdigestTemplateSpec*  wdigest_template_  = nullptr;
    const templates::KerberosTemplateSpec* kerberos_template_ = nullptr;
    const templates::DpapiTemplateSpec*    dpapi_template_    = nullptr;
    const templates::TspkgTemplateSpec*    tspkg_template_    = nullptr;

    SessionFieldLayout session_layout_{};
    std::uint64_t      logon_list_va_  = 0;
    std::uint32_t      session_count_  = 1;
    std::uint64_t      ptr_entry_loc_  = 0;
};

} // namespace KvcForensic::lsa
