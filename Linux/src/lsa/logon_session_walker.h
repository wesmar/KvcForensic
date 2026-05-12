#pragma once

#include "core/module_index.h"
#include "core/virtual_memory.h"
#include "lsa/structures.h"
#include "lsa/template_registry.h"
#include "minidump/minidump_parser.h"
#include "security/lsa_secrets_extractor.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace kvc::lsa {

class LogonSessionWalker {
public:
    LogonSessionWalker(const core::VirtualMemory& vmem,
                       const minidump::DumpMetadata& metadata,
                       const core::ModuleIndex& modules,
                       const templates::TemplateRegistry& registry);

    bool initialize(std::uint32_t build_number);
    std::vector<LogonSession> walk();

    const security::LsaSecretsExtractor* secrets() const { return secrets_.get(); }
    std::string active_msv_template_name() const {
        return active_msv_template_.name;
    }
    bool used_heuristic_layout() const { return used_heuristic_; }
    bool used_runtime_fallback() const { return used_runtime_fallback_; }
    const std::string& last_error() const { return last_error_; }

private:
    struct SessionFieldLayout {
        std::size_t luid_offset = 0;
        std::size_t username_offset = 0;
        std::size_t domain_offset = 0;
        std::size_t sid_ptr_offset = 0;
        std::size_t credentials_ptr_offset = 0;
    };

    std::uint64_t find_msv_logon_list();
    SessionFieldLayout detect_layout();
    std::vector<LogonSession> enumerate(const SessionFieldLayout& layout) const;
    bool is_readable_ptr(std::uint64_t va, std::size_t size = 1) const;
    static bool is_likely_luid(std::uint64_t luid);
    int score_layout(const SessionFieldLayout& layout, std::uint64_t ptr_entry_loc,
                     std::uint32_t session_count) const;
    bool configure_best_msv_template();

    const core::VirtualMemory& vmem_;
    const minidump::DumpMetadata& metadata_;
    const core::ModuleIndex& modules_;
    const templates::TemplateRegistry& registry_;

    std::unique_ptr<security::LsaSecretsExtractor> secrets_;
    std::vector<const templates::MsvTemplateSpec*> msv_candidates_;
    const templates::MsvTemplateSpec* msv_template_ = nullptr;
    templates::MsvTemplateSpec active_msv_template_{};
    const templates::WdigestTemplateSpec* wdigest_template_ = nullptr;
    const templates::KerberosTemplateSpec* kerberos_template_ = nullptr;
    const templates::DpapiTemplateSpec* dpapi_template_ = nullptr;
    const templates::TspkgTemplateSpec* tspkg_template_ = nullptr;

    SessionFieldLayout session_layout_{};
    std::uint64_t logon_list_va_ = 0;
    std::uint32_t session_count_ = 1;
    std::uint64_t ptr_entry_loc_ = 0;
    bool used_heuristic_ = false;
    bool used_runtime_fallback_ = false;
    std::string last_error_;
};

} // namespace kvc::lsa
