#pragma once

#include "core/module_index.h"
#include "lsa/structures.h"
#include "lsa/template_registry.h"
#include "minidump/minidump_parser.h"

#include <filesystem>
#include <string>
#include <vector>

namespace kvc::analysis {

struct AnalysisResult {
    minidump::DumpMetadata metadata;
    std::vector<lsa::LogonSession> sessions;
    std::string active_msv_template;
    std::string active_wdigest_template;
    std::string active_kerberos_template;
    std::string active_dpapi_template;
    std::string active_lsa_secrets_template;
    std::string active_tspkg_template;
    bool secrets_extractor_initialized = false;
    std::string secrets_extractor_error;
    std::uint64_t lsa_secrets_signature_va = 0;
    std::vector<std::byte> aes_key;
    std::vector<std::byte> des_key;
    std::vector<std::byte> iv;
};

struct ReportOptions {
    bool full = false;
    // Default: redact all credential material (keys, hashes, passwords,
    // masterkeys). The session frame (LUID/user/domain/SID, package presence,
    // ticket counts) is always shown. Flip to true only on local triage.
    bool reveal_secrets = false;
};

class ReportBuilder {
public:
    static std::string build_text(const AnalysisResult& result, const ReportOptions& opts);
    static std::string build_json(const AnalysisResult& result, const ReportOptions& opts);

    // Back-compat thin wrappers (used by inspection commands).
    static std::string build_text(const AnalysisResult& result, bool full) {
        return build_text(result, {full, false});
    }
    static std::string build_json(const AnalysisResult& result) {
        return build_json(result, {false, false});
    }
};

void write_text_file(const std::filesystem::path& path, const std::string& text);

} // namespace kvc::analysis
