#include "cli/credential_pipeline.h"

#include "core/signature_scanner.h"
#include "lsa/logon_session_walker.h"

#include <cstdlib>
#include <filesystem>

namespace kvc::cli {

CredentialPipeline::CredentialPipeline(
    const minidump::DumpMetadata& metadata,
    const core::VirtualMemory& vmem,
    const core::ModuleIndex& modules,
    const lsa::templates::TemplateRegistry& registry)
    : metadata_(metadata), vmem_(vmem), modules_(modules), registry_(registry) {}

analysis::AnalysisResult CredentialPipeline::run() {
    analysis::AnalysisResult res;
    res.metadata = metadata_;
    if (!metadata_.system_info) {
        res.secrets_extractor_error = "system_info stream missing";
        return res;
    }
    const std::uint32_t build = metadata_.system_info->build;

    if (const auto* t = registry_.select_msv(build)) res.active_msv_template = t->name;
    if (const auto* t = registry_.select_wdigest(build)) res.active_wdigest_template = t->name;
    if (const auto* t = registry_.select_kerberos(build)) res.active_kerberos_template = t->name;
    if (const auto* t = registry_.select_dpapi(build)) res.active_dpapi_template = t->name;
    if (const auto* t = registry_.select_tspkg(build)) res.active_tspkg_template = t->name;
    if (const auto* t = registry_.select_lsa_secrets(build)) res.active_lsa_secrets_template = t->name;

    lsa::LogonSessionWalker walker(vmem_, metadata_, modules_, registry_);
    const bool ok = walker.initialize(build);
    if (const auto* sec = walker.secrets()) {
        res.secrets_extractor_initialized = sec->is_initialized();
        res.secrets_extractor_error = sec->last_error();
        res.lsa_secrets_signature_va = sec->signature_va();
        if (sec->is_initialized()) {
            res.aes_key = sec->aes_key();
            res.des_key = sec->des_key();
            res.iv = sec->iv();
            if (!sec->active_template_name().empty()) {
                res.active_lsa_secrets_template = sec->active_template_name();
            }
        }
    }
    if (ok) {
        if (!walker.active_msv_template_name().empty()) {
            res.active_msv_template = walker.active_msv_template_name();
        }
        res.sessions = walker.walk();
    } else if (res.secrets_extractor_error.empty()) {
        res.secrets_extractor_error = walker.last_error();
    }
    return res;
}

std::filesystem::path resolve_template_path(
    const std::filesystem::path& explicit_path,
    const std::filesystem::path& argv0) {
    namespace fs = std::filesystem;
    auto exists = [](const fs::path& p) {
        std::error_code ec;
        return !p.empty() && fs::exists(p, ec) && fs::is_regular_file(p, ec);
    };
    if (exists(explicit_path)) return explicit_path;
    if (const char* env = std::getenv("KVC_TEMPLATES"); env && *env) {
        fs::path p(env);
        if (exists(p)) return p;
    }
    if (!argv0.empty()) {
        std::error_code ec;
        fs::path exe = fs::weakly_canonical(argv0, ec);
        if (!ec) {
            const fs::path dir = exe.parent_path();
            for (const auto& candidate : {
                     dir / "KvcForensic.json",
                     dir / "resources" / "KvcForensic.json",
                     dir.parent_path() / "resources" / "KvcForensic.json",
                 }) {
                if (exists(candidate)) return candidate;
            }
        }
    }
    for (const auto& candidate : {
             fs::path("KvcForensic.json"),
             fs::path("resources/KvcForensic.json"),
             fs::path("linux-cli/resources/KvcForensic.json"),
             fs::path("/etc/kvc/KvcForensic.json"),
             fs::path("/usr/share/kvc/KvcForensic.json"),
         }) {
        if (exists(candidate)) return candidate;
    }
    return {};
}

} // namespace kvc::cli
