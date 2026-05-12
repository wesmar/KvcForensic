#pragma once

#include "analysis/report_builder.h"
#include "core/module_index.h"
#include "core/virtual_memory.h"
#include "lsa/template_registry.h"
#include "minidump/minidump_parser.h"

#include <filesystem>

namespace kvc::cli {

class CredentialPipeline {
public:
    CredentialPipeline(
        const minidump::DumpMetadata& metadata,
        const core::VirtualMemory& vmem,
        const core::ModuleIndex& modules,
        const lsa::templates::TemplateRegistry& registry);

    analysis::AnalysisResult run();

private:
    const minidump::DumpMetadata& metadata_;
    const core::VirtualMemory& vmem_;
    const core::ModuleIndex& modules_;
    const lsa::templates::TemplateRegistry& registry_;
};

// Resolve template JSON path. Order: explicit override, $KVC_TEMPLATES,
// alongside exe (argv0), CWD, /etc/kvc/KvcForensic.json. Empty result == not found.
std::filesystem::path resolve_template_path(
    const std::filesystem::path& explicit_path,
    const std::filesystem::path& argv0);

} // namespace kvc::cli
