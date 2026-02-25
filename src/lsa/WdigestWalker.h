#pragma once

#include "lsa/LogonSessionWalker.h"
#include "security/LsaSecretsExtractor.h"
#include "lsa/TemplateRegistry.h"
#include "core/VirtualMemory.h"
#include "minidump/MinidumpParser.h"

#include <vector>

namespace KvcForensic::lsa {

class WdigestWalker {
public:
    WdigestWalker(
        const core::VirtualMemory& vmem,
        const minidump::MinidumpMetadata& metadata,
        security::LsaSecretsExtractor* extractor,
        const templates::WdigestTemplateSpec* tmpl);

    void Walk(std::vector<LogonSession>& sessions);

private:
    const core::VirtualMemory& vmem_;
    const minidump::MinidumpMetadata& metadata_;
    security::LsaSecretsExtractor* extractor_;
    const templates::WdigestTemplateSpec* tmpl_;
};

} // namespace KvcForensic::lsa
