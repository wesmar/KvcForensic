#pragma once

#include "lsa/LogonSessionWalker.h"
#include "security/LsaSecretsExtractor.h"
#include "lsa/TemplateRegistry.h"
#include "core/VirtualMemory.h"
#include "minidump/MinidumpParser.h"

#include <vector>

namespace KvcForensic::lsa {

class DpapiWalker {
public:
    DpapiWalker(
        const core::VirtualMemory& vmem,
        const minidump::MinidumpMetadata& metadata,
        security::LsaSecretsExtractor* extractor,
        const templates::DpapiTemplateSpec* tmpl);

    void Walk(std::vector<LogonSession>& sessions);

private:
    const core::VirtualMemory& vmem_;
    const minidump::MinidumpMetadata& metadata_;
    security::LsaSecretsExtractor* extractor_;
    const templates::DpapiTemplateSpec* tmpl_;
};

} // namespace KvcForensic::lsa
