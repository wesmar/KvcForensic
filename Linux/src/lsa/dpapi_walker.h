#pragma once

#include "core/module_index.h"
#include "core/virtual_memory.h"
#include "lsa/structures.h"
#include "lsa/template_registry.h"
#include "security/lsa_secrets_extractor.h"

#include <vector>

namespace kvc::lsa {

class DpapiWalker {
public:
    DpapiWalker(const core::VirtualMemory& vmem,
                const core::ModuleIndex& modules,
                const security::LsaSecretsExtractor* extractor,
                const templates::DpapiTemplateSpec* tmpl);

    void walk(std::vector<LogonSession>& sessions) const;

private:
    const core::VirtualMemory& vmem_;
    const core::ModuleIndex& modules_;
    const security::LsaSecretsExtractor* extractor_;
    const templates::DpapiTemplateSpec* tmpl_;
};

} // namespace kvc::lsa
