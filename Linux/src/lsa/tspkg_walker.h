#pragma once

#include "core/module_index.h"
#include "core/virtual_memory.h"
#include "lsa/structures.h"
#include "lsa/template_registry.h"
#include "security/lsa_secrets_extractor.h"

#include <vector>

namespace kvc::lsa {

class TspkgWalker {
public:
    TspkgWalker(const core::VirtualMemory& vmem,
                const core::ModuleIndex& modules,
                const security::LsaSecretsExtractor* extractor,
                const templates::TspkgTemplateSpec* tmpl);

    void walk(std::vector<LogonSession>& sessions) const;

private:
    const core::VirtualMemory& vmem_;
    const core::ModuleIndex& modules_;
    const security::LsaSecretsExtractor* extractor_;
    const templates::TspkgTemplateSpec* tmpl_;
};

} // namespace kvc::lsa
