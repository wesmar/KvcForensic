#pragma once

#include "core/module_index.h"
#include "core/virtual_memory.h"
#include "lsa/structures.h"
#include "lsa/template_registry.h"
#include "security/lsa_secrets_extractor.h"

#include <cstdint>
#include <set>
#include <vector>

namespace kvc::lsa {

class KerberosWalker {
public:
    KerberosWalker(const core::VirtualMemory& vmem,
                   const core::ModuleIndex& modules,
                   const security::LsaSecretsExtractor* extractor,
                   const templates::KerberosTemplateSpec* tmpl);

    void walk(std::vector<LogonSession>& sessions) const;

private:
    void walk_avl(std::uint64_t node, std::uint64_t table,
                  std::vector<LogonSession>& sessions,
                  std::set<std::uint64_t>& visited) const;
    void walk_tickets(std::uint64_t session_ptr, KerberosCredential& cred) const;

    const core::VirtualMemory& vmem_;
    const core::ModuleIndex& modules_;
    const security::LsaSecretsExtractor* extractor_;
    const templates::KerberosTemplateSpec* tmpl_;
};

} // namespace kvc::lsa
