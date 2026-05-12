#pragma once

#include "core/virtual_memory.h"
#include "lsa/structures.h"
#include "lsa/template_registry.h"
#include "security/lsa_secrets_extractor.h"

#include <cstdint>
#include <span>
#include <vector>

namespace kvc::lsa {

class MsvWalker {
public:
    MsvWalker(const core::VirtualMemory& vmem,
              const security::LsaSecretsExtractor* extractor,
              const templates::MsvTemplateSpec* tmpl,
              std::size_t credentials_ptr_offset);

    void extract(LogonSession& session) const;
    void extract_credman(LogonSession& session) const;

private:
    void walk_credentials_list(std::uint64_t list_ptr, std::uint64_t sentinel,
                                std::vector<MsvCredential>& out) const;
    void walk_primary_credentials(std::uint64_t primary_ptr, std::uint64_t sentinel,
                                   std::vector<MsvCredential>& out) const;
    MsvCredential decrypt_primary(std::span<const std::byte> encrypted) const;

    const core::VirtualMemory& vmem_;
    const security::LsaSecretsExtractor* extractor_;
    const templates::MsvTemplateSpec* tmpl_;
    std::size_t credentials_ptr_offset_;
};

} // namespace kvc::lsa
