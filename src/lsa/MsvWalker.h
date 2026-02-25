#pragma once

#include "lsa/LogonSessionWalker.h"
#include "security/MsvCredentials.h"
#include "security/LsaSecretsExtractor.h"
#include "lsa/TemplateRegistry.h"
#include "core/VirtualMemory.h"

#include <cstdint>
#include <span>
#include <vector>

namespace KvcForensic::lsa {

class MsvWalker {
public:
    MsvWalker(
        const core::VirtualMemory& vmem,
        security::LsaSecretsExtractor* extractor,
        const templates::MsvTemplateSpec* tmpl,
        std::size_t credentials_ptr_offset);

    void ExtractCredentials(LogonSession& session);
    void ExtractCredmanCredentials(LogonSession& session);

private:
    void WalkCredentialsList(
        std::uint64_t credentials_list_ptr,
        std::uint64_t sentinel,
        std::vector<security::MsvCredential>& creds);

    void WalkPrimaryCredentials(
        std::uint64_t primary_ptr,
        std::uint64_t sentinel,
        std::vector<security::MsvCredential>& creds);

    security::MsvCredential DecryptPrimaryCredential(std::span<const std::byte> encrypted_data);

    const core::VirtualMemory& vmem_;
    security::LsaSecretsExtractor* extractor_;
    const templates::MsvTemplateSpec* tmpl_;
    std::size_t credentials_ptr_offset_;
};

} // namespace KvcForensic::lsa
