#pragma once

#include "lsa/LogonSessionWalker.h"
#include "security/LsaSecretsExtractor.h"
#include "lsa/TemplateRegistry.h"
#include "core/VirtualMemory.h"
#include "minidump/MinidumpParser.h"

#include <cstdint>
#include <set>
#include <vector>

namespace KvcForensic::lsa {

class KerberosWalker {
public:
    KerberosWalker(
        const core::VirtualMemory& vmem,
        const minidump::MinidumpMetadata& metadata,
        security::LsaSecretsExtractor* extractor,
        const templates::KerberosTemplateSpec* tmpl);

    void Walk(std::vector<LogonSession>& sessions);

private:
    void WalkAvlNode(
        std::uint64_t node_addr,
        std::uint64_t table_addr,
        std::vector<LogonSession>& sessions,
        std::set<std::uint64_t>& visited);

    void WalkKerberosTickets(
        std::uint64_t session_ptr,
        security::KerberosCredential& cred);

    const core::VirtualMemory& vmem_;
    const minidump::MinidumpMetadata& metadata_;
    security::LsaSecretsExtractor* extractor_;
    const templates::KerberosTemplateSpec* tmpl_;
};

} // namespace KvcForensic::lsa
