#pragma once

#include "lsa/LogonSessionWalker.h"
#include "security/LsaSecretsExtractor.h"
#include "lsa/TemplateRegistry.h"
#include "core/VirtualMemory.h"
#include "minidump/MinidumpParser.h"

#include <vector>

namespace KvcForensic::lsa {

// Walks the KIWI_TSPKG_LIST_ENTRY linked list inside tspkg.dll to extract
// Terminal Services (RDP) credentials. The encrypted UNICODE_STRING blob in
// each entry is decrypted with the same LSA key material used by all other
// packages. The plaintext is an inline KERB_INTERACTIVE_LOGON /
// MSV1_0_INTERACTIVE_LOGON layout with 3 consecutive UNICODE_STRING headers
// (domain, username, password) followed by raw UTF-16 string data.
class TspkgWalker {
public:
    TspkgWalker(
        const core::VirtualMemory& vmem,
        const minidump::MinidumpMetadata& metadata,
        security::LsaSecretsExtractor* extractor,
        const templates::TspkgTemplateSpec* tmpl);

    void Walk(std::vector<LogonSession>& sessions);

private:
    const core::VirtualMemory& vmem_;
    const minidump::MinidumpMetadata& metadata_;
    security::LsaSecretsExtractor* extractor_;
    const templates::TspkgTemplateSpec* tmpl_;
};

} // namespace KvcForensic::lsa
