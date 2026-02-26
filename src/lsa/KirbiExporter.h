#pragma once

#include "lsa/LogonSessionWalker.h"
#include "security/MsvCredentials.h"

#include <cstdint>
#include <string>
#include <vector>

namespace KvcForensic::lsa {

// Exports Kerberos tickets from a parsed dump to disk in two formats:
//
//   .kirbi  — KRB-CRED APPLICATION tag wrapping the raw Ticket DER bytes,
//             compatible with Rubeus, mimikatz Pass-the-Ticket, and impacket.
//
//   .ccache — MIT Kerberos credential cache v4, readable by impacket, krb5
//             tools, and Linux kerberized applications directly.
//
// Both formats are written to the directory specified by export_dir. Files are
// named: <domain>_<username>_<service>_<enc_type>.<n>.<ext>
// where <n> is a per-session counter to avoid collisions between duplicate
// service names.
//
// Files are written using CreateFileW + WriteFile (no CRT dependency beyond
// what's already linked). A failed write for one ticket does not abort the
// rest of the export.
struct ExportStats {
    std::size_t kirbi_written = 0;
    std::size_t ccache_written = 0;
    std::size_t errors = 0;
};

class KirbiExporter {
public:
    // Export all tickets in all sessions to export_dir.
    // Returns aggregate stats. export_dir is created if it does not exist.
    static ExportStats Export(
        const std::vector<LogonSession>& sessions,
        const std::wstring& export_dir);

    // Build .kirbi bytes for a single ticket (exposed for testing).
    static std::vector<std::uint8_t> BuildKirbi(const security::KerberosTicket& ticket);

    // Build .ccache bytes for a single credential entry (exposed for testing).
    // realm and client_name are used for the ccache principal fields.
    static std::vector<std::uint8_t> BuildCcache(
        const security::KerberosCredential& cred,
        const security::KerberosTicket& ticket);

private:
    static bool WriteFile(const std::wstring& path,
                          const std::vector<std::uint8_t>& data);
    static std::wstring MakeSafeFilename(const std::wstring& s, std::size_t max_len = 32);
    static std::wstring BuildTicketBaseName(
        const LogonSession& session,
        const security::KerberosCredential& cred,
        const security::KerberosTicket& ticket,
        std::size_t index);
};

} // namespace KvcForensic::lsa
