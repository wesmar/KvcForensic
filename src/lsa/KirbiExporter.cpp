#include "lsa/KirbiExporter.h"

#include <Windows.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <sstream>
#include <string>
#include <vector>

namespace KvcForensic::lsa {

// ============================================================================
// Minimal DER / BER builder — no third-party library, BCrypt only.
// Produces correct DER for the small subset needed by KRB-CRED.
// ============================================================================
namespace der {

using Bytes = std::vector<std::uint8_t>;

static void AppendLen(Bytes& out, std::size_t n) {
    if (n < 0x80) {
        out.push_back(static_cast<std::uint8_t>(n));
    } else if (n <= 0xFF) {
        out.push_back(0x81);
        out.push_back(static_cast<std::uint8_t>(n));
    } else if (n <= 0xFFFF) {
        out.push_back(0x82);
        out.push_back(static_cast<std::uint8_t>(n >> 8));
        out.push_back(static_cast<std::uint8_t>(n & 0xFF));
    } else {
        out.push_back(0x83);
        out.push_back(static_cast<std::uint8_t>(n >> 16));
        out.push_back(static_cast<std::uint8_t>((n >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(n & 0xFF));
    }
}

static Bytes Tag(std::uint8_t tag, const Bytes& inner) {
    Bytes out;
    out.reserve(1 + 4 + inner.size());
    out.push_back(tag);
    AppendLen(out, inner.size());
    out.insert(out.end(), inner.begin(), inner.end());
    return out;
}

// 0x30 = SEQUENCE (CONSTRUCTED | UNIVERSAL | 16)
static Bytes Sequence(const Bytes& inner) { return Tag(0x30, inner); }

// [n] EXPLICIT CONSTRUCTED context tag
static Bytes Ctx(std::uint8_t n, const Bytes& inner) {
    return Tag(static_cast<std::uint8_t>(0xA0 | n), inner);
}

// APPLICATION [n] CONSTRUCTED
static Bytes App(std::uint8_t n, const Bytes& inner) {
    return Tag(static_cast<std::uint8_t>(0x60 | n), inner);
}

// INTEGER
static Bytes Integer(std::int64_t v) {
    Bytes val;
    if (v == 0) {
        val.push_back(0x00);
    } else {
        // Encode big-endian, minimal, with sign byte.
        std::uint64_t uv = static_cast<std::uint64_t>(v);
        bool neg = (v < 0);
        // Use 8 bytes then trim.
        for (int i = 7; i >= 0; --i)
            val.push_back(static_cast<std::uint8_t>((uv >> (i * 8)) & 0xFF));
        // Remove leading 0x00 bytes unless they precede a byte with bit7 set.
        while (val.size() > 1 && val[0] == 0x00 && (val[1] & 0x80) == 0)
            val.erase(val.begin());
        if (!neg && (val[0] & 0x80))
            val.insert(val.begin(), 0x00); // prevent sign misinterpretation
    }
    return Tag(0x02, val);
}

// OCTET STRING
static Bytes OctetString(const std::uint8_t* data, std::size_t len) {
    Bytes inner(data, data + len);
    return Tag(0x04, inner);
}

static Bytes Concat(std::initializer_list<Bytes> parts) {
    Bytes out;
    for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}

} // namespace der

// ============================================================================
// .kirbi format
//
//   KRB-CRED ::= [APPLICATION 22] SEQUENCE {
//     pvno      [0] INTEGER (5),
//     msg-type  [1] INTEGER (22),
//     tickets   [2] SEQUENCE OF Ticket,
//     enc-part  [3] EncryptedData { etype=0, cipher='' }
//   }
//
// The raw bytes in KerberosTicket::data are the DER-encoded Ticket value.
// We wrap them as-is inside the SEQUENCE OF.
// ============================================================================
std::vector<std::uint8_t> KirbiExporter::BuildKirbi(
    const security::KerberosTicket& ticket)
{
    using namespace der;

    // pvno [0] = 5
    const Bytes pvno = Ctx(0, Integer(5));
    // msg-type [1] = 22 (KRB_CRED)
    const Bytes msg_type = Ctx(1, Integer(22));

    // tickets [2] — wrap raw DER ticket bytes inside SEQUENCE OF
    Bytes ticket_inner(
        reinterpret_cast<const std::uint8_t*>(ticket.data.data()),
        reinterpret_cast<const std::uint8_t*>(ticket.data.data() + ticket.data.size()));
    const Bytes tickets = Ctx(2, Sequence(ticket_inner));

    // enc-part [3] — EncryptedData SEQUENCE { etype [0] = 0, cipher [2] = '' }
    const Bytes enc_etype  = Ctx(0, Integer(0));
    const Bytes enc_cipher = Ctx(2, OctetString(nullptr, 0));
    const Bytes enc_part   = Ctx(3, Sequence(Concat({enc_etype, enc_cipher})));

    const Bytes krb_cred_body = Sequence(Concat({pvno, msg_type, tickets, enc_part}));
    // APPLICATION 22 = 0x60 | 22 = 0x76
    return App(22, krb_cred_body);
}

// ============================================================================
// .ccache format (MIT Kerberos credential cache, file format version 4)
//
// https://www.gnu.org/software/shishi/manual/html_node/The-Credential-Cache-Binary-File-Format.html
//
// All multi-byte integers are BIG-ENDIAN.
//
// file ::= cc_v4_header default_principal credential*
//
// cc_v4_header ::= 0x05 0x04 header_len header_field*
// header_field ::= uint16 tag, uint16 len, data
//   tag 1 = time offset (int32 seconds + int32 useconds) — we write zeros.
//
// principal ::= uint32 name_type, uint32 count,
//               counted_octet realm, counted_octet component[count]
// counted_octet ::= uint32 len, bytes
//
// credential ::= principal client, principal server,
//                keyblock, uint32 auth_time, uint32 start_time,
//                uint32 end_time, uint32 renew_till,
//                uint8 is_skey, uint32be ticket_flags,
//                addresses, authdata,
//                counted_octet ticket, counted_octet second_ticket
//
// keyblock ::= uint16 etype, uint16 etype (again, legacy), uint32 len, bytes
// addresses ::= uint32 count (we write 0)
// authdata  ::= uint32 count (we write 0)
// ============================================================================
namespace ccache {

static void AppendU16(std::vector<std::uint8_t>& v, std::uint16_t n) {
    v.push_back(static_cast<std::uint8_t>(n >> 8));
    v.push_back(static_cast<std::uint8_t>(n & 0xFF));
}
static void AppendU32(std::vector<std::uint8_t>& v, std::uint32_t n) {
    v.push_back(static_cast<std::uint8_t>(n >> 24));
    v.push_back(static_cast<std::uint8_t>((n >> 16) & 0xFF));
    v.push_back(static_cast<std::uint8_t>((n >> 8) & 0xFF));
    v.push_back(static_cast<std::uint8_t>(n & 0xFF));
}

static std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    const int need = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(),
        static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (need <= 0) return {};
    std::string out(static_cast<std::size_t>(need), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(),
        static_cast<int>(w.size()), out.data(), need, nullptr, nullptr);
    return out;
}

static void AppendCountedOctet(std::vector<std::uint8_t>& v, const std::string& s) {
    AppendU32(v, static_cast<std::uint32_t>(s.size()));
    v.insert(v.end(), s.begin(), s.end());
}

static void AppendCountedOctet(std::vector<std::uint8_t>& v,
                                const std::uint8_t* data, std::size_t len) {
    AppendU32(v, static_cast<std::uint32_t>(len));
    v.insert(v.end(), data, data + len);
}

static void AppendPrincipal(std::vector<std::uint8_t>& v,
                             const std::string& realm,
                             const std::vector<std::string>& components,
                             std::uint32_t name_type = 1) {
    AppendU32(v, name_type);
    AppendU32(v, static_cast<std::uint32_t>(components.size()));
    AppendCountedOctet(v, realm);
    for (const auto& c : components) AppendCountedOctet(v, c);
}

} // namespace ccache

std::vector<std::uint8_t> KirbiExporter::BuildCcache(
    const security::KerberosCredential& cred,
    const security::KerberosTicket& ticket)
{
    using namespace ccache;

    std::vector<std::uint8_t> out;
    out.reserve(512);

    // ── Header ──────────────────────────────────────────────────────────────
    out.push_back(0x05);  // file_format_version high
    out.push_back(0x04);  // file_format_version low = 0x0504

    // Header tags section: tag 1 (time offset), 8 bytes of zeros.
    constexpr std::uint16_t kTagTimeOffset = 1;
    constexpr std::uint16_t kTagDataLen    = 8;
    // Total header data length = 4 (tag header) + 8 (data) = 12; but the
    // header_len field itself covers only the tags bytes.
    AppendU16(out, 4 + kTagDataLen);     // header_len
    AppendU16(out, kTagTimeOffset);
    AppendU16(out, kTagDataLen);
    for (int i = 0; i < 8; ++i) out.push_back(0x00);  // all-zeros time offset

    // ── Default principal (client) ──────────────────────────────────────────
    const std::string realm   = WideToUtf8(!cred.domainname.empty()
                                            ? cred.domainname : L"UNKNOWN");
    const std::string client  = WideToUtf8(!cred.username.empty()
                                            ? cred.username : L"unknown");
    // NT_PRINCIPAL = 1
    AppendPrincipal(out, realm, {client}, 1);

    // ── Credential record ───────────────────────────────────────────────────

    // client principal (same as default)
    AppendPrincipal(out, realm, {client}, 1);

    // server/service principal
    const std::string svc = WideToUtf8(!ticket.service_name.empty()
                                        ? ticket.service_name : L"unknown");
    // NT_SRV_INST = 2; split on '/' for host components if present.
    std::vector<std::string> svc_parts;
    {
        std::string s = svc;
        std::size_t pos = 0;
        while ((pos = s.find('/')) != std::string::npos) {
            svc_parts.push_back(s.substr(0, pos));
            s = s.substr(pos + 1);
        }
        svc_parts.push_back(s);
    }
    AppendPrincipal(out, realm, svc_parts, 2);

    // keyblock: etype (2 bytes) + etype again (2 bytes, legacy) + key bytes
    // We have no key material, so write enc_type and empty key.
    AppendU16(out, static_cast<std::uint16_t>(ticket.enc_type));
    AppendU16(out, static_cast<std::uint16_t>(ticket.enc_type));
    AppendU32(out, 0);  // key length = 0 (no key)

    // Timestamps (all zero — we don't have them from the dump)
    AppendU32(out, 0);  // auth_time
    AppendU32(out, 0);  // start_time
    AppendU32(out, 0);  // end_time
    AppendU32(out, 0);  // renew_till

    out.push_back(0);   // is_skey = false

    // ticket_flags (big-endian)
    AppendU32(out, ticket.flags);

    // addresses count = 0
    AppendU32(out, 0);

    // authdata count = 0
    AppendU32(out, 0);

    // ticket bytes (the raw DER Ticket)
    AppendCountedOctet(out,
        reinterpret_cast<const std::uint8_t*>(ticket.data.data()),
        ticket.data.size());

    // second_ticket: empty
    AppendU32(out, 0);

    return out;
}

// ============================================================================
// File writing helpers
// ============================================================================

bool KirbiExporter::WriteFile(
    const std::wstring& path,
    const std::vector<std::uint8_t>& data)
{
    const HANDLE hFile = ::CreateFileW(
        path.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    const BOOL ok = ::WriteFile(
        hFile, data.data(),
        static_cast<DWORD>(data.size()), &written, nullptr);
    ::CloseHandle(hFile);
    return ok && written == static_cast<DWORD>(data.size());
}

std::wstring KirbiExporter::MakeSafeFilename(const std::wstring& s, const std::size_t max_len) {
    std::wstring out;
    out.reserve(s.size());
    for (const wchar_t ch : s) {
        if (ch == L'/' || ch == L'\\' || ch == L':' || ch == L'*' ||
            ch == L'?' || ch == L'"'  || ch == L'<' || ch == L'>' ||
            ch == L'|' || ch == L' '  || ch == L'\0') {
            out.push_back(L'_');
        } else {
            out.push_back(ch);
        }
    }
    if (out.size() > max_len) out.resize(max_len);
    if (out.empty()) out = L"unknown";
    return out;
}

std::wstring KirbiExporter::BuildTicketBaseName(
    const LogonSession& session,
    const security::KerberosCredential& cred,
    const security::KerberosTicket& ticket,
    const std::size_t index)
{
    const std::wstring dom  = MakeSafeFilename(!cred.domainname.empty()
                                ? cred.domainname : session.domainname);
    const std::wstring user = MakeSafeFilename(!cred.username.empty()
                                ? cred.username : session.username);
    const std::wstring svc  = MakeSafeFilename(!ticket.service_name.empty()
                                ? ticket.service_name : L"ticket");

    std::wostringstream ss;
    ss << dom << L"_" << user << L"_" << svc
       << L"_etype" << ticket.enc_type
       << L"_" << index;
    return ss.str();
}

// ============================================================================
// Main export entry point
// ============================================================================

ExportStats KirbiExporter::Export(
    const std::vector<LogonSession>& sessions,
    const std::wstring& export_dir)
{
    ExportStats stats{};

    // Ensure directory exists
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(export_dir), ec);
    if (ec) {
        ++stats.errors;
        return stats;
    }

    std::size_t global_idx = 0;

    for (const auto& session : sessions) {
        for (const auto& cred : session.kerberos_credentials) {
            for (const auto& ticket : cred.tickets) {
                if (ticket.data.empty()) continue;

                const std::wstring base = BuildTicketBaseName(
                    session, cred, ticket, global_idx++);
                const std::wstring dir = export_dir.back() == L'\\' ||
                                         export_dir.back() == L'/'
                                         ? export_dir : export_dir + L"\\";

                // .kirbi
                {
                    const auto kirbi = BuildKirbi(ticket);
                    const std::wstring path = dir + base + L".kirbi";
                    if (WriteFile(path, kirbi))
                        ++stats.kirbi_written;
                    else
                        ++stats.errors;
                }

                // .ccache
                {
                    const auto ccache = BuildCcache(cred, ticket);
                    const std::wstring path = dir + base + L".ccache";
                    if (WriteFile(path, ccache))
                        ++stats.ccache_written;
                    else
                        ++stats.errors;
                }
            }
        }
    }

    return stats;
}

} // namespace KvcForensic::lsa
