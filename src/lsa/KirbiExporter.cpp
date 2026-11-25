#include "lsa/KirbiExporter.h"

#include <Windows.h>

#include <algorithm>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace KvcForensic::lsa {

namespace {

std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    const int need = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(),
        static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (need <= 0) return {};
    std::string out(static_cast<std::size_t>(need), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(),
        static_cast<int>(w.size()), out.data(), need, nullptr, nullptr);
    return out;
}

std::vector<std::wstring> SplitKerberosName(const std::wstring& value) {
    std::vector<std::wstring> components;
    std::size_t start = 0;
    while (start <= value.size()) {
        const auto end = value.find(L'/', start);
        const auto component = value.substr(
            start, end == std::wstring::npos ? std::wstring::npos : end - start);
        if (!component.empty()) components.push_back(component);
        if (end == std::wstring::npos) break;
        start = end + 1;
    }
    return components;
}

} // namespace

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
    Bytes inner;
    if (data != nullptr && len != 0) inner.assign(data, data + len);
    return Tag(0x04, inner);
}

static Bytes GeneralString(const std::wstring& value) {
    const std::string utf8 = WideToUtf8(value);
    return Tag(0x1B, Bytes(utf8.begin(), utf8.end()));
}

static Bytes BitString32(const std::uint32_t value) {
    Bytes inner(5);
    inner[0] = 0x00;
    inner[1] = static_cast<std::uint8_t>(value >> 24);
    inner[2] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
    inner[3] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
    inner[4] = static_cast<std::uint8_t>(value & 0xFF);
    return Tag(0x03, inner);
}

static std::optional<Bytes> GeneralizedTime(const std::uint64_t filetime) {
    if (filetime == 0) return std::nullopt;

    FILETIME ft{};
    ft.dwLowDateTime = static_cast<DWORD>(filetime & 0xFFFFFFFFu);
    ft.dwHighDateTime = static_cast<DWORD>(filetime >> 32);
    SYSTEMTIME st{};
    if (!::FileTimeToSystemTime(&ft, &st) || st.wYear < 1970) {
        return std::nullopt;
    }

    char text[16]{};
    const int written = std::snprintf(
        text, sizeof(text), "%04u%02u%02u%02u%02u%02uZ",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    if (written != 15) return std::nullopt;
    return Tag(0x18, Bytes(text, text + written));
}

static Bytes Concat(std::initializer_list<Bytes> parts) {
    Bytes out;
    for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}

} // namespace der

namespace {

using der::Bytes;

std::vector<std::wstring> ComponentsOrFallback(
    const security::KerberosName& name,
    const std::wstring& fallback) {
    if (!name.components.empty()) return name.components;
    return SplitKerberosName(fallback);
}

Bytes BuildPrincipalName(
    const security::KerberosName& name,
    const std::wstring& fallback,
    const std::uint16_t fallback_type) {
    const auto components = ComponentsOrFallback(name, fallback);
    const std::vector<std::wstring> effective_components =
        components.empty() ? std::vector<std::wstring>{L"unknown"} : components;

    Bytes strings;
    for (const auto& component : effective_components) {
        const auto encoded = der::GeneralString(component);
        strings.insert(strings.end(), encoded.begin(), encoded.end());
    }

    const auto name_type = name.name_type != 0 ? name.name_type : fallback_type;
    return der::Sequence(der::Concat({
        der::Ctx(0, der::Integer(name_type)),
        der::Ctx(1, der::Sequence(strings))
    }));
}

Bytes BuildEncryptionKey(const security::KerberosTicket& ticket) {
    const auto key_type = ticket.key_type != 0 ? ticket.key_type : ticket.enc_type;
    return der::Sequence(der::Concat({
        der::Ctx(0, der::Integer(key_type)),
        der::Ctx(1, der::OctetString(
            reinterpret_cast<const std::uint8_t*>(ticket.session_key.data()),
            ticket.session_key.size()))
    }));
}

Bytes BuildEncryptedData(
    const std::uint32_t etype,
    const std::uint32_t kvno,
    const std::vector<std::byte>& cipher) {
    Bytes fields = der::Ctx(0, der::Integer(etype));
    if (etype != 0) fields = der::Concat({fields, der::Ctx(1, der::Integer(kvno))});
    fields = der::Concat({
        std::move(fields),
        der::Ctx(2, der::OctetString(
            reinterpret_cast<const std::uint8_t*>(cipher.data()),
            cipher.size()))
    });
    return der::Sequence(fields);
}

Bytes BuildTicket(
    const security::KerberosTicket& ticket,
    const security::KerberosCredential& cred) {
    const auto realm_w = !ticket.domain_name.empty()
        ? ticket.domain_name : cred.domainname;
    const auto realm = realm_w.empty() ? std::wstring(L"UNKNOWN") : realm_w;
    const auto service_name = BuildPrincipalName(ticket.service, ticket.service_name, 2);
    const auto encrypted_data = BuildEncryptedData(
        ticket.enc_type, ticket.kvno, ticket.data);
    return der::App(1, der::Sequence(der::Concat({
        der::Ctx(0, der::Integer(5)),
        der::Ctx(1, der::GeneralString(realm)),
        der::Ctx(2, service_name),
        der::Ctx(3, encrypted_data)
    })));
}

Bytes BuildEncKrbCredPart(
    const security::KerberosTicket& ticket,
    const security::KerberosCredential& cred) {
    const auto prealm_w = !ticket.alt_target_domain_name.empty()
        ? ticket.alt_target_domain_name : cred.domainname;
    const auto srealm_w = !ticket.domain_name.empty()
        ? ticket.domain_name : cred.domainname;
    const auto prealm = prealm_w.empty() ? std::wstring(L"UNKNOWN") : prealm_w;
    const auto srealm = srealm_w.empty() ? std::wstring(L"UNKNOWN") : srealm_w;

    std::vector<Bytes> info_fields;
    info_fields.push_back(der::Ctx(0, BuildEncryptionKey(ticket)));
    info_fields.push_back(der::Ctx(1, der::GeneralString(prealm)));
    info_fields.push_back(der::Ctx(2, BuildPrincipalName(ticket.client, cred.username, 1)));
    info_fields.push_back(der::Ctx(3, der::BitString32(ticket.flags)));
    if (const auto t = der::GeneralizedTime(ticket.start_time)) {
        info_fields.push_back(der::Ctx(5, *t));
    }
    if (const auto t = der::GeneralizedTime(ticket.end_time)) {
        info_fields.push_back(der::Ctx(6, *t));
    }
    if (const auto t = der::GeneralizedTime(ticket.renew_until)) {
        info_fields.push_back(der::Ctx(7, *t));
    }
    info_fields.push_back(der::Ctx(8, der::GeneralString(srealm)));
    info_fields.push_back(der::Ctx(
        9, BuildPrincipalName(ticket.service, ticket.service_name, 2)));

    Bytes info;
    for (const auto& field : info_fields) {
        info.insert(info.end(), field.begin(), field.end());
    }
    const auto ticket_info = der::Sequence(der::Sequence(info));
    return der::App(29, der::Sequence(der::Ctx(0, ticket_info)));
}

Bytes BuildKirbiWithCredential(
    const security::KerberosTicket& ticket,
    const security::KerberosCredential& cred) {
    using namespace der;
    const Bytes pvno = Ctx(0, Integer(5));
    const Bytes msg_type = Ctx(1, Integer(22));
    const Bytes tickets = Ctx(2, Sequence(BuildTicket(ticket, cred)));
    const Bytes cred_part = BuildEncKrbCredPart(ticket, cred);
    const Bytes enc_part = Ctx(3, BuildEncryptedData(0, 0,
        std::vector<std::byte>(
            reinterpret_cast<const std::byte*>(cred_part.data()),
            reinterpret_cast<const std::byte*>(cred_part.data() + cred_part.size()))));
    return App(22, Sequence(Concat({pvno, msg_type, tickets, enc_part})));
}

std::uint32_t FiletimeToUnixSeconds(const std::uint64_t filetime) {
    constexpr std::uint64_t kEpochDifference = 116444736000000000ULL;
    if (filetime < kEpochDifference) return 0;
    const auto seconds = (filetime - kEpochDifference) / 10000000ULL;
    if (seconds > 0xFFFFFFFFULL) return 0;
    return static_cast<std::uint32_t>(seconds);
}

} // namespace

// ============================================================================
// .kirbi format
//
//   KRB-CRED ::= [APPLICATION 22] SEQUENCE {
//     pvno      [0] INTEGER (5),
//     msg-type  [1] INTEGER (22),
//     tickets   [2] SEQUENCE OF Ticket,
//     enc-part  [3] EncryptedData { etype=0, cipher=EncKrbCredPart }
//   }
//
// KerberosTicket::data contains only the encrypted Ticket.cipher value from
// the LSA cache. The Ticket and clear-text EncKrbCredPart wrappers are built
// here from the surrounding cache metadata.
// ============================================================================
std::vector<std::uint8_t> KirbiExporter::BuildKirbi(
    const security::KerberosTicket& ticket)
{
    // BuildKirbi is also used by unit tests with only the credential values
    // embedded in the ticket, so keep a small local credential fallback.
    security::KerberosCredential fallback_cred;
    if (!ticket.alt_target_domain_name.empty()) {
        fallback_cred.domainname = ticket.alt_target_domain_name;
    } else if (!ticket.domain_name.empty()) {
        fallback_cred.domainname = ticket.domain_name;
    }
    if (!ticket.client.components.empty()) {
        fallback_cred.username = ticket.client.DisplayName();
    }
    return BuildKirbiWithCredential(ticket, fallback_cred);
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
    const std::wstring client_realm_w =
        !ticket.alt_target_domain_name.empty()
            ? ticket.alt_target_domain_name
            : (!cred.domainname.empty() ? cred.domainname : L"UNKNOWN");
    const std::wstring server_realm_w =
        !ticket.domain_name.empty()
            ? ticket.domain_name
            : (!cred.domainname.empty() ? cred.domainname : L"UNKNOWN");
    const std::string realm = WideToUtf8(client_realm_w);
    const std::string server_realm = WideToUtf8(server_realm_w);

    std::vector<std::string> client_parts;
    for (const auto& component :
         ComponentsOrFallback(ticket.client, cred.username)) {
        client_parts.push_back(WideToUtf8(component));
    }
    if (client_parts.empty()) client_parts.push_back("unknown");

    // NT_PRINCIPAL = 1
    AppendPrincipal(out, realm, client_parts, 1);

    // ── Credential record ───────────────────────────────────────────────────

    // client principal (same as default)
    AppendPrincipal(out, realm, client_parts, 1);

    // server/service principal
    // NT_SRV_INST = 2; split on '/' for host components if present.
    std::vector<std::string> svc_parts;
    for (const auto& component :
         ComponentsOrFallback(ticket.service, ticket.service_name)) {
        svc_parts.push_back(WideToUtf8(component));
    }
    if (svc_parts.empty()) svc_parts.push_back("unknown");
    const std::uint32_t service_type =
        ticket.service.name_type != 0 ? ticket.service.name_type : 2;
    AppendPrincipal(out, server_realm, svc_parts, service_type);

    // keyblock: etype (2 bytes) + etype again (2 bytes, legacy) + key bytes
    const auto key_type = static_cast<std::uint16_t>(
        ticket.key_type != 0 ? ticket.key_type : ticket.enc_type);
    AppendU16(out, key_type);
    AppendU16(out, key_type);
    const auto key_length = static_cast<std::uint16_t>(
        (std::min)(ticket.session_key.size(), static_cast<std::size_t>(0xFFFF)));
    AppendU16(out, key_length);
    if (key_length != 0) {
        out.insert(out.end(),
            reinterpret_cast<const std::uint8_t*>(ticket.session_key.data()),
            reinterpret_cast<const std::uint8_t*>(ticket.session_key.data()) + key_length);
    }

    AppendU32(out, FiletimeToUnixSeconds(ticket.start_time));  // auth_time
    AppendU32(out, FiletimeToUnixSeconds(ticket.start_time));
    AppendU32(out, FiletimeToUnixSeconds(ticket.end_time));
    AppendU32(out, FiletimeToUnixSeconds(ticket.renew_until));

    out.push_back(0);   // is_skey = false

    // ticket_flags (big-endian)
    AppendU32(out, ticket.flags);

    // addresses count = 0
    AppendU32(out, 0);

    // authdata count = 0
    AppendU32(out, 0);

    // ccache stores the plain DER Ticket, not the encrypted cipher alone.
    const auto ticket_der = BuildTicket(ticket, cred);
    AppendCountedOctet(out, ticket_der.data(), ticket_der.size());

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
                if (ticket.session_key.empty()) {
                    ++stats.errors;
                    continue;
                }

                const std::wstring base = BuildTicketBaseName(
                    session, cred, ticket, global_idx++);
                const std::wstring dir = export_dir.back() == L'\\' ||
                                         export_dir.back() == L'/'
                                         ? export_dir : export_dir + L"\\";

                // .kirbi
                {
                    const auto kirbi = BuildKirbiWithCredential(ticket, cred);
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
