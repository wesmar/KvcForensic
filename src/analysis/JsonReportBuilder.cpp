#include "analysis/JsonReportBuilder.h"

#include "analysis/ReportRenderer.h"
#include "core/HexUtils.h"
#include "core/TextEncoding.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace KvcForensic::analysis {

std::wstring BuildJsonReport(const SafeAnalysisReport& report) {
    std::wstringstream ss;
    ss << std::hex;

    using namespace renderer;

    auto JStr = [&](const std::wstring& v) { return L"\"" + EscapeJson(v) + L"\""; };
    auto JHex = [&](const std::vector<std::byte>& b) -> std::wstring {
        return b.empty() ? L"null" : L"\"" + core::BytesToHex(b) + L"\"";
    };

    // ── 1. SESSIONS (credentials) — most useful section, always first ──────
    ss << L"{\n  \"sessions\": [\n";
    for (std::size_t si = 0; si < report.sessions.size(); ++si) {
        const auto& s = report.sessions[si];
        ss << L"    {\n";
        ss << L"      \"luid\": " << std::dec << s.authentication_id << std::hex << L",\n";
        ss << L"      \"luid_hex\": \"" << LuidHex(s.authentication_id) << L"\",\n";
        ss << L"      \"username\": " << JStr(s.username) << L",\n";
        ss << L"      \"domainname\": " << JStr(s.domainname) << L",\n";
        ss << L"      \"sid\": " << JStr(core::Utf8ToWide(s.sid, CP_UTF8)) << L",\n";

        // MSV
        ss << L"      \"msv\": [\n";
        const auto msv_deduped = Dedup(s.msv_credentials, [](const auto& c) {
            return c.username + L"|" + core::BytesToHex(c.nt_hash);
        });
        bool first = true;
        for (const auto& cref : msv_deduped) {
            const auto& c = cref.get();
            if (!first) ss << L",\n"; first = false;
            ss << L"        {\n";
            ss << L"          \"username\": "   << JStr(c.username)   << L",\n";
            ss << L"          \"domainname\": " << JStr(c.domainname) << L",\n";
            ss << L"          \"nt\": "         << JHex(c.nt_hash)    << L",\n";
            ss << L"          \"sha1\": "       << JHex(c.sha1_hash)  << L",\n";
            ss << L"          \"dpapi\": "      << JHex(c.dpapi)      << L"\n";
            ss << L"        }";
        }
        ss << (first ? L"" : L"\n") << L"      ],\n";

        // WDigest
        ss << L"      \"wdigest\": [\n";
        const auto wdigest_deduped = Dedup(s.wdigest_credentials, [](const auto& c) {
            return c.username + L"|" + c.domainname + L"|" + c.password;
        });
        first = true;
        for (const auto& cref : wdigest_deduped) {
            const auto& c = cref.get();
            if (!first) ss << L",\n"; first = false;
            ss << L"        {\n";
            ss << L"          \"username\": "   << JStr(c.username)   << L",\n";
            ss << L"          \"domainname\": " << JStr(c.domainname) << L",\n";
            ss << L"          \"password\": "   << (c.password.empty() ? L"null" : JStr(c.password)) << L"\n";
            ss << L"        }";
        }
        ss << (first ? L"" : L"\n") << L"      ],\n";

        // Kerberos
        ss << L"      \"kerberos\": [\n";
        const auto kerb_deduped = Dedup(s.kerberos_credentials, [](const auto& c) {
            return c.username + L"|" + c.domainname;
        });
        first = true;
        for (const auto& cref : kerb_deduped) {
            const auto& c = cref.get();
            if (!first) ss << L",\n"; first = false;
            ss << L"        {\n";
            ss << L"          \"username\": "   << JStr(c.username)   << L",\n";
            ss << L"          \"domainname\": " << JStr(c.domainname) << L",\n";
            ss << L"          \"password\": "   << (c.password.empty() ? L"null" : JStr(c.password)) << L",\n";
            ss << L"          \"tickets\": [\n";
            for (std::size_t ti = 0; ti < c.tickets.size(); ++ti) {
                const auto& t = c.tickets[ti];
                if (ti > 0) ss << L",\n";
                ss << L"            {\n";
                ss << L"              \"service\": " << JStr(t.service_name) << L",\n";
                ss << L"              \"target\": "  << JStr(t.target_name)  << L",\n";
                ss << L"              \"client\": "  << JStr(t.client_name)  << L",\n";
                ss << std::dec;
                ss << L"              \"flags\": \"0x" << std::hex
                   << std::setfill(L'0') << std::setw(8) << t.flags << std::dec << L"\",\n";
                ss << L"              \"enc_type\": " << t.enc_type << L",\n";
                ss << L"              \"kvno\": "     << t.kvno     << L",\n";
                ss << L"              \"size\": "     << t.data.size() << L",\n";
                ss << L"              \"ticket\": \"" << core::BytesToHex(t.data) << L"\"\n";
                ss << L"            }";
            }
            ss << (c.tickets.empty() ? L"" : L"\n") << L"          ]\n";
            ss << L"        }";
        }
        ss << (first ? L"" : L"\n") << L"      ],\n";

        // CredMan
        ss << L"      \"credman\": [\n";
        const auto credman_deduped = Dedup(s.credman_credentials, [](const auto& c) {
            return c.username + L"|" + c.domainname + L"|" + c.password;
        });
        first = true;
        for (const auto& cref : credman_deduped) {
            const auto& c = cref.get();
            if (!first) ss << L",\n"; first = false;
            ss << L"        {\n";
            ss << L"          \"username\": "   << JStr(c.username)   << L",\n";
            ss << L"          \"domainname\": " << JStr(c.domainname) << L",\n";
            ss << L"          \"password\": "   << (c.password.empty() ? L"null" : JStr(c.password)) << L"\n";
            ss << L"        }";
        }
        ss << (first ? L"" : L"\n") << L"      ],\n";

        // DPAPI
        ss << L"      \"dpapi\": [\n";
        const auto dpapi_deduped = Dedup(s.dpapi_credentials, [](const auto& c) {
            return core::Utf8ToWide(c.key_guid, CP_UTF8);
        });
        first = true;
        for (const auto& cref : dpapi_deduped) {
            const auto& c = cref.get();
            if (!first) ss << L",\n"; first = false;
            ss << L"        {\n";
            ss << std::dec;
            ss << L"          \"luid\": "         << c.luid << L",\n";
            ss << L"          \"key_guid\": "     << JStr(core::Utf8ToWide(c.key_guid, CP_UTF8))      << L",\n";
            ss << L"          \"masterkey\": \""  << core::BytesToHex(c.masterkey)                     << L"\",\n";
            ss << L"          \"sha1_masterkey\": "<< JStr(core::Utf8ToWide(c.sha1_masterkey, CP_UTF8))<< L"\n";
            ss << L"        }";
        }
        ss << (first ? L"" : L"\n") << L"      ]\n";

        ss << L"    }";
        if (si + 1 < report.sessions.size()) ss << L",";
        ss << L"\n";
    }
    ss << L"  ],\n";

    // ── 2. META (technical details for admins) ─────────────────────────────
    ss << L"  \"meta\": {\n";
    ss << L"    \"decryption\": {\n";
    ss << L"      \"active\": " << (report.decryption_active ? L"true" : L"false") << L",\n";
    ss << L"      \"aes_key_bits\": " << std::dec << report.aes_key_bits << std::hex << L",\n";
    ss << L"      \"note\": " << JStr(report.decryption_note) << L"\n";
    ss << L"    },\n";
    ss << L"    \"input\": {\n";
    ss << L"      \"path\": "  << JStr(report.dump.path) << L",\n";
    ss << L"      \"size\": "  << std::dec << report.dump.file_size << L",\n";
    ss << L"      \"valid\": " << (report.dump.valid ? L"true" : L"false") << L",\n";
    ss << L"      \"error\": " << JStr(report.dump.error) << L"\n";
    ss << L"    },\n";
    ss << L"    \"system\": {\n";
    if (report.dump.system_info.has_value() && report.dump.system_info->valid) {
        const auto& sys = report.dump.system_info.value();
        ss << L"      \"architecture\": " << sys.processor_architecture << L",\n";
        ss << L"      \"build\": \""      << sys.major << L"." << sys.minor << L"." << sys.build << L"\"\n";
    } else {
        ss << L"      \"architecture\": null,\n";
        ss << L"      \"build\": null\n";
    }
    ss << L"    },\n";
    ss << L"    \"template\": {\n";
    ss << L"      \"name\": "        << JStr(report.selected_template.template_name) << L",\n";
    ss << L"      \"min_build\": "   << report.selected_template.min_supported_build << L",\n";
    ss << L"      \"description\": " << JStr(report.selected_template.description) << L"\n";
    ss << L"    },\n";
    ss << L"    \"security_layout\": {\n";
    ss << L"      \"build\": "      << report.security.layout.build_number << L",\n";
    ss << L"      \"configured\": " << (report.security.layout_configured ? L"true" : L"false") << L",\n";
    ss << L"      \"notes\": "      << JStr(report.security.layout.notes) << L"\n";
    ss << L"    },\n";
    ss << L"    \"header\": {\n";
    ss << L"      \"signature\": \""    << HexU32(report.dump.signature)  << L"\",\n";
    ss << L"      \"stream_count\": "  << report.dump.stream_count        << L",\n";
    ss << L"      \"timestamp\": \""   << HexU32(report.dump.timestamp)   << L"\",\n";
    ss << L"      \"flags\": \""       << HexU64(report.dump.flags)       << L"\"\n";
    ss << L"    },\n";
    ss << L"    \"memory\": {\n";
    ss << L"      \"memory64_ranges\": " << report.dump.memory64_range_count  << L",\n";
    ss << L"      \"memory64_bytes\": "  << report.dump.memory64_total_bytes  << L",\n";
    ss << L"      \"memory_ranges\": "   << report.dump.memory_range_count    << L",\n";
    ss << L"      \"threads\": "         << report.dump.thread_count           << L"\n";
    ss << L"    },\n";
    ss << L"    \"modules\": [\n";
    const std::size_t module_limit = (std::min)(report.dump.modules.size(), static_cast<std::size_t>(120));
    for (std::size_t i = 0; i < module_limit; ++i) {
        const auto& mod = report.dump.modules[i];
        ss << L"      {\"name\": " << JStr(mod.name)
           << L", \"base\": \"" << HexU64(mod.base_address)
           << L"\", \"size\": " << mod.size << L"}";
        if (i + 1 < module_limit) ss << L",";
        ss << L"\n";
    }
    ss << L"    ]\n";
    ss << L"  }\n";
    ss << L"}\n";
    return ss.str();
}

} // namespace KvcForensic::analysis
