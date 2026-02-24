#include "analysis/TextReportBuilder.h"

#include "analysis/ReportRenderer.h"
#include "core/HexUtils.h"
#include "core/TextEncoding.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace KvcForensic::analysis {

namespace {

using namespace renderer;

std::wstring BaseName(const std::wstring& p) {
    auto pos = p.rfind(L'\\');
    if (pos == std::wstring::npos) pos = p.rfind(L'/');
    return (pos == std::wstring::npos) ? p : p.substr(pos + 1);
}

// Metadata section: Input / Header / System / Template / Streams / Modules / Security.
// Returns false if dump is invalid (error already written to ss).
bool AppendMetadata(std::wstringstream& ss, const SafeAnalysisReport& report) {
    ss << L"KvcForensic Advanced Analysis Report\r\n";
    ss << L"==================================\r\n\r\n";

    ss << L"Input\r\n";
    ss << L"- Path: " << report.dump.path << L"\r\n";
    ss << L"- Size: " << report.dump.file_size << L" bytes\r\n\r\n";

    if (!report.dump.valid) {
        ss << L"Status\r\n";
        ss << L"- Parse: FAILED\r\n";
        ss << L"- Error: " << report.dump.error << L"\r\n";
        return false;
    }

    ss << L"Header\r\n";
    ss << L"- Signature: " << HexU32(report.dump.signature) << L"\r\n";
    ss << L"- Version: " << HexU32(report.dump.version) << L"\r\n";
    ss << L"- Streams: " << report.dump.stream_count << L"\r\n";
    ss << L"- Directory RVA: " << HexU32(report.dump.stream_directory_rva) << L"\r\n";
    ss << L"- Checksum: " << HexU32(report.dump.checksum) << L"\r\n";
    ss << L"- Timestamp: " << HexU32(report.dump.timestamp) << L"\r\n";
    ss << L"- Flags: " << HexU64(report.dump.flags) << L"\r\n\r\n";

    ss << L"System\r\n";
    if (report.dump.system_info.has_value() && report.dump.system_info->valid) {
        const auto& sys = report.dump.system_info.value();
        ss << L"- Architecture: " << sys.processor_architecture << L"\r\n";
        ss << L"- Build: " << sys.major << L"." << sys.minor << L"." << sys.build << L"\r\n";
    } else {
        ss << L"- Build: unavailable in dump\r\n";
    }
    ss << L"\r\n";

    ss << L"Template Selection\r\n";
    ss << L"- Selected: " << report.selected_template.template_name << L"\r\n";
    ss << L"- Min build: " << report.selected_template.min_supported_build << L"\r\n";
    ss << L"- Note: " << report.selected_template.description << L"\r\n\r\n";

    ss << L"Streams\r\n";
    for (const auto& stream : report.dump.streams) {
        ss << L"- Type=" << stream.type << L" (" << stream.type_name << L")"
           << L", Size=" << stream.data_size
           << L", RVA=" << HexU32(stream.rva) << L"\r\n";
    }
    ss << L"- Memory64 ranges: " << report.dump.memory64_range_count
       << L", Total bytes: " << report.dump.memory64_total_bytes << L"\r\n";
    ss << L"- MemoryList ranges: " << report.dump.memory_range_count << L"\r\n";
    ss << L"- ThreadList count: " << report.dump.thread_count << L"\r\n";
    ss << L"- ThreadExList count: " << report.dump.thread_ex_count << L"\r\n";
    ss << L"- Unloaded modules: " << report.dump.unloaded_module_count << L"\r\n";
    ss << L"- Handle descriptors: " << report.dump.handle_descriptor_count << L"\r\n";
    ss << L"- MemoryInfo entries: " << report.dump.memory_info_entry_count << L"\r\n";
    ss << L"- ThreadInfo entries: " << report.dump.thread_info_entry_count << L"\r\n";
    ss << L"\r\n";

    ss << L"Modules (" << report.dump.modules.size() << L")\r\n";
    const std::size_t module_limit = (std::min)(report.dump.modules.size(), static_cast<std::size_t>(40));
    for (std::size_t i = 0; i < module_limit; ++i) {
        const auto& mod = report.dump.modules[i];
        ss << L"- " << mod.name
           << L" | Base=" << HexU64(mod.base_address)
           << L" | Size=" << mod.size << L"\r\n";
    }
    if (report.dump.modules.size() > module_limit) {
        ss << L"- ... truncated, total modules: " << report.dump.modules.size() << L"\r\n";
    }
    ss << L"\r\n";

    ss << L"Security Packages\r\n";
    ss << L"- Layout build: " << report.security.layout.build_number << L"\r\n";
    ss << L"- Layout configured: " << (report.security.layout_configured ? L"yes" : L"no") << L"\r\n";
    ss << L"- Layout notes: " << report.security.layout.notes << L"\r\n";
    for (const auto& package : report.security.package_reports) {
        ss << L"- " << package.package_name
           << L": module_present=" << (package.module_present ? L"yes" : L"no")
           << L", analyzed_bytes=" << package.analyzed_bytes << L"\r\n";
        for (const auto& note : package.notes) {
            ss << L"  note: " << note << L"\r\n";
        }
    }
    ss << L"\r\n";
    return true;
}

// Credentials section: FILE header + AES status + logon sessions.
void AppendCredentials(std::wstringstream& ss, const SafeAnalysisReport& report) {
    ss << L"FILE: ======== " << BaseName(report.dump.path) << L" =======\r\n";

    if (report.decryption_active) {
        ss << L"[+] AES-" << report.aes_key_bits << L" decryption active"
           << L"   sessions: " << report.sessions.size() << L"\r\n";
    } else {
        ss << L"[!] Decryption key not found\r\n";
    }
    ss << L"\r\n";

    for (const auto& s : report.sessions) {
        ss << L"== LogonSession ==\r\n";
        ss << L"authentication_id " << std::dec << s.authentication_id
           << L" (" << std::hex << s.authentication_id << std::dec << L")\r\n";
        ss << L"username "   << s.username   << L"\r\n";
        ss << L"domainname " << s.domainname << L"\r\n";
        ss << L"sid "        << core::Utf8ToWide(s.sid, CP_UTF8) << L"\r\n";
        ss << L"luid "       << s.authentication_id << L"\r\n";

        // MSV
        const auto msv_deduped = Dedup(s.msv_credentials, [](const auto& c) {
            return c.username + L"|" + core::BytesToHex(c.nt_hash);
        });
        for (const auto& cref : msv_deduped) {
            const auto& c = cref.get();
            ss << L"\t== MSV ==\r\n";
            ss << L"\t\tUsername: " << c.username   << L"\r\n";
            ss << L"\t\tDomain: "   << c.domainname << L"\r\n";
            ss << L"\t\tLM: "   << (c.lm_hash.empty() ? L"NA" : core::BytesToHex(c.lm_hash)) << L"\r\n";
            ss << L"\t\tNT: "   << (c.nt_hash.empty() ? L"NA" : core::BytesToHex(c.nt_hash)) << L"\r\n";
            if (!c.sha1_hash.empty()) ss << L"\t\tSHA1: "  << core::BytesToHex(c.sha1_hash) << L"\r\n";
            if (!c.dpapi.empty())     ss << L"\t\tDPAPI: " << core::BytesToHex(c.dpapi)     << L"\r\n";
        }

        // WDigest
        const auto wdigest_deduped = Dedup(s.wdigest_credentials, [](const auto& c) {
            return c.username + L"|" + c.domainname + L"|" + c.password;
        });
        for (const auto& cref : wdigest_deduped) {
            const auto& c = cref.get();
            ss << L"\t== WDIGEST [" << LuidHex(c.luid) << L"]==\r\n";
            ss << L"\t\tusername "       << c.username   << L"\r\n";
            ss << L"\t\tdomainname "     << c.domainname << L"\r\n";
            ss << L"\t\tpassword "       << (c.password.empty() ? L"None" : c.password) << L"\r\n";
            ss << L"\t\tpassword (hex) " << c.password_hex << L"\r\n";
        }

        // Kerberos
        const auto kerb_deduped = Dedup(s.kerberos_credentials, [](const auto& c) {
            return c.username + L"|" + c.domainname;
        });
        for (const auto& cref : kerb_deduped) {
            const auto& c = cref.get();
            ss << L"\t== Kerberos ==\r\n";
            ss << L"\t\tUsername: " << c.username   << L"\r\n";
            ss << L"\t\tDomain: "   << c.domainname << L"\r\n";
            if (!c.password.empty())
                ss << L"\t\tPassword: " << c.password << L"\r\n";
            for (const auto& t : c.tickets) {
                ss << L"\t\t[Ticket]\r\n";
                if (!t.service_name.empty())
                    ss << L"\t\t\tServiceName: " << t.service_name << L"\r\n";
                if (!t.target_name.empty())
                    ss << L"\t\t\tTargetName:  " << t.target_name  << L"\r\n";
                if (!t.client_name.empty())
                    ss << L"\t\t\tClientName:  " << t.client_name  << L"\r\n";
                ss << L"\t\t\tFlags:   0x" << std::hex
                   << std::setfill(L'0') << std::setw(8) << t.flags << std::dec << L"\r\n";
                ss << L"\t\t\tEncType: " << t.enc_type
                   << L"  Kvno: "        << t.kvno << L"\r\n";
                if (!t.data.empty())
                    ss << L"\t\t\tTicket:  " << core::BytesToHex(t.data).substr(0, 64)
                       << L"...\r\n";
            }
        }

        // CREDMAN
        const auto credman_deduped = Dedup(s.credman_credentials, [](const auto& c) {
            return c.username + L"|" + c.domainname + L"|" + c.password;
        });
        for (const auto& cref : credman_deduped) {
            const auto& c = cref.get();
            ss << L"\t== CREDMAN [" << LuidHex(s.authentication_id) << L"]==\r\n";
            ss << L"\t\tluid "     << s.authentication_id << L"\r\n";
            ss << L"\t\tusername " << c.username          << L"\r\n";
            ss << L"\t\tdomain "   << c.domainname        << L"\r\n";
            ss << L"\t\tpassword " << (c.password.empty() ? L"None" : c.password) << L"\r\n";
            if (!c.password_hex.empty())
                ss << L"\t\tpassword (hex) " << c.password_hex << L"\r\n";
        }

        // DPAPI
        const auto dpapi_deduped = Dedup(s.dpapi_credentials, [](const auto& c) {
            return core::Utf8ToWide(c.key_guid, CP_UTF8);
        });
        for (const auto& cref : dpapi_deduped) {
            const auto& c = cref.get();
            ss << L"\t== DPAPI [" << LuidHex(c.luid) << L"]==\r\n";
            ss << L"\t\tluid "          << c.luid                                     << L"\r\n";
            ss << L"\t\tkey_guid "      << core::Utf8ToWide(c.key_guid, CP_UTF8)      << L"\r\n";
            ss << L"\t\tmasterkey "     << core::BytesToHex(c.masterkey)               << L"\r\n";
            ss << L"\t\tsha1_masterkey "<< core::Utf8ToWide(c.sha1_masterkey, CP_UTF8)<< L"\r\n";
        }

        ss << L"\r\n";
    }

    ss << L"[*] " << std::dec << report.sessions.size() << L" logon session(s) parsed.\r\n";
}

} // namespace

// Default output: FILE header + AES status + logon sessions.
std::wstring BuildTextReport(const SafeAnalysisReport& report) {
    std::wstringstream ss;
    AppendCredentials(ss, report);
    return ss.str();
}

// Full output: metadata sections + credentials (use with --full flag).
std::wstring BuildFullTextReport(const SafeAnalysisReport& report) {
    std::wstringstream ss;
    const bool valid = AppendMetadata(ss, report);
    if (valid) {
        AppendCredentials(ss, report);
    }
    return ss.str();
}

} // namespace KvcForensic::analysis
