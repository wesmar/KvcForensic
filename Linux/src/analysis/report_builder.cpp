#include "analysis/report_builder.h"

#include "core/text_utils.h"

#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace kvc::analysis {

namespace {

std::string hex64(std::uint64_t v) {
    std::ostringstream ss;
    ss << "0x" << std::hex << std::setw(16) << std::setfill('0') << v;
    return ss.str();
}

std::string json_escape(std::string_view in) {
    std::string out;
    out.reserve(in.size() + 8);
    for (const char ch : in) {
        switch (ch) {
        case '\\': out += "\\\\"; break;
        case '"': out += "\\\""; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (static_cast<unsigned char>(ch) < 0x20) out += "?";
            else out.push_back(ch);
            break;
        }
    }
    return out;
}

constexpr const char* kRedacted = "<redacted>";

std::string secret_hex(std::span<const std::byte> bytes, bool reveal) {
    if (bytes.empty()) return {};
    if (!reveal) return kRedacted;
    return core::bytes_to_hex(bytes);
}

std::string secret_text(std::string_view text, bool reveal) {
    if (text.empty()) return {};
    if (!reveal) return kRedacted;
    return std::string(text);
}

} // namespace

std::string ReportBuilder::build_text(const AnalysisResult& r, const ReportOptions& opts) {
    const auto& d = r.metadata;
    const bool full = opts.full;
    const bool reveal = opts.reveal_secrets;

    std::ostringstream out;
    out << "FILE: KvcForensic Linux output\n";
    out << "dump_path      " << d.path.string() << '\n';
    out << "dump_size      " << d.file_size << '\n';
    if (d.system_info) {
        out << "build_number   " << d.system_info->build << '\n';
        out << "os_version     " << d.system_info->major << '.' << d.system_info->minor
            << " (" << d.system_info->build << ")\n";
    } else {
        out << "build_number   unknown\n";
        out << "os_version     unknown\n";
    }
    out << "msv_template       " << (r.active_msv_template.empty() ? "<none>" : r.active_msv_template) << '\n';
    out << "wdigest_template   " << (r.active_wdigest_template.empty() ? "<none>" : r.active_wdigest_template) << '\n';
    out << "kerberos_template  " << (r.active_kerberos_template.empty() ? "<none>" : r.active_kerberos_template) << '\n';
    out << "dpapi_template     " << (r.active_dpapi_template.empty() ? "<none>" : r.active_dpapi_template) << '\n';
    out << "lsa_secrets_tmpl   " << (r.active_lsa_secrets_template.empty() ? "<none>" : r.active_lsa_secrets_template) << '\n';
    out << "tspkg_template     " << (r.active_tspkg_template.empty() ? "<none>" : r.active_tspkg_template) << '\n';
    out << "lsa_secrets_init   " << (r.secrets_extractor_initialized ? "yes" : "no") << '\n';
    if (!r.secrets_extractor_error.empty())
        out << "lsa_secrets_error  " << r.secrets_extractor_error << '\n';
    if (r.lsa_secrets_signature_va != 0)
        out << "lsa_secrets_sig_va " << hex64(r.lsa_secrets_signature_va) << '\n';
    out << "secrets_revealed   " << (reveal ? "yes" : "no") << '\n';
    if (!r.aes_key.empty()) {
        out << "aes_key            " << secret_hex(r.aes_key, reveal)
            << " (len=" << r.aes_key.size() << ")\n";
    }
    if (!r.des_key.empty()) {
        out << "des_key            " << secret_hex(r.des_key, reveal)
            << " (len=" << r.des_key.size() << ")\n";
    }
    if (!r.iv.empty()) {
        out << "iv                 " << secret_hex(r.iv, reveal)
            << " (len=" << r.iv.size() << ")\n";
    }

    if (!r.sessions.empty()) {
        out << "\n== Logon sessions (" << r.sessions.size() << ") ==\n";
        for (const auto& s : r.sessions) {
            out << "luid " << hex64(s.authentication_id)
                << "  user '" << s.username << "'"
                << "  domain '" << s.domainname << "'"
                << "  sid " << (s.sid.empty() ? "<none>" : s.sid) << '\n';
            for (const auto& c : s.msv_credentials) {
                out << "  msv user='" << c.username
                    << "' domain='" << c.domainname << "'"
                    << " nt=" << secret_hex(c.nt_hash, reveal)
                    << " sha1=" << secret_hex(c.sha1_hash, reveal)
                    << " dpapi=" << secret_hex(c.dpapi, reveal);
                if (!c.lm_hash.empty()) out << " lm=" << secret_hex(c.lm_hash, reveal);
                out << '\n';
            }
            for (const auto& c : s.wdigest_credentials) {
                out << "  wdigest user='" << c.username
                    << "' domain='" << c.domainname << "'"
                    << " pwd='" << secret_text(c.password, reveal) << "'"
                    << " hex=" << secret_text(c.password_hex, reveal) << '\n';
            }
            for (const auto& c : s.tspkg_credentials) {
                out << "  tspkg user='" << c.username
                    << "' domain='" << c.domainname << "'"
                    << " pwd='" << secret_text(c.password, reveal) << "'\n";
            }
            for (const auto& c : s.kerberos_credentials) {
                out << "  kerberos user='" << c.username
                    << "' domain='" << c.domainname << "'"
                    << " pwd='" << secret_text(c.password, reveal) << "'"
                    << " tickets=" << c.tickets.size() << '\n';
            }
            for (const auto& c : s.dpapi_credentials) {
                out << "  dpapi guid=" << c.key_guid
                    << " sha1=" << secret_text(c.sha1_masterkey, reveal)
                    << " bytes=" << c.masterkey.size() << '\n';
            }
        }
    }

    if (!full) return out.str();

    out << "\n== Minidump ==\n";
    out << "signature            " << hex64(d.header.signature) << '\n';
    out << "version              " << d.header.version << '\n';
    out << "stream_count         " << d.header.stream_count << '\n';
    out << "stream_directory_rva " << hex64(d.header.stream_directory_rva) << '\n';
    out << "timestamp            " << d.header.timestamp << '\n';
    out << "flags                " << hex64(d.header.flags) << '\n';
    out << "modules              " << d.modules.size() << '\n';
    // Report header-derived descriptor count (Windows-compatible). Resident
    // range count after validation is reported separately for diagnostics.
    out << "memory64_ranges      " << d.memory64_descriptor_count << '\n';
    out << "memory64_resident    " << d.memory_ranges.size() << '\n';
    if (d.memory64_skipped_descriptors > 0)
        out << "memory64_skipped     " << d.memory64_skipped_descriptors << '\n';
    out << "memory64_total_bytes " << d.memory64_total_bytes << '\n';
    out << "thread_count         " << d.thread_count << '\n';
    out << "thread_ex_count      " << d.thread_ex_count << '\n';

    out << "\n== Streams ==\n";
    for (const auto& s : d.streams) {
        out << minidump::stream_type_name(s.type)
            << " type=" << s.type
            << " rva=" << hex64(s.rva)
            << " size=" << s.size << '\n';
    }

    out << "\n== Modules ==\n";
    for (const auto& m : d.modules) {
        out << hex64(m.base_address) << " size=" << m.size << " " << m.name << '\n';
    }

    return out.str();
}

std::string ReportBuilder::build_json(const AnalysisResult& r, const ReportOptions& opts) {
    const bool reveal = opts.reveal_secrets;
    const auto& d = r.metadata;

    auto hex_or_null = [&](std::span<const std::byte> bytes) -> std::string {
        if (bytes.empty()) return "null";
        if (!reveal) return "\"" + std::string(kRedacted) + "\"";
        return "\"" + core::bytes_to_hex(bytes) + "\"";
    };
    auto text_or_null = [&](std::string_view t) -> std::string {
        if (t.empty()) return "null";
        if (!reveal) return "\"" + std::string(kRedacted) + "\"";
        return "\"" + json_escape(t) + "\"";
    };

    std::ostringstream out;
    out << "{\n";
    out << "  \"dump_path\": \"" << json_escape(d.path.string()) << "\",\n";
    out << "  \"dump_size\": " << d.file_size << ",\n";
    out << "  \"build_number\": ";
    if (d.system_info) out << d.system_info->build; else out << "null";
    out << ",\n";
    out << "  \"stream_count\": " << d.header.stream_count << ",\n";
    out << "  \"module_count\": " << d.modules.size() << ",\n";
    out << "  \"memory64_range_count\": " << d.memory64_descriptor_count << ",\n";
    out << "  \"memory64_resident_count\": " << d.memory_ranges.size() << ",\n";
    out << "  \"memory64_skipped\": " << d.memory64_skipped_descriptors << ",\n";
    out << "  \"memory64_total_bytes\": " << d.memory64_total_bytes << ",\n";
    out << "  \"thread_count\": " << d.thread_count << ",\n";
    out << "  \"secrets_revealed\": " << (reveal ? "true" : "false") << ",\n";
    out << "  \"templates\": {\n";
    out << "    \"msv\": \"" << json_escape(r.active_msv_template) << "\",\n";
    out << "    \"wdigest\": \"" << json_escape(r.active_wdigest_template) << "\",\n";
    out << "    \"kerberos\": \"" << json_escape(r.active_kerberos_template) << "\",\n";
    out << "    \"dpapi\": \"" << json_escape(r.active_dpapi_template) << "\",\n";
    out << "    \"lsa_secrets\": \"" << json_escape(r.active_lsa_secrets_template) << "\",\n";
    out << "    \"tspkg\": \"" << json_escape(r.active_tspkg_template) << "\"\n";
    out << "  },\n";
    out << "  \"lsa_secrets\": {\n";
    out << "    \"initialized\": " << (r.secrets_extractor_initialized ? "true" : "false") << ",\n";
    out << "    \"error\": \"" << json_escape(r.secrets_extractor_error) << "\",\n";
    out << "    \"signature_va\": " << r.lsa_secrets_signature_va << ",\n";
    out << "    \"aes_key_len\": " << r.aes_key.size() << ",\n";
    out << "    \"des_key_len\": " << r.des_key.size() << ",\n";
    out << "    \"iv_len\": " << r.iv.size() << ",\n";
    out << "    \"aes_key\": " << hex_or_null(r.aes_key) << ",\n";
    out << "    \"des_key\": " << hex_or_null(r.des_key) << ",\n";
    out << "    \"iv\": " << hex_or_null(r.iv) << "\n";
    out << "  },\n";
    out << "  \"sessions\": [\n";
    for (std::size_t i = 0; i < r.sessions.size(); ++i) {
        const auto& s = r.sessions[i];
        out << "    {\n";
        out << "      \"luid\": " << s.authentication_id << ",\n";
        out << "      \"username\": \"" << json_escape(s.username) << "\",\n";
        out << "      \"domain\": \"" << json_escape(s.domainname) << "\",\n";
        out << "      \"sid\": \"" << json_escape(s.sid) << "\",\n";
        out << "      \"msv\": [";
        for (std::size_t j = 0; j < s.msv_credentials.size(); ++j) {
            const auto& c = s.msv_credentials[j];
            out << (j ? "," : "") << "{\"user\":\"" << json_escape(c.username)
                << "\",\"domain\":\"" << json_escape(c.domainname)
                << "\",\"nt\":" << hex_or_null(c.nt_hash)
                << ",\"sha1\":" << hex_or_null(c.sha1_hash)
                << ",\"dpapi\":" << hex_or_null(c.dpapi)
                << ",\"lm\":" << hex_or_null(c.lm_hash)
                << "}";
        }
        out << "],\n";
        out << "      \"wdigest\": [";
        for (std::size_t j = 0; j < s.wdigest_credentials.size(); ++j) {
            const auto& c = s.wdigest_credentials[j];
            out << (j ? "," : "") << "{\"user\":\"" << json_escape(c.username)
                << "\",\"domain\":\"" << json_escape(c.domainname)
                << "\",\"password\":" << text_or_null(c.password)
                << ",\"password_hex\":" << text_or_null(c.password_hex) << "}";
        }
        out << "],\n";
        out << "      \"tspkg\": [";
        for (std::size_t j = 0; j < s.tspkg_credentials.size(); ++j) {
            const auto& c = s.tspkg_credentials[j];
            out << (j ? "," : "") << "{\"user\":\"" << json_escape(c.username)
                << "\",\"domain\":\"" << json_escape(c.domainname)
                << "\",\"password\":" << text_or_null(c.password) << "}";
        }
        out << "],\n";
        out << "      \"kerberos\": [";
        for (std::size_t j = 0; j < s.kerberos_credentials.size(); ++j) {
            const auto& c = s.kerberos_credentials[j];
            out << (j ? "," : "") << "{\"user\":\"" << json_escape(c.username)
                << "\",\"domain\":\"" << json_escape(c.domainname)
                << "\",\"password\":" << text_or_null(c.password)
                << ",\"tickets\":" << c.tickets.size() << "}";
        }
        out << "],\n";
        out << "      \"dpapi\": [";
        for (std::size_t j = 0; j < s.dpapi_credentials.size(); ++j) {
            const auto& c = s.dpapi_credentials[j];
            out << (j ? "," : "") << "{\"guid\":\"" << json_escape(c.key_guid)
                << "\",\"sha1\":" << text_or_null(c.sha1_masterkey)
                << ",\"bytes\":" << c.masterkey.size() << "}";
        }
        out << "]\n";
        out << "    }" << (i + 1 == r.sessions.size() ? "" : ",") << "\n";
    }
    out << "  ],\n";
    out << "  \"streams\": [\n";
    for (std::size_t i = 0; i < d.streams.size(); ++i) {
        const auto& s = d.streams[i];
        out << "    {\"type\": " << s.type
            << ", \"name\": \"" << minidump::stream_type_name(s.type)
            << "\", \"rva\": " << s.rva
            << ", \"size\": " << s.size << "}"
            << (i + 1 == d.streams.size() ? "\n" : ",\n");
    }
    out << "  ]\n";
    out << "}\n";
    return out.str();
}

void write_text_file(const std::filesystem::path& path, const std::string& text) {
    std::ofstream out(path, std::ios::binary);
    if (!out) throw std::runtime_error("cannot open output file: " + path.string());
    out.write(text.data(), static_cast<std::streamsize>(text.size()));
    if (!out) throw std::runtime_error("write failed: " + path.string());
}

} // namespace kvc::analysis
