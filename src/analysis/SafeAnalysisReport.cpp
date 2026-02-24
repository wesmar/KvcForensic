#include "analysis/SafeAnalysisReport.h"

#include <Windows.h>

#include "core/HexUtils.h"
#include "core/MemoryReader.h"
#include "core/StringUtils.h"
#include "core/TextEncoding.h"
#include "core/VirtualMemory.h"
#include "lsa/LogonSessionWalker.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace KvcForensic::analysis {

namespace {

std::optional<std::wstring> ReadTextFile(const std::wstring& path) {
    std::ifstream in(std::filesystem::path(path), std::ios::binary);
    if (!in) {
        return std::nullopt;
    }
    in.seekg(0, std::ios::end);
    const auto length = in.tellg();
    in.seekg(0, std::ios::beg);
    if (length < 0) {
        return std::nullopt;
    }

    std::string bytes(static_cast<std::size_t>(length), '\0');
    in.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    if (!in) {
        return std::nullopt;
    }

    std::wstring text = core::Utf8ToWide(bytes, CP_UTF8);
    if (!text.empty()) {
        return text;
    }
    text = core::Utf8ToWide(bytes, CP_ACP);
    if (!text.empty()) {
        return text;
    }
    return std::nullopt;
}

} // namespace

SafeAnalysisReport SafeAnalysisEngine::AnalyzeFile(
    const std::wstring& dump_path,
    const std::optional<std::uint32_t> forced_build_number) const {
    SafeAnalysisReport report{};

    minidump::MinidumpParser parser;
    report.dump = parser.ParseFile(dump_path);

    std::uint32_t build = forced_build_number.value_or(0);
    if (build == 0 && report.dump.system_info.has_value() && report.dump.system_info->valid) {
        build = report.dump.system_info->build;
    }
    report.selected_template = template_select::SelectTemplateForBuild(build);

    core::MemoryReader reader;
    std::span<const std::byte> mapped_data{};
    if (reader.Open(dump_path)) {
        mapped_data = reader.View();
    }

    security::SecurityAnalysisEngine security_engine;
    report.security = security_engine.Analyze(mapped_data, report.dump, build);

    if (mapped_data.size() > 0 && !report.dump.memory_ranges.empty()) {
        core::VirtualMemory vmem(mapped_data, report.dump.memory_ranges);
        lsa::LogonSessionWalker walker(vmem, report.dump);
        if (walker.Initialize(build)) {
            auto sessions = walker.Walk();

            for (auto& s : sessions) {
                walker.ExtractCredentials(s);
                walker.ExtractCredmanCredentials(s);
            }
            walker.WalkWdigestList(sessions);
            walker.WalkKerberosAvl(sessions);
            walker.WalkDpapiList(sessions);

            report.sessions = sessions;

            if (walker.GetSecretsExtractor() && walker.GetSecretsExtractor()->IsInitialized()) {
                report.decryption_active = true;
                report.aes_key_bits = walker.GetSecretsExtractor()->GetAesKey().size() * 8;
            }
        }
    }

    return report;
}

std::wstring BuildReferenceComparison(
    const SafeAnalysisReport& report,
    const std::wstring& reference_path) {
    const auto ref_opt = ReadTextFile(reference_path);
    if (!ref_opt.has_value()) {
        std::wstringstream ss;
        ss << L"Reference comparison\r\n";
        ss << L"- File: " << reference_path << L"\r\n";
        ss << L"- Status: cannot read reference file\r\n";
        return ss.str();
    }

    const std::wstring ref = core::ToLower(ref_opt.value());
    std::wstringstream result;
    result << L"Reference comparison\r\n";
    result << L"- File: " << reference_path << L"\r\n";

    int matches = 0;
    int total = 0;

    if (report.dump.system_info.has_value() && report.dump.system_info->valid) {
        ++total;
        const auto& sys = report.dump.system_info.value();
        std::wstringstream build_ss;
        build_ss << sys.major << L"." << sys.minor << L"." << sys.build;
        if (ref.find(core::ToLower(build_ss.str())) != std::wstring::npos) {
            ++matches;
        }
    }

    ++total;
    if (ref.find(core::ToLower(report.selected_template.template_name)) != std::wstring::npos) {
        ++matches;
    }

    const std::size_t module_cap = (std::min)(report.dump.modules.size(), static_cast<std::size_t>(20));
    std::size_t module_hits = 0;
    for (std::size_t i = 0; i < module_cap; ++i) {
        const auto name = core::ToLower(report.dump.modules[i].name);
        if (!name.empty() && ref.find(name) != std::wstring::npos) {
            ++module_hits;
        }
    }

    result << L"- Core markers matched: " << matches << L"/" << total << L"\r\n";
    result << L"- Module-name overlaps (top " << module_cap << L"): " << module_hits << L"\r\n";
    result << L"- Note: this is structural text comparison only.\r\n";
    return result.str();
}

bool WriteUtf8File(
    const std::wstring& path,
    const std::wstring& text,
    std::wstring* error) {
    std::ofstream out(std::filesystem::path(path), std::ios::binary);
    if (!out) {
        if (error != nullptr) {
            *error = L"Cannot open file for writing.";
        }
        return false;
    }

    const auto utf8 = core::WideToUtf8(text);
    out.write(utf8.data(), static_cast<std::streamsize>(utf8.size()));
    if (!out) {
        if (error != nullptr) {
            *error = L"Write failed.";
        }
        return false;
    }
    return true;
}

} // namespace KvcForensic::analysis
