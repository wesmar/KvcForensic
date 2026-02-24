#pragma once

#include "LsaTemplateSelector.h"
#include "lsa/LogonSessionWalker.h"
#include "minidump/MinidumpParser.h"
#include "security/SecurityAnalysisEngine.h"

#include <optional>
#include <string>
#include <vector>

namespace KvcForensic::analysis {

struct SafeAnalysisReport {
    minidump::MinidumpMetadata dump;
    template_select::LsaTemplateMetadata selected_template;
    security::SecurityAnalysisResult security;
    std::vector<lsa::LogonSession> sessions;
    bool decryption_active = false;
    std::size_t aes_key_bits = 0;
};

class SafeAnalysisEngine {
public:
    SafeAnalysisReport AnalyzeFile(
        const std::wstring& dump_path,
        std::optional<std::uint32_t> forced_build_number = std::nullopt) const;
};

std::wstring BuildReferenceComparison(
    const SafeAnalysisReport& report,
    const std::wstring& reference_path);

bool WriteUtf8File(
    const std::wstring& path,
    const std::wstring& text,
    std::wstring* error);

} // namespace KvcForensic::analysis
