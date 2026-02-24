#pragma once

#include "minidump/MinidumpParser.h"
#include "security/BuildLayout.h"
#include "security/SecurityPackageReport.h"

#include <cstddef>
#include <span>
#include <vector>

namespace KvcForensic::security {

struct SecurityAnalysisResult {
    BuildLayout layout{};
    bool layout_configured = false;
    std::vector<SecurityPackageReport> package_reports;
};

class SecurityAnalysisEngine {
public:
    SecurityAnalysisResult Analyze(
        std::span<const std::byte> data,
        const minidump::MinidumpMetadata& metadata,
        std::uint32_t build_number) const;
};

} // namespace KvcForensic::security
