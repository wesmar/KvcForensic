#pragma once

#include "minidump/MinidumpParser.h"
#include "security/SecurityPackageReport.h"

#include <cstddef>
#include <span>
#include <vector>

namespace KvcForensic::security {

struct SecurityAnalysisResult {
    std::vector<SecurityPackageReport> package_reports;
};

class SecurityAnalysisEngine {
public:
    SecurityAnalysisResult Analyze(
        std::span<const std::byte> data,
        const minidump::MinidumpMetadata& metadata) const;
};

} // namespace KvcForensic::security
