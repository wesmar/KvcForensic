#pragma once

#include "analysis/SafeAnalysisReport.h"

#include <string>

namespace KvcForensic::analysis {

std::wstring BuildJsonReport(const SafeAnalysisReport& report);

} // namespace KvcForensic::analysis
