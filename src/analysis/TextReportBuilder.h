#pragma once

#include "analysis/SafeAnalysisReport.h"

#include <string>

namespace KvcForensic::analysis {

// Credentials only: FILE: ====== header + logon sessions (default output).
std::wstring BuildTextReport(const SafeAnalysisReport& report);

// Full report: metadata (Header/Streams/Modules/Security) + credentials (--full flag).
std::wstring BuildFullTextReport(const SafeAnalysisReport& report);

} // namespace KvcForensic::analysis
