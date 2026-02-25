#pragma once

#include "minidump/MinidumpParser.h"
#include "security/SecurityPackageReport.h"

#include <cstddef>
#include <span>
#include <string>

namespace KvcForensic::security {

class ISecurityPackage {
public:
    virtual ~ISecurityPackage() = default;

    virtual std::wstring Name() const = 0;
    // Extraction is driven by JSON templates (TemplateRegistry); no hardcoded
    // layout offsets are needed here.
    virtual void SetContext(
        const minidump::MinidumpMetadata* metadata) = 0;
    virtual void Reset() = 0;
    // Package analyzers provide lightweight module/layout diagnostics.
    // Deep credential extraction is performed by lsa::LogonSessionWalker.
    virtual void Analyze(std::span<const std::byte> data) = 0;
    virtual SecurityPackageReport Report() const = 0;
};

} // namespace KvcForensic::security
