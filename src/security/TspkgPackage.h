#pragma once

#include "security/ISecurityPackage.h"
#include "security/SecurityPackageReport.h"

namespace KvcForensic::security {

class TspkgPackage final : public ISecurityPackage {
public:
    std::wstring Name() const override { return L"TSPKG"; }
    void SetContext(const minidump::MinidumpMetadata* metadata) override { metadata_ = metadata; }
    void Reset() override { report_ = {}; }
    void Analyze(std::span<const std::byte> data) override;
    SecurityPackageReport Report() const override { return report_; }

private:
    const minidump::MinidumpMetadata* metadata_ = nullptr;
    SecurityPackageReport report_;
};

} // namespace KvcForensic::security
