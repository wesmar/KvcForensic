#pragma once

#include "security/ISecurityPackage.h"

#include <cstddef>
#include <span>
#include <string>

namespace KvcForensic::security {

class KerberosPackage final : public ISecurityPackage {
public:
    std::wstring Name() const override;
    void SetContext(
        const minidump::MinidumpMetadata* metadata,
        const BuildLayout* layout) override;
    void Reset() override;
    void Analyze(std::span<const std::byte> data) override;
    SecurityPackageReport Report() const override;

private:
    const minidump::MinidumpMetadata* metadata_ = nullptr;
    const BuildLayout* layout_ = nullptr;
    SecurityPackageReport report_{};
};

} // namespace KvcForensic::security
