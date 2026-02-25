#include "security/SecurityAnalysisEngine.h"

#include "security/SecurityPackageRegistry.h"

namespace KvcForensic::security {

SecurityAnalysisResult SecurityAnalysisEngine::Analyze(
    const std::span<const std::byte> data,
    const minidump::MinidumpMetadata& metadata) const {
    SecurityAnalysisResult result{};

    auto packages = SecurityPackageRegistry::CreateDefaultPackages();
    result.package_reports.reserve(packages.size());

    for (auto& package : packages) {
        package->Reset();
        package->SetContext(&metadata);
        package->Analyze(data);
        result.package_reports.push_back(package->Report());
    }

    return result;
}

} // namespace KvcForensic::security
