#include "security/TspkgPackage.h"

#include "core/StringUtils.h"

namespace KvcForensic::security {

void TspkgPackage::Analyze(const std::span<const std::byte> data) {
    report_.package_name  = Name();
    report_.analyzed_bytes = data.size();
    report_.module_present = false;

    if (metadata_ != nullptr) {
        for (const auto& module : metadata_->modules) {
            if (core::ContainsInsensitive(module.name, L"tspkg.dll")) {
                report_.module_present = true;
                break;
            }
        }
    }

    if (!report_.module_present) {
        report_.notes.push_back(L"tspkg.dll not found in module list — "
                                 L"Terminal Services credentials not available.");
    }
}

} // namespace KvcForensic::security
