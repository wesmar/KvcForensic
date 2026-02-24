#include "security/DpapiPackage.h"

#include "core/BinaryUtils.h"
#include "core/StringUtils.h"

#include <vector>

namespace KvcForensic::security {

std::wstring DpapiPackage::Name() const {
    return L"DPAPI";
}

void DpapiPackage::SetContext(
    const minidump::MinidumpMetadata* metadata,
    const BuildLayout* layout) {
    metadata_ = metadata;
    layout_ = layout;
}

void DpapiPackage::Reset() {
    report_ = SecurityPackageReport{};
    report_.package_name = Name();
}

void DpapiPackage::Analyze(const std::span<const std::byte> data) {
    report_.analyzed_bytes = data.size();
    report_.module_present = false;

    if (metadata_ != nullptr) {
        for (const auto& module : metadata_->modules) {
            if (core::ContainsInsensitive(module.name, L"dpapisrv.dll") ||
                core::ContainsInsensitive(module.name, L"lsasrv.dll")) {
                report_.module_present = true;
                break;
            }
        }
    }

    // DPAPI masterkey signature patterns (x64)
    // Pattern for KIWI_MASTERKEY_CACHE_ENTRY list head
    // Reference: pypykatz dpapi templates
    // WIN_10_1607+: 48 89 4F 08 48 89 78 08 (offset +11)
    const std::vector<std::uint8_t> x64_sig_win10_plus = {
        0x48, 0x89, 0x4f, 0x08, 0x48, 0x89, 0x78, 0x08
    };
    const auto sig_hits = core::CountPatternOccurrences(data, x64_sig_win10_plus);
    if (sig_hits > 0) {
        report_.notes.push_back(L"DPAPI signature candidate found in dump image.");
    } else {
        report_.notes.push_back(L"DPAPI signature candidate not found (may still be valid).");
    }
}

SecurityPackageReport DpapiPackage::Report() const {
    return report_;
}

} // namespace KvcForensic::security
