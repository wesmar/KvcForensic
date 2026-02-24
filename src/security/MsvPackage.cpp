#include "security/MsvPackage.h"

#include "core/BinaryUtils.h"
#include "core/StringUtils.h"

#include <vector>

namespace KvcForensic::security {

std::wstring MsvPackage::Name() const {
    return L"MSV1_0";
}

void MsvPackage::SetContext(
    const minidump::MinidumpMetadata* metadata,
    const BuildLayout* layout) {
    metadata_ = metadata;
    layout_ = layout;
}

void MsvPackage::Reset() {
    report_ = SecurityPackageReport{};
    report_.package_name = Name();
}

void MsvPackage::Analyze(const std::span<const std::byte> data) {
    report_.analyzed_bytes = data.size();
    report_.module_present = false;

    if (metadata_ != nullptr) {
        for (const auto& module : metadata_->modules) {
            if (core::ContainsInsensitive(module.name, L"msv1_0.dll")) {
                report_.module_present = true;
                break;
            }
        }
    }

    if (layout_ != nullptr) {
        if (layout_->msv_list_offset == 0) {
            report_.notes.push_back(L"msv_list_offset is not configured (dummy layout).");
        } else {
            report_.notes.push_back(L"msv_list_offset configured.");
        }
    }

    // Lightweight validation that the expected MSV list signature exists in mapped data.
    const std::vector<std::uint8_t> x64_sig_25h2 = {
        0x45, 0x89, 0x34, 0x24, 0x8b, 0xfb, 0x45, 0x85, 0xc0, 0x0f
    };
    const auto sig_hits = core::CountPatternOccurrences(data, x64_sig_25h2);
    if (sig_hits > 0) {
        report_.notes.push_back(L"MSV signature candidate found in dump image.");
    } else {
        report_.notes.push_back(L"MSV signature candidate not found (may still be valid on other templates).");
    }
}

SecurityPackageReport MsvPackage::Report() const {
    return report_;
}

} // namespace KvcForensic::security
