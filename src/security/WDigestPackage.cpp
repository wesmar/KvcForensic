#include "security/WDigestPackage.h"

#include "core/BinaryUtils.h"
#include "core/StringUtils.h"

#include <vector>

namespace KvcForensic::security {

std::wstring WDigestPackage::Name() const {
    return L"WDigest";
}

void WDigestPackage::SetContext(
    const minidump::MinidumpMetadata* metadata,
    const BuildLayout* layout) {
    metadata_ = metadata;
    layout_ = layout;
}

void WDigestPackage::Reset() {
    report_ = SecurityPackageReport{};
    report_.package_name = Name();
}

void WDigestPackage::Analyze(const std::span<const std::byte> data) {
    report_.analyzed_bytes = data.size();
    report_.module_present = false;

    if (metadata_ != nullptr) {
        for (const auto& module : metadata_->modules) {
            if (core::ContainsInsensitive(module.name, L"wdigest.dll")) {
                report_.module_present = true;
                break;
            }
        }
    }

    if (layout_ != nullptr) {
        if (layout_->wdigest_list_offset == 0) {
            report_.notes.push_back(L"wdigest_list_offset is not configured (dummy layout).");
        } else {
            report_.notes.push_back(L"wdigest_list_offset configured.");
        }
    }

    const std::vector<std::uint8_t> x64_sig_11 = {
        0x48, 0x3b, 0xc6, 0x74, 0x11, 0x8b, 0x4b, 0x20, 0x39, 0x48
    };
    const auto sig_hits = core::CountPatternOccurrences(data, x64_sig_11);
    if (sig_hits > 0) {
        report_.notes.push_back(L"WDigest signature candidate found in dump image.");
    } else {
        report_.notes.push_back(L"WDigest signature candidate not found (may still be valid on other templates).");
    }
}

SecurityPackageReport WDigestPackage::Report() const {
    return report_;
}

} // namespace KvcForensic::security
