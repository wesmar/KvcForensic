#include "security/KerberosPackage.h"

#include "core/BinaryUtils.h"
#include "core/StringUtils.h"

#include <vector>

namespace KvcForensic::security {

std::wstring KerberosPackage::Name() const {
    return L"Kerberos";
}

void KerberosPackage::SetContext(
    const minidump::MinidumpMetadata* metadata,
    const BuildLayout* layout) {
    metadata_ = metadata;
    layout_ = layout;
}

void KerberosPackage::Reset() {
    report_ = SecurityPackageReport{};
    report_.package_name = Name();
}

void KerberosPackage::Analyze(const std::span<const std::byte> data) {
    report_.analyzed_bytes = data.size();
    report_.module_present = false;

    if (metadata_ != nullptr) {
        for (const auto& module : metadata_->modules) {
            if (core::ContainsInsensitive(module.name, L"kerberos.dll")) {
                report_.module_present = true;
                break;
            }
        }
    }

    if (layout_ != nullptr) {
        if (layout_->kerberos_list_offset == 0) {
            report_.notes.push_back(L"kerberos_list_offset is not configured (dummy layout).");
        } else {
            report_.notes.push_back(L"kerberos_list_offset configured.");
        }
    }

    const std::vector<std::uint8_t> x64_sig_vista_plus = {
        0x48, 0x8b, 0x18, 0x48, 0x8d, 0x0d
    };
    const auto sig_hits = core::CountPatternOccurrences(data, x64_sig_vista_plus);
    if (sig_hits > 0) {
        report_.notes.push_back(L"Kerberos signature candidate found in dump image.");
    } else {
        report_.notes.push_back(L"Kerberos signature candidate not found (may still be valid on other templates).");
    }
}

SecurityPackageReport KerberosPackage::Report() const {
    return report_;
}

} // namespace KvcForensic::security
