#include "security/MsvPackage.h"

#include "core/BinaryUtils.h"
#include "core/StringUtils.h"
#include "lsa/TemplateRegistry.h"

#include <vector>

namespace KvcForensic::security {

std::wstring MsvPackage::Name() const {
    return L"MSV1_0";
}

void MsvPackage::SetContext(
    const minidump::MinidumpMetadata* metadata) {
    metadata_ = metadata;
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

    std::vector<const lsa::templates::MsvTemplateSpec*> candidates;
    if (metadata_ != nullptr && metadata_->system_info.has_value() && metadata_->system_info->valid) {
        candidates = lsa::templates::SelectMsvTemplateCandidatesX64(metadata_->system_info->build);
        if (candidates.empty()) {
            if (const auto* single = lsa::templates::SelectMsvTemplateX64(metadata_->system_info->build);
                single != nullptr) {
                candidates.push_back(single);
            }
        }
    }

    bool signature_found = false;
    for (const auto* candidate : candidates) {
        if (candidate == nullptr || candidate->signature.empty()) {
            continue;
        }
        if (core::CountPatternOccurrences(data, candidate->signature) > 0) {
            signature_found = true;
            break;
        }
    }

    if (!signature_found) {
        // Fallback for diagnostics before template registry initialization or when
        // build metadata is unavailable.
        const std::vector<std::uint8_t> x64_sig_25h2 = {
            0x45, 0x89, 0x34, 0x24, 0x8b, 0xfb, 0x45, 0x85, 0xc0, 0x0f
        };
        signature_found = core::CountPatternOccurrences(data, x64_sig_25h2) > 0;
    }

    if (signature_found) {
        report_.notes.push_back(L"MSV signature candidate found in dump image.");
    } else {
        report_.notes.push_back(L"MSV signature candidate not found (may still be valid on other templates).");
    }
}

SecurityPackageReport MsvPackage::Report() const {
    return report_;
}

} // namespace KvcForensic::security
