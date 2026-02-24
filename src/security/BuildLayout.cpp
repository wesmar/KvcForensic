#include "security/BuildLayout.h"

#include <array>

namespace KvcForensic::security {

namespace {

const std::array<BuildLayout, 6> kKnownLayouts{{
    {
        26200, 0x1337, 0x1337, 0x1337, 0x1337, 0x1337, 0x1337,
        L"Manually filled layout for Windows 11 25H2 (10.0.26200) - Placeholder values for backend delegation."
    },
    {
        26100, 0, 0, 0, 0, 0, 0,
        L"Dummy layout for Windows 11 24H2 (10.0.26100). Fill manually."
    },
    {
        22631, 0, 0, 0, 0, 0, 0,
        L"Dummy layout for Windows 11 23H2 (10.0.22631). Fill manually."
    },
    {
        22621, 0, 0, 0, 0, 0, 0,
        L"Dummy layout for Windows 11 22H2 (10.0.22621). Fill manually."
    },
    {
        22000, 0, 0, 0, 0, 0, 0,
        L"Dummy layout for Windows 11 21H2 (10.0.22000). Fill manually."
    },
    {
        17763, 0, 0, 0, 0, 0, 0,
        L"Dummy layout for Windows 10 1809+ baseline. Fill manually."
    }
}};

const BuildLayout kLayoutFallback{
    0,
    0, 0, 0, 0, 0, 0,
    L"No predefined layout for this build."
};

} // namespace

const BuildLayout& ResolveBuildLayout(const std::uint32_t build_number) {
    // Table is ordered descending by build; first match is the active layout.
#ifndef NDEBUG
    for (std::size_t i = 1; i < kKnownLayouts.size(); ++i) {
        if (kKnownLayouts[i - 1].build_number < kKnownLayouts[i].build_number) {
            return kLayoutFallback;
        }
    }
#endif
    for (const auto& layout : kKnownLayouts) {
        if (build_number >= layout.build_number) {
            return layout;
        }
    }
    return kLayoutFallback;
}

} // namespace KvcForensic::security
