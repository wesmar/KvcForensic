#include "LsaTemplateSelector.h"

namespace KvcForensic::template_select {

namespace {
constexpr std::uint32_t kWin7Min = 7000;
constexpr std::uint32_t kWin8Min = 8000;
constexpr std::uint32_t kWinBlueMin = 9400;
constexpr std::uint32_t kWin10Min = 9800;
constexpr std::uint32_t kWin10_1809 = 17763;
constexpr std::uint32_t kWin11BuildMin = 22000;
constexpr std::uint32_t kWin11_24H2 = 26100;
constexpr std::uint32_t kWin11_25H2 = 26200;
}

LsaTemplateMetadata SelectTemplateForWindows11(const std::uint32_t build_number) {
    if (build_number >= kWin11_24H2) {
        return {
            L"LSA_x64_9",
            kWin11_24H2,
            L"Windows 11 24H2+ (including 25H2) map to x64_9."
        };
    }

    if (build_number >= kWin11BuildMin) {
        return {
            L"LSA_x64_8",
            kWin11BuildMin,
            L"Windows 11 builds before 24H2 map to x64_8."
        };
    }

    return {
        L"Unsupported by this Windows 11-only scaffold",
        kWin11BuildMin,
        L"This C++ scaffold intentionally targets Windows 11 only."
    };
}

LsaTemplateMetadata SelectTemplateForBuild(const std::uint32_t build_number) {
    if (build_number >= kWin11BuildMin) {
        return SelectTemplateForWindows11(build_number);
    }

    if (build_number >= kWin10_1809) {
        return {
            L"LSA_x64_6",
            kWin10_1809,
            L"Windows 10 1809 up to pre-Windows 11 map to x64_6."
        };
    }

    if (build_number >= kWin10Min) {
        return {
            L"LSA_x64_5",
            kWin10Min,
            L"Early Windows 10 builds map to x64_5."
        };
    }

    if (build_number >= kWinBlueMin) {
        return {
            L"LSA_x64_4",
            kWinBlueMin,
            L"Windows 8.1 generation maps to x64_4."
        };
    }

    if (build_number >= kWin8Min) {
        return {
            L"LSA_x64_3_or_7",
            kWin8Min,
            L"Windows 8 generation may map to x64_3 or x64_7 depending on binary timestamp."
        };
    }

    if (build_number >= kWin7Min) {
        return {
            L"LSA_x64_2",
            kWin7Min,
            L"Windows 7 generation maps to x64_2."
        };
    }

    if (build_number > 0) {
        return {
            L"LSA_x64_1",
            5000,
            L"Pre-Windows 7 NT6 generation maps to x64_1."
        };
    }

    return {
        L"Unknown",
        0,
        L"Build number missing; template cannot be resolved."
    };
}

} // namespace KvcForensic::template_select
