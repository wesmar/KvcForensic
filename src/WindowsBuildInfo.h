#pragma once

#include <cstdint>
#include <string>

namespace KvcForensic::platform {

struct OsBuildInfo {
    std::uint32_t major = 0;
    std::uint32_t minor = 0;
    std::uint32_t build = 0;
    bool ok = false;
    std::wstring error;
};

OsBuildInfo QueryOsBuild();

std::wstring BuildInfoToText(const OsBuildInfo& info);

} // namespace KvcForensic::platform
