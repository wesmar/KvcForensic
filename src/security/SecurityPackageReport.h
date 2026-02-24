#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace KvcForensic::security {

struct SecurityPackageReport {
    std::wstring package_name;
    bool module_present = false;
    std::size_t analyzed_bytes = 0;
    std::vector<std::wstring> notes;
};

} // namespace KvcForensic::security
