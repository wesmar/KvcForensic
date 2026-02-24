#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace KvcForensic::core {

inline std::size_t CountPatternOccurrences(
    const std::span<const std::byte> data,
    const std::vector<std::uint8_t>& pattern) {
    if (pattern.empty() || data.size() < pattern.size()) return 0;

    std::size_t count = 0;
    for (std::size_t i = 0; i + pattern.size() <= data.size(); ++i) {
        bool match = true;
        for (std::size_t j = 0; j < pattern.size(); ++j) {
            if (static_cast<std::uint8_t>(data[i + j]) != pattern[j]) {
                match = false;
                break;
            }
        }
        if (match) ++count;
    }
    return count;
}

} // namespace KvcForensic::core

