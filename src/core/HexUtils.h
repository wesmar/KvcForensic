#pragma once

#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <span>
#include <sstream>
#include <string>
#include <vector>

namespace KvcForensic::core {

inline std::wstring BytesToHex(const std::span<const std::byte> bytes) {
    std::wstringstream ss;
    ss << std::hex << std::setfill(L'0');
    for (const auto b : bytes) {
        ss << std::setw(2) << static_cast<int>(static_cast<unsigned char>(b));
    }
    return ss.str();
}

inline std::wstring BytesToHex(const std::span<const std::uint8_t> bytes) {
    std::wstringstream ss;
    ss << std::hex << std::setfill(L'0');
    for (const auto b : bytes) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

inline std::wstring BytesToHex(const std::vector<std::byte>& bytes) {
    return BytesToHex(std::span<const std::byte>(bytes.data(), bytes.size()));
}

inline std::wstring BytesToHex(const std::vector<std::uint8_t>& bytes) {
    return BytesToHex(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
}

} // namespace KvcForensic::core

