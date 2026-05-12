#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kvc::core {

// Decode a little-endian UTF-16 byte span into UTF-8.
// Non-printable characters in the BMP are preserved; surrogate pairs are decoded.
std::string utf16le_to_utf8(std::span<const std::byte> bytes);
std::string utf16le_to_utf8(const std::u16string& s);

// Replace any non-printable byte with '?'. Bounded copy.
std::string sanitize_ascii(std::string_view in);

// Lowercased ASCII copy.
std::string to_lower(std::string_view in);

// Substring case-insensitive (ASCII).
bool icontains(std::string_view haystack, std::string_view needle);

// Hex encode bytes (no prefix, lower case).
std::string bytes_to_hex(std::span<const std::byte> bytes);
std::string bytes_to_hex(std::span<const std::uint8_t> bytes);

// Parse hex string ("aabb...") to bytes. Empty vector on error.
std::vector<std::uint8_t> parse_hex(std::string_view hex);

} // namespace kvc::core
