#include "core/text_utils.h"

#include <cctype>

namespace kvc::core {

namespace {

void append_utf8(std::string& out, std::uint32_t cp) {
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

std::uint16_t read_u16le(const std::byte* p) {
    return static_cast<std::uint16_t>(
        static_cast<unsigned char>(p[0]) |
        (static_cast<unsigned char>(p[1]) << 8));
}

} // namespace

std::string utf16le_to_utf8(std::span<const std::byte> bytes) {
    std::string out;
    out.reserve(bytes.size());
    const std::size_t n = bytes.size() & ~std::size_t{1};
    for (std::size_t i = 0; i < n; i += 2) {
        const std::uint16_t u = read_u16le(bytes.data() + i);
        if (u >= 0xD800 && u <= 0xDBFF && i + 4 <= n) {
            const std::uint16_t lo = read_u16le(bytes.data() + i + 2);
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                const std::uint32_t cp = 0x10000u +
                    ((static_cast<std::uint32_t>(u) - 0xD800u) << 10) +
                    (static_cast<std::uint32_t>(lo) - 0xDC00u);
                append_utf8(out, cp);
                i += 2;
                continue;
            }
        }
        if (u == 0) break;
        append_utf8(out, u);
    }
    return out;
}

std::string utf16le_to_utf8(const std::u16string& s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        const std::uint16_t u = static_cast<std::uint16_t>(s[i]);
        if (u >= 0xD800 && u <= 0xDBFF && i + 1 < s.size()) {
            const std::uint16_t lo = static_cast<std::uint16_t>(s[i + 1]);
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                const std::uint32_t cp = 0x10000u +
                    ((static_cast<std::uint32_t>(u) - 0xD800u) << 10) +
                    (static_cast<std::uint32_t>(lo) - 0xDC00u);
                append_utf8(out, cp);
                ++i;
                continue;
            }
        }
        if (u == 0) break;
        append_utf8(out, u);
    }
    return out;
}

std::string sanitize_ascii(std::string_view in) {
    std::string out;
    out.reserve(in.size());
    for (const char ch : in) {
        const unsigned char uc = static_cast<unsigned char>(ch);
        if (uc >= 0x20 && uc < 0x7f) out.push_back(static_cast<char>(uc));
        else out.push_back('?');
    }
    return out;
}

std::string to_lower(std::string_view in) {
    std::string out(in);
    for (char& ch : out) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return out;
}

bool icontains(std::string_view haystack, std::string_view needle) {
    if (needle.empty()) return true;
    if (needle.size() > haystack.size()) return false;
    for (std::size_t i = 0; i + needle.size() <= haystack.size(); ++i) {
        bool match = true;
        for (std::size_t j = 0; j < needle.size(); ++j) {
            const auto a = std::tolower(static_cast<unsigned char>(haystack[i + j]));
            const auto b = std::tolower(static_cast<unsigned char>(needle[j]));
            if (a != b) { match = false; break; }
        }
        if (match) return true;
    }
    return false;
}

namespace {
const char kHex[] = "0123456789abcdef";
} // namespace

std::string bytes_to_hex(std::span<const std::byte> bytes) {
    std::string out;
    out.resize(bytes.size() * 2);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        const unsigned char b = static_cast<unsigned char>(bytes[i]);
        out[i * 2] = kHex[b >> 4];
        out[i * 2 + 1] = kHex[b & 0xF];
    }
    return out;
}

std::string bytes_to_hex(std::span<const std::uint8_t> bytes) {
    std::string out;
    out.resize(bytes.size() * 2);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        out[i * 2] = kHex[bytes[i] >> 4];
        out[i * 2 + 1] = kHex[bytes[i] & 0xF];
    }
    return out;
}

std::vector<std::uint8_t> parse_hex(std::string_view hex) {
    std::vector<std::uint8_t> out;
    if ((hex.size() % 2) != 0) return out;
    out.reserve(hex.size() / 2);
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

} // namespace kvc::core
