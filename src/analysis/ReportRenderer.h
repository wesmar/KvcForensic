#pragma once

#include <cstdint>
#include <functional>
#include <iomanip>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace KvcForensic::analysis::renderer {

inline std::wstring HexU32(const std::uint32_t value) {
    std::wstringstream ss;
    ss << L"0x" << std::hex << std::setw(8) << std::setfill(L'0') << value;
    return ss.str();
}

inline std::wstring HexU64(const std::uint64_t value) {
    std::wstringstream ss;
    ss << L"0x" << std::hex << std::setw(16) << std::setfill(L'0') << value;
    return ss.str();
}

inline std::wstring LuidHex(const std::uint64_t id) {
    std::wostringstream hs;
    hs << std::hex << id;
    return hs.str();
}

inline std::wstring EscapeJson(const std::wstring& input) {
    std::wstring out;
    out.reserve(input.size() + 8);
    for (const auto ch : input) {
        switch (ch) {
        case L'\\': out += L"\\\\"; break;
        case L'"':  out += L"\\\""; break;
        case L'\r': out += L"\\r";  break;
        case L'\n': out += L"\\n";  break;
        case L'\t': out += L"\\t";  break;
        default:
            if (ch < 0x20) {
                wchar_t buf[7];
                swprintf_s(buf, L"\\u%04X", static_cast<unsigned>(ch));
                out += buf;
            } else {
                out.push_back(ch);
            }
            break;
        }
    }
    return out;
}

// Dedup: returns unique elements (first occurrence) filtered by key returned from KeyFn.
template<typename T, typename KeyFn>
std::vector<std::reference_wrapper<const T>>
Dedup(const std::vector<T>& items, KeyFn key) {
    std::set<std::wstring> seen;
    std::vector<std::reference_wrapper<const T>> result;
    for (const auto& item : items)
        if (seen.insert(key(item)).second)
            result.emplace_back(item);
    return result;
}

} // namespace KvcForensic::analysis::renderer
