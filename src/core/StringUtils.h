#pragma once

#include <algorithm>
#include <cwctype>
#include <string>

namespace KvcForensic::core {

inline std::wstring ToLower(const std::wstring& text) {
    std::wstring out = text;
    std::transform(out.begin(), out.end(), out.begin(),
        [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
    return out;
}

inline bool ContainsInsensitive(const std::wstring& haystack, const std::wstring& needle) {
    return ToLower(haystack).find(ToLower(needle)) != std::wstring::npos;
}

inline bool ContainsInsensitive(const std::wstring& haystack, const wchar_t* needle) {
    return ToLower(haystack).find(ToLower(needle)) != std::wstring::npos;
}

} // namespace KvcForensic::core

