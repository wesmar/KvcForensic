#pragma once

#include <Windows.h>

#include <string>

namespace KvcForensic::core {

inline std::wstring Utf8ToWide(const std::string& input, const UINT code_page = CP_UTF8) {
    if (input.empty()) {
        return L"";
    }
    const int needed = ::MultiByteToWideChar(
        code_page, 0, input.data(), static_cast<int>(input.size()), nullptr, 0);
    if (needed <= 0) {
        return L"";
    }
    std::wstring out(static_cast<std::size_t>(needed), L'\0');
    (void)::MultiByteToWideChar(
        code_page, 0, input.data(), static_cast<int>(input.size()), out.data(), needed);
    return out;
}

inline std::string WideToUtf8(const std::wstring& input, const UINT code_page = CP_UTF8) {
    if (input.empty()) {
        return {};
    }
    const int needed = ::WideCharToMultiByte(
        code_page, 0, input.data(), static_cast<int>(input.size()),
        nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        return {};
    }
    std::string out(static_cast<std::size_t>(needed), '\0');
    (void)::WideCharToMultiByte(
        code_page, 0, input.data(), static_cast<int>(input.size()),
        out.data(), needed, nullptr, nullptr);
    return out;
}

} // namespace KvcForensic::core

