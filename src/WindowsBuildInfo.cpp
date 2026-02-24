#include "WindowsBuildInfo.h"

#include <Windows.h>
#include <winternl.h>

#include <sstream>

namespace KvcForensic::platform {

namespace {
using RtlGetVersionFn = LONG (WINAPI*)(PRTL_OSVERSIONINFOW);
}

OsBuildInfo QueryOsBuild() {
    OsBuildInfo info{};

    const HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        info.error = L"GetModuleHandleW(ntdll.dll) failed.";
        return info;
    }

    const auto rtlGetVersion = reinterpret_cast<RtlGetVersionFn>(
        ::GetProcAddress(ntdll, "RtlGetVersion"));
    if (rtlGetVersion == nullptr) {
        info.error = L"GetProcAddress(RtlGetVersion) failed.";
        return info;
    }

    RTL_OSVERSIONINFOW osvi{};
    osvi.dwOSVersionInfoSize = sizeof(osvi);

    if (rtlGetVersion(&osvi) != 0) {
        info.error = L"RtlGetVersion returned non-zero status.";
        return info;
    }

    info.major = osvi.dwMajorVersion;
    info.minor = osvi.dwMinorVersion;
    info.build = osvi.dwBuildNumber;
    info.ok = true;
    return info;
}

std::wstring BuildInfoToText(const OsBuildInfo& info) {
    std::wstringstream ss;
    if (!info.ok) {
        ss << L"OS query failed: " << info.error;
        return ss.str();
    }

    ss << L"Detected OS build: "
       << info.major << L'.' << info.minor << L'.' << info.build;
    return ss.str();
}

} // namespace KvcForensic::platform
