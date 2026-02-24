#include "security/TrustedInstaller.h"
#include "core/HandleGuards.h"

#include <tlhelp32.h>
#include <string_view>

#pragma comment(lib, "advapi32.lib")

namespace KvcForensic::security {

namespace {

using namespace KvcForensic::core;

bool EnablePrivilege(std::wstring_view privilegeName) {
    HandleGuard token;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, token.addressof())) {
        return false;
    }

    LUID luid;
    if (!::LookupPrivilegeValueW(nullptr, privilegeName.data(), &luid)) {
        return false;
    }

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    ::AdjustTokenPrivileges(token.get(), FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);
    return ::GetLastError() == ERROR_SUCCESS;
}

DWORD GetProcessIdByName(std::wstring_view processName) {
    HandleGuard snapshot(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot) return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (::Process32FirstW(snapshot.get(), &pe)) {
        do {
            if (std::wstring_view(pe.szExeFile) == processName) {
                return pe.th32ProcessID;
            }
        } while (::Process32NextW(snapshot.get(), &pe));
    }
    return 0;
}

bool ImpersonateSystem() {
    if (!EnablePrivilege(L"SeDebugPrivilege")) return false;

    DWORD systemPid = GetProcessIdByName(L"winlogon.exe");
    if (systemPid == 0) return false;

    HandleGuard systemProcess(::OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, systemPid));
    if (!systemProcess) return false;

    HandleGuard systemToken;
    if (!::OpenProcessToken(systemProcess.get(), TOKEN_DUPLICATE | TOKEN_QUERY, systemToken.addressof())) {
        return false;
    }

    HandleGuard duplicatedToken;
    if (!::DuplicateTokenEx(systemToken.get(), MAXIMUM_ALLOWED, nullptr, SecurityImpersonation,
                            TokenImpersonation, duplicatedToken.addressof())) {
        return false;
    }

    return ::ImpersonateLoggedOnUser(duplicatedToken.get()) != FALSE;
}

DWORD StartTrustedInstallerService() {
    ScHandleGuard scm(::OpenSCManagerW(nullptr, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT));
    if (!scm) return 0;

    ScHandleGuard service(::OpenServiceW(scm.get(), L"TrustedInstaller", SERVICE_QUERY_STATUS | SERVICE_START));
    if (!service) return 0;

    SERVICE_STATUS_PROCESS statusBuffer{};
    DWORD bytesNeeded = 0;

    if (!::QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&statusBuffer),
                                sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)) {
        return 0;
    }

    if (statusBuffer.dwCurrentState == SERVICE_RUNNING) {
        return statusBuffer.dwProcessId;
    }

    if (statusBuffer.dwCurrentState == SERVICE_STOPPED) {
        if (!::StartServiceW(service.get(), 0, nullptr)) {
            return 0;
        }
    }

    constexpr int kMaxPolls = 10;
    constexpr DWORD kPollIntervalMs = 100;
    for (int i = 0; i < kMaxPolls; ++i) {
        if (::QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&statusBuffer),
                                   sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)) {
            if (statusBuffer.dwCurrentState == SERVICE_RUNNING) {
                return statusBuffer.dwProcessId;
            }
            if (statusBuffer.dwCurrentState == SERVICE_STOPPED) {
                break;
            }
        } else {
            break;
        }
        ::Sleep(kPollIntervalMs);
    }

    return 0;
}

} // namespace

bool TrustedInstaller::Impersonate() {
    if (!EnablePrivilege(L"SeDebugPrivilege") || !EnablePrivilege(L"SeImpersonatePrivilege")) {
        return false;
    }

    ImpersonationGuard systemImpersonation;
    if (!ImpersonateSystem()) {
        return false;
    }
    systemImpersonation.adopt();

    DWORD tiPid = StartTrustedInstallerService();
    if (tiPid == 0) return false;

    HandleGuard tiProcess(::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, tiPid));
    if (!tiProcess) return false;

    HandleGuard tiToken;
    if (!::OpenProcessToken(tiProcess.get(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, tiToken.addressof())) {
        return false;
    }

    HandleGuard duplicatedToken;
    if (!::DuplicateTokenEx(tiToken.get(), MAXIMUM_ALLOWED, nullptr, SecurityImpersonation,
                            TokenImpersonation, duplicatedToken.addressof())) {
        return false;
    }

    // Enable classic TI privileges we might need (Backup, Restore, Debug, Impersonate, Tcb)
    const wchar_t* privilegesToEnable[] = {
        L"SeBackupPrivilege",
        L"SeRestorePrivilege",
        L"SeDebugPrivilege",
        L"SeImpersonatePrivilege",
        L"SeTcbPrivilege",
        L"SeTakeOwnershipPrivilege",
        L"SeSecurityPrivilege"
    };

    for (const auto& priv : privilegesToEnable) {
        LUID luid;
        if (::LookupPrivilegeValueW(nullptr, priv, &luid)) {
            TOKEN_PRIVILEGES tp{};
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            ::AdjustTokenPrivileges(duplicatedToken.get(), FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);
        }
    }

    bool success = ::ImpersonateLoggedOnUser(duplicatedToken.get()) != FALSE;
    if (success) {
        // systemImpersonation will revert first, but ImpersonateLoggedOnUser overwrites thread token.
        // RevertToSelf() in Revert() will clear it completely.
        systemImpersonation.release(); 
    }
    return success;
}

void TrustedInstaller::Revert() {
    ::RevertToSelf();
}

bool TrustedInstaller::RunCommand(const std::wstring& commandLine) {
    if (!EnablePrivilege(L"SeDebugPrivilege") || !EnablePrivilege(L"SeImpersonatePrivilege")) {
        return false;
    }

    ImpersonationGuard systemImpersonation;
    if (!ImpersonateSystem()) {
        return false;
    }
    systemImpersonation.adopt();

    DWORD tiPid = StartTrustedInstallerService();
    if (tiPid == 0) return false;

    HandleGuard tiProcess(::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, tiPid));
    if (!tiProcess) return false;

    HandleGuard tiToken;
    if (!::OpenProcessToken(tiProcess.get(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, tiToken.addressof())) {
        return false;
    }

    HandleGuard duplicatedToken;
    // Use TokenPrimary for CreateProcessWithTokenW
    if (!::DuplicateTokenEx(tiToken.get(), MAXIMUM_ALLOWED, nullptr, SecurityImpersonation,
                            TokenPrimary, duplicatedToken.addressof())) {
        return false;
    }

    // Wrap in "cmd.exe /k <command>" so the console window stays open after
    // the command finishes. CREATE_NEW_CONSOLE opens a visible, independent
    // console window instead of inheriting (or not showing) the parent console.
    std::wstring mutableCmd = L"cmd.exe /k " + commandLine;

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    BOOL result = ::CreateProcessWithTokenW(
        duplicatedToken.get(),
        0,
        nullptr,
        mutableCmd.data(),
        CREATE_NEW_CONSOLE,
        nullptr,
        nullptr,
        &si,
        &pi
    );

    if (result) {
        // Don't wait — let the new console window live independently.
        ::CloseHandle(pi.hThread);
        ::CloseHandle(pi.hProcess);
    }

    return result != FALSE;
}

} // namespace KvcForensic::security
