#pragma once

#include <windows.h>
#include <string>

namespace KvcForensic::security {

class TrustedInstaller {
public:
    // Enables required privileges and impersonates TrustedInstaller for the current thread.
    // Returns true on success.
    static bool Impersonate();

    // Reverts the current thread to its original token.
    static void Revert();

    // Executes a command line as TrustedInstaller.
    static bool RunCommand(const std::wstring& commandLine);
};

} // namespace KvcForensic::security
