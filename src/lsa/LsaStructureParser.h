#pragma once

#include "lsa/LsaStructures.h"

#include <cstddef>
#include <optional>
#include <span>
#include <string>

namespace KvcForensic::lsa {

struct SessionLayoutValidation {
    bool ok = false;
    std::wstring error;
    std::size_t consumed = 0;
};

std::optional<LSA_LOGON_SESSION_DATA64> ReadSessionData(
    std::span<const std::byte> buffer,
    std::size_t offset);

SessionLayoutValidation ValidateSessionDataLayout(
    std::span<const std::byte> buffer,
    std::size_t offset);

} // namespace KvcForensic::lsa
