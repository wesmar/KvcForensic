#include "lsa/LsaStructureParser.h"

#include <cstring>

namespace KvcForensic::lsa {

std::optional<LSA_LOGON_SESSION_DATA64> ReadSessionData(
    const std::span<const std::byte> buffer,
    const std::size_t offset) {
    if (offset + sizeof(LSA_LOGON_SESSION_DATA64) > buffer.size()) {
        return std::nullopt;
    }

    LSA_LOGON_SESSION_DATA64 out{};
    std::memcpy(&out, buffer.data() + offset, sizeof(out));
    return out;
}

SessionLayoutValidation ValidateSessionDataLayout(
    const std::span<const std::byte> buffer,
    const std::size_t offset) {
    SessionLayoutValidation result{};

    const auto session = ReadSessionData(buffer, offset);
    if (!session.has_value()) {
        result.error = L"Buffer is too small for LSA_LOGON_SESSION_DATA64.";
        return result;
    }

    if (session->Size != 0 && session->Size < sizeof(LSA_LOGON_SESSION_DATA64)) {
        result.error = L"Session size field is smaller than expected structure size.";
        return result;
    }

    result.ok = true;
    result.consumed = sizeof(LSA_LOGON_SESSION_DATA64);
    return result;
}

} // namespace KvcForensic::lsa
