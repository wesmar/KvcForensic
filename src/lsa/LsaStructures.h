#pragma once

#include <cstdint>

namespace KvcForensic::lsa {

// Minimal x64 structures used for safe layout validation in dump buffers.
struct LUID64 {
    std::uint32_t LowPart = 0;
    std::int32_t HighPart = 0;
};

struct LIST_ENTRY64 {
    std::uint64_t Flink = 0;
    std::uint64_t Blink = 0;
};

struct UNICODE_STRING64 {
    std::uint16_t Length = 0;
    std::uint16_t MaximumLength = 0;
    std::uint32_t Padding = 0;
    std::uint64_t Buffer = 0;
};

// Simplified x64 layout for session metadata parsing (no secret fields).
struct LSA_LOGON_SESSION_DATA64 {
    std::uint32_t Size = 0;
    std::uint32_t Reserved0 = 0;
    LUID64 LogonId{};
    UNICODE_STRING64 UserName{};
    UNICODE_STRING64 LogonDomain{};
    UNICODE_STRING64 AuthenticationPackage{};
    std::uint32_t LogonType = 0;
    std::uint32_t Session = 0;
    std::uint64_t Sid = 0;
    std::int64_t LogonTime = 0;
    UNICODE_STRING64 LogonServer{};
    UNICODE_STRING64 DnsDomainName{};
    UNICODE_STRING64 Upn{};
};

static_assert(sizeof(LUID64) == 8, "Unexpected LUID64 size");
static_assert(sizeof(LIST_ENTRY64) == 16, "Unexpected LIST_ENTRY64 size");
static_assert(sizeof(UNICODE_STRING64) == 16, "Unexpected UNICODE_STRING64 size");
static_assert(sizeof(LSA_LOGON_SESSION_DATA64) == 136, "Unexpected LSA_LOGON_SESSION_DATA64 size");

} // namespace KvcForensic::lsa
