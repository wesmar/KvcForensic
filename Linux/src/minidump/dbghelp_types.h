#pragma once

#include <cstdint>

namespace kvc::minidump {

// Minimal subset of MINIDUMP_STREAM_TYPE (dbghelp.h).
enum class StreamType : std::uint32_t {
    Unused = 0,
    ThreadList = 3,
    ModuleList = 4,
    MemoryList = 5,
    Exception = 6,
    SystemInfo = 7,
    ThreadExList = 8,
    Memory64List = 9,
    CommentA = 10,
    CommentW = 11,
    HandleData = 12,
    FunctionTable = 13,
    UnloadedModuleList = 14,
    MiscInfo = 15,
    MemoryInfoList = 16,
    ThreadInfoList = 17,
    HandleOperationList = 18,
    Token = 19,
    JavaScriptData = 20,
    SystemMemoryInfo = 21,
    ProcessVmCounters = 22,
    IptTrace = 23,
    ThreadNames = 24,
};

struct LocationDescriptor {
    std::uint32_t data_size = 0;
    std::uint32_t rva = 0;
};

struct DirectoryEntry {
    std::uint32_t stream_type = 0;
    LocationDescriptor location{};
};

struct Header {
    std::uint32_t signature = 0;
    std::uint32_t version = 0;
    std::uint32_t stream_count = 0;
    std::uint32_t stream_directory_rva = 0;
    std::uint32_t checksum = 0;
    std::uint32_t timestamp = 0;
    std::uint64_t flags = 0;
};

static_assert(sizeof(LocationDescriptor) == 8);
static_assert(sizeof(DirectoryEntry) == 12);
static_assert(sizeof(Header) == 32);

constexpr std::uint32_t kMinidumpSignature = 0x504d444d; // "MDMP"

const char* stream_type_name(std::uint32_t type);

} // namespace kvc::minidump
