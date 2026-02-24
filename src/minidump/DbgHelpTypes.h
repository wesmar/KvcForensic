#pragma once

#include <cstdint>

namespace KvcForensic::minidump {

// Subset and naming compatible with DbgHelp.h MINIDUMP_STREAM_TYPE.
enum class MINIDUMP_STREAM_TYPE : std::uint32_t {
    UnusedStream = 0,
    ReservedStream0 = 1,
    ReservedStream1 = 2,
    ThreadListStream = 3,
    ModuleListStream = 4,
    MemoryListStream = 5,
    ExceptionStream = 6,
    SystemInfoStream = 7,
    ThreadExListStream = 8,
    Memory64ListStream = 9,
    CommentStreamA = 10,
    CommentStreamW = 11,
    HandleDataStream = 12,
    FunctionTableStream = 13,
    UnloadedModuleListStream = 14,
    MiscInfoStream = 15,
    MemoryInfoListStream = 16,
    ThreadInfoListStream = 17,
    HandleOperationListStream = 18,
    TokenStream = 19,
    JavaScriptDataStream = 20,
    SystemMemoryInfoStream = 21,
    ProcessVmCountersStream = 22,
    IptTraceStream = 23,
    ThreadNamesStream = 24,
    ceStreamNull = 25
};

struct MINIDUMP_LOCATION_DESCRIPTOR {
    std::uint32_t DataSize = 0;
    std::uint32_t Rva = 0;
};

struct MINIDUMP_DIRECTORY {
    std::uint32_t StreamType = 0;
    MINIDUMP_LOCATION_DESCRIPTOR Location{};
};

struct MINIDUMP_HEADER {
    std::uint32_t Signature = 0;
    std::uint32_t Version = 0;
    std::uint32_t NumberOfStreams = 0;
    std::uint32_t StreamDirectoryRva = 0;
    std::uint32_t CheckSum = 0;
    std::uint32_t TimeDateStamp = 0;
    std::uint64_t Flags = 0;
};

static_assert(sizeof(MINIDUMP_LOCATION_DESCRIPTOR) == 8, "Unexpected MINIDUMP_LOCATION_DESCRIPTOR size");
static_assert(sizeof(MINIDUMP_DIRECTORY) == 12, "Unexpected MINIDUMP_DIRECTORY size");
static_assert(sizeof(MINIDUMP_HEADER) == 32, "Unexpected MINIDUMP_HEADER size");

} // namespace KvcForensic::minidump
