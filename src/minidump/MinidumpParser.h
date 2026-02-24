#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace KvcForensic::minidump {

struct StreamDirectoryEntry {
    std::uint32_t type = 0;
    std::wstring type_name;
    std::uint32_t data_size = 0;
    std::uint32_t rva = 0;
};

struct SystemVersionInfo {
    std::uint16_t processor_architecture = 0;
    std::uint32_t major = 0;
    std::uint32_t minor = 0;
    std::uint32_t build = 0;
    bool valid = false;
};

struct ModuleInfo {
    std::uint64_t base_address = 0;
    std::uint32_t size = 0;
    std::wstring name;
};

struct MemoryRange {
    std::uint64_t start_vva = 0;
    std::uint64_t size = 0;
    std::uint32_t file_rva = 0;
};

struct MinidumpMetadata {
    std::wstring path;
    std::uint64_t file_size = 0;
    bool valid = false;
    std::wstring error;

    std::uint32_t signature = 0;
    std::uint32_t version = 0;
    std::uint32_t stream_count = 0;
    std::uint32_t stream_directory_rva = 0;
    std::uint32_t checksum = 0;
    std::uint32_t timestamp = 0;
    std::uint64_t flags = 0;

    std::optional<SystemVersionInfo> system_info;
    std::vector<StreamDirectoryEntry> streams;
    std::vector<ModuleInfo> modules;
    std::vector<MemoryRange> memory_ranges;

    std::uint64_t memory64_range_count = 0;
    std::uint64_t memory64_total_bytes = 0;
    std::uint32_t memory_range_count = 0;
    std::uint32_t thread_count = 0;
    std::uint32_t thread_ex_count = 0;
    std::uint32_t unloaded_module_count = 0;
    std::uint32_t handle_descriptor_count = 0;
    std::uint64_t memory_info_entry_count = 0;
    std::uint32_t thread_info_entry_count = 0;
};

class MinidumpParser {
public:
    MinidumpMetadata ParseFile(const std::wstring& path) const;
};

const wchar_t* StreamTypeToString(std::uint32_t type);

} // namespace KvcForensic::minidump
