#pragma once

#include "core/memory_reader.h"
#include "minidump/dbghelp_types.h"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace kvc::minidump {

struct StreamEntry {
    std::uint32_t type = 0;
    std::uint32_t rva = 0;
    std::uint32_t size = 0;
};

struct SystemVersion {
    std::uint16_t processor_architecture = 0;
    std::uint32_t major = 0;
    std::uint32_t minor = 0;
    std::uint32_t build = 0;
};

struct ModuleInfo {
    std::uint64_t base_address = 0;
    std::uint32_t size = 0;
    std::string name; // UTF-8
};

struct MemoryRange {
    std::uint64_t virtual_address = 0;
    std::uint64_t size = 0;
    std::uint64_t file_rva = 0;
};

struct DumpMetadata {
    std::filesystem::path path;
    std::uint64_t file_size = 0;
    Header header{};

    std::optional<SystemVersion> system_info;
    std::vector<StreamEntry> streams;
    std::vector<ModuleInfo> modules;
    std::vector<MemoryRange> memory_ranges;

    std::uint64_t memory64_total_bytes = 0;
    // Raw descriptor count from Memory64ListStream header. Matches the
    // Windows DbgHelp reporting; `memory_ranges.size()` may be smaller after
    // dropping zero-byte or out-of-file descriptors during validation.
    std::uint64_t memory64_descriptor_count = 0;
    std::uint64_t memory64_skipped_descriptors = 0;
    std::uint32_t memory_list_count = 0;
    std::uint32_t thread_count = 0;
    std::uint32_t thread_ex_count = 0;
    std::uint32_t unloaded_module_count = 0;
    std::uint32_t handle_descriptor_count = 0;
    std::uint64_t memory_info_entry_count = 0;
    std::uint32_t thread_info_entry_count = 0;

    // Backing mmap. Memory ranges file_rva fields point into this buffer.
    // Held by shared_ptr so callers can keep the parser-owned view alive.
    std::shared_ptr<core::MemoryReader> reader;

    std::span<const std::byte> file_bytes() const {
        return reader ? reader->view() : std::span<const std::byte>{};
    }
};

class MinidumpParser {
public:
    DumpMetadata parse(const std::filesystem::path& path) const;

    const std::string& last_error() const { return error_; }

private:
    mutable std::string error_;
};

} // namespace kvc::minidump
