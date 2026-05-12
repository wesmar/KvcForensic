#include "minidump/minidump_parser.h"

#include "core/text_utils.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace kvc::minidump {

namespace {

constexpr std::size_t kModuleEntrySize = 108;
constexpr std::size_t kMemoryDescriptor64Size = 16;

template <typename T>
bool read_at(std::span<const std::byte> data, std::size_t offset, T& out) {
    if (offset > data.size() || sizeof(T) > data.size() - offset) return false;
    std::memcpy(&out, data.data() + offset, sizeof(T));
    return true;
}

std::string read_minidump_utf16_name(std::span<const std::byte> data, std::uint32_t name_rva) {
    std::uint32_t byte_len = 0;
    if (!read_at(data, name_rva, byte_len)) return "<invalid-name-rva>";
    const std::size_t text_offset = static_cast<std::size_t>(name_rva) + 4;
    if ((byte_len % 2u) != 0 || text_offset > data.size() ||
        byte_len > data.size() - text_offset) {
        return "<invalid-name-rva>";
    }
    return core::utf16le_to_utf8(data.subspan(text_offset, byte_len));
}

bool stream_in_bounds(std::span<const std::byte> data, const StreamEntry& s) {
    return s.rva <= data.size() && s.size <= data.size() - s.rva;
}

} // namespace

const char* stream_type_name(std::uint32_t type) {
    switch (static_cast<StreamType>(type)) {
    case StreamType::Unused: return "UnusedStream";
    case StreamType::ThreadList: return "ThreadListStream";
    case StreamType::ModuleList: return "ModuleListStream";
    case StreamType::MemoryList: return "MemoryListStream";
    case StreamType::Exception: return "ExceptionStream";
    case StreamType::SystemInfo: return "SystemInfoStream";
    case StreamType::ThreadExList: return "ThreadExListStream";
    case StreamType::Memory64List: return "Memory64ListStream";
    case StreamType::CommentA: return "CommentStreamA";
    case StreamType::CommentW: return "CommentStreamW";
    case StreamType::HandleData: return "HandleDataStream";
    case StreamType::FunctionTable: return "FunctionTableStream";
    case StreamType::UnloadedModuleList: return "UnloadedModuleListStream";
    case StreamType::MiscInfo: return "MiscInfoStream";
    case StreamType::MemoryInfoList: return "MemoryInfoListStream";
    case StreamType::ThreadInfoList: return "ThreadInfoListStream";
    case StreamType::HandleOperationList: return "HandleOperationListStream";
    case StreamType::Token: return "TokenStream";
    case StreamType::JavaScriptData: return "JavaScriptDataStream";
    case StreamType::SystemMemoryInfo: return "SystemMemoryInfoStream";
    case StreamType::ProcessVmCounters: return "ProcessVmCountersStream";
    case StreamType::IptTrace: return "IptTraceStream";
    case StreamType::ThreadNames: return "ThreadNamesStream";
    default: return "UnknownStreamType";
    }
}

DumpMetadata MinidumpParser::parse(const std::filesystem::path& path) const {
    error_.clear();

    auto reader = std::make_shared<core::MemoryReader>();
    if (!reader->open(path)) {
        error_ = reader->last_error();
        throw std::runtime_error("cannot open dump: " + error_);
    }

    DumpMetadata out{};
    out.path = path;
    out.file_size = reader->size();
    out.reader = reader;

    const auto data = reader->view();
    if (!read_at(data, 0, out.header)) {
        throw std::runtime_error("file too small for minidump header");
    }
    if (out.header.signature != kMinidumpSignature) {
        throw std::runtime_error("invalid minidump signature");
    }

    const std::size_t dir_base = out.header.stream_directory_rva;
    const std::size_t dir_count = out.header.stream_count;
    if (dir_base > data.size() ||
        dir_count > (data.size() - dir_base) / sizeof(DirectoryEntry)) {
        throw std::runtime_error("stream directory out of bounds");
    }

    out.streams.reserve(dir_count);
    for (std::size_t i = 0; i < dir_count; ++i) {
        DirectoryEntry de{};
        if (!read_at(data, dir_base + i * sizeof(DirectoryEntry), de)) {
            throw std::runtime_error("stream directory parse failed");
        }
        out.streams.push_back({de.stream_type, de.location.rva, de.location.data_size});
    }

    for (const auto& s : out.streams) {
        if (!stream_in_bounds(data, s)) continue;
        const std::size_t rva = s.rva;
        const std::size_t size = s.size;
        const auto t = static_cast<StreamType>(s.type);

        if (t == StreamType::SystemInfo && size >= 24) {
            SystemVersion sv{};
            std::uint16_t arch = 0;
            std::uint32_t maj = 0, min = 0, bld = 0;
            if (read_at(data, rva, arch) &&
                read_at(data, rva + 8, maj) &&
                read_at(data, rva + 12, min) &&
                read_at(data, rva + 16, bld)) {
                sv.processor_architecture = arch;
                sv.major = maj;
                sv.minor = min;
                sv.build = bld;
                out.system_info = sv;
            }
            continue;
        }

        if (t == StreamType::ModuleList && size >= 4) {
            std::uint32_t count = 0;
            if (!read_at(data, rva, count)) continue;
            const std::size_t avail = (size - 4) / kModuleEntrySize;
            const std::uint32_t safe = static_cast<std::uint32_t>(
                std::min<std::size_t>(count, avail));
            out.modules.reserve(safe);
            for (std::uint32_t i = 0; i < safe; ++i) {
                const std::size_t off = rva + 4 + static_cast<std::size_t>(i) * kModuleEntrySize;
                ModuleInfo m{};
                std::uint32_t name_rva = 0;
                if (!read_at(data, off, m.base_address) ||
                    !read_at(data, off + 8, m.size) ||
                    !read_at(data, off + 20, name_rva)) {
                    continue;
                }
                m.name = read_minidump_utf16_name(data, name_rva);
                out.modules.push_back(std::move(m));
            }
            continue;
        }

        if (t == StreamType::Memory64List && size >= 16) {
            std::uint64_t count = 0;
            std::uint64_t base_rva = 0;
            if (!read_at(data, rva, count) || !read_at(data, rva + 8, base_rva)) continue;
            const std::size_t avail = (size - 16) / kMemoryDescriptor64Size;
            const std::uint64_t safe = std::min<std::uint64_t>(count, avail);
            const std::uint64_t kU64Max = std::numeric_limits<std::uint64_t>::max();
            const std::uint64_t dump_size = data.size();
            std::uint64_t file_rva = base_rva;
            std::uint64_t total = 0;
            out.memory64_descriptor_count = safe;
            std::uint64_t skipped = 0;
            out.memory_ranges.reserve(static_cast<std::size_t>(safe));
            if (file_rva > dump_size) { out.memory64_skipped_descriptors = safe; continue; }
            for (std::uint64_t i = 0; i < safe; ++i) {
                const std::size_t d = rva + 16 + static_cast<std::size_t>(i) * kMemoryDescriptor64Size;
                std::uint64_t va = 0, bytes = 0;
                if (!read_at(data, d, va) || !read_at(data, d + 8, bytes)) {
                    // Truncated descriptor: count remaining as skipped so the
                    // header-derived descriptor_count still reflects intent.
                    skipped += (safe - i);
                    break;
                }
                // Zero-byte descriptors are valid in DbgHelp records but carry
                // no resident memory; keep them out of the resolver but tally
                // separately so reporting matches Windows DbgHelp counts.
                if (bytes == 0) { ++skipped; continue; }
                if (bytes > kU64Max - va) { skipped += (safe - i); break; }
                if (bytes > dump_size - file_rva) { skipped += (safe - i); break; }
                out.memory_ranges.push_back({va, bytes, file_rva});
                if (bytes > kU64Max - total) total = kU64Max;
                else total += bytes;
                file_rva += bytes;
            }
            out.memory64_total_bytes = total;
            out.memory64_skipped_descriptors = skipped;
            continue;
        }

        if (t == StreamType::MemoryList && size >= 4) {
            std::uint32_t v = 0; read_at(data, rva, v);
            out.memory_list_count = v;
        } else if (t == StreamType::ThreadList && size >= 4) {
            std::uint32_t v = 0; read_at(data, rva, v);
            out.thread_count = v;
        } else if (t == StreamType::ThreadExList && size >= 4) {
            std::uint32_t v = 0; read_at(data, rva, v);
            out.thread_ex_count = v;
        } else if (t == StreamType::UnloadedModuleList && size >= 12) {
            std::uint32_t v = 0; read_at(data, rva + 8, v);
            out.unloaded_module_count = v;
        } else if (t == StreamType::HandleData && size >= 12) {
            std::uint32_t v = 0; read_at(data, rva + 8, v);
            out.handle_descriptor_count = v;
        } else if (t == StreamType::MemoryInfoList && size >= 16) {
            std::uint64_t v = 0; read_at(data, rva + 8, v);
            out.memory_info_entry_count = v;
        } else if (t == StreamType::ThreadInfoList && size >= 12) {
            std::uint32_t v = 0; read_at(data, rva + 8, v);
            out.thread_info_entry_count = v;
        }
    }

    return out;
}

} // namespace kvc::minidump
