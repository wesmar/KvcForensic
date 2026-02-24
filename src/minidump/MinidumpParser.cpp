#include "minidump/MinidumpParser.h"

#include "core/MemoryReader.h"
#include "minidump/DbgHelpTypes.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <span>

namespace KvcForensic::minidump {

namespace {

constexpr std::uint32_t kMinidumpSignature = 0x504d444d; // "MDMP"
constexpr std::size_t kSystemInfoMinSize = 24;
constexpr std::size_t kModuleListPrefixSize = 4;
constexpr std::size_t kModuleEntrySize = 108;
constexpr std::size_t kModuleNameLengthFieldSize = 4;
constexpr std::size_t kMemoryDescriptor64Size = 16;

template <typename T>
bool ReadStructAt(const std::span<const std::byte> data, const std::size_t offset, T* out) {
    if (offset + sizeof(T) > data.size()) {
        return false;
    }
    std::memcpy(out, data.data() + offset, sizeof(T));
    return true;
}

std::uint16_t ReadU16(const std::span<const std::byte> data, const std::size_t offset, bool* ok) {
    std::uint16_t v = 0;
    *ok = ReadStructAt(data, offset, &v);
    return v;
}

std::uint32_t ReadU32(const std::span<const std::byte> data, const std::size_t offset, bool* ok) {
    std::uint32_t v = 0;
    *ok = ReadStructAt(data, offset, &v);
    return v;
}

std::uint64_t ReadU64(const std::span<const std::byte> data, const std::size_t offset, bool* ok) {
    std::uint64_t v = 0;
    *ok = ReadStructAt(data, offset, &v);
    return v;
}

std::wstring ReadMinidumpUtf16String(
    const std::span<const std::byte> data,
    const std::uint32_t rva,
    bool* ok) {
    const std::size_t base = static_cast<std::size_t>(rva);
    const std::uint32_t byte_len = ReadU32(data, base, ok);
    if (!*ok) {
        return L"";
    }

    const std::size_t str_offset = base + kModuleNameLengthFieldSize;
    const std::size_t str_end = str_offset + byte_len;
    if (str_end > data.size() || (byte_len % 2) != 0) {
        *ok = false;
        return L"";
    }

    std::wstring out;
    out.reserve(byte_len / 2);
    for (std::size_t i = 0; i < byte_len; i += 2) {
        const auto ch = static_cast<wchar_t>(ReadU16(data, str_offset + i, ok));
        if (!*ok) {
            return L"";
        }
        out.push_back(ch);
    }
    return out;
}

} // namespace

const wchar_t* StreamTypeToString(const std::uint32_t type) {
    switch (static_cast<MINIDUMP_STREAM_TYPE>(type)) {
    case MINIDUMP_STREAM_TYPE::UnusedStream: return L"UnusedStream";
    case MINIDUMP_STREAM_TYPE::ThreadListStream: return L"ThreadListStream";
    case MINIDUMP_STREAM_TYPE::ModuleListStream: return L"ModuleListStream";
    case MINIDUMP_STREAM_TYPE::MemoryListStream: return L"MemoryListStream";
    case MINIDUMP_STREAM_TYPE::ExceptionStream: return L"ExceptionStream";
    case MINIDUMP_STREAM_TYPE::SystemInfoStream: return L"SystemInfoStream";
    case MINIDUMP_STREAM_TYPE::ThreadExListStream: return L"ThreadExListStream";
    case MINIDUMP_STREAM_TYPE::Memory64ListStream: return L"Memory64ListStream";
    case MINIDUMP_STREAM_TYPE::CommentStreamA: return L"CommentStreamA";
    case MINIDUMP_STREAM_TYPE::CommentStreamW: return L"CommentStreamW";
    case MINIDUMP_STREAM_TYPE::HandleDataStream: return L"HandleDataStream";
    case MINIDUMP_STREAM_TYPE::FunctionTableStream: return L"FunctionTableStream";
    case MINIDUMP_STREAM_TYPE::UnloadedModuleListStream: return L"UnloadedModuleListStream";
    case MINIDUMP_STREAM_TYPE::MiscInfoStream: return L"MiscInfoStream";
    case MINIDUMP_STREAM_TYPE::MemoryInfoListStream: return L"MemoryInfoListStream";
    case MINIDUMP_STREAM_TYPE::ThreadInfoListStream: return L"ThreadInfoListStream";
    case MINIDUMP_STREAM_TYPE::HandleOperationListStream: return L"HandleOperationListStream";
    case MINIDUMP_STREAM_TYPE::TokenStream: return L"TokenStream";
    case MINIDUMP_STREAM_TYPE::JavaScriptDataStream: return L"JavaScriptDataStream";
    case MINIDUMP_STREAM_TYPE::SystemMemoryInfoStream: return L"SystemMemoryInfoStream";
    case MINIDUMP_STREAM_TYPE::ProcessVmCountersStream: return L"ProcessVmCountersStream";
    case MINIDUMP_STREAM_TYPE::IptTraceStream: return L"IptTraceStream";
    case MINIDUMP_STREAM_TYPE::ThreadNamesStream: return L"ThreadNamesStream";
    default: return L"UnknownStreamType";
    }
}

MinidumpMetadata MinidumpParser::ParseFile(const std::wstring& path) const {
    MinidumpMetadata out{};
    out.path = path;

    core::MemoryReader reader;
    if (!reader.Open(path)) {
        out.error = reader.LastError().empty() ? L"Cannot open dump file." : reader.LastError();
        return out;
    }

    const std::span<const std::byte> data = reader.View();
    out.file_size = reader.Size();
    if (data.empty()) {
        out.error = L"Mapped file view is empty.";
        return out;
    }

    MINIDUMP_HEADER header{};
    if (!ReadStructAt(data, 0, &header)) {
        out.error = L"File is too small for MINIDUMP header.";
        return out;
    }
    out.signature = header.Signature;
    out.version = header.Version;
    out.stream_count = header.NumberOfStreams;
    out.stream_directory_rva = header.StreamDirectoryRva;
    out.checksum = header.CheckSum;
    out.timestamp = header.TimeDateStamp;
    out.flags = header.Flags;

    if (out.signature != kMinidumpSignature) {
        out.error = L"Invalid MINIDUMP signature.";
        return out;
    }

    const std::size_t directory_base = static_cast<std::size_t>(out.stream_directory_rva);
    const std::size_t directory_size = static_cast<std::size_t>(out.stream_count) * sizeof(MINIDUMP_DIRECTORY);
    if (directory_base + directory_size > data.size()) {
        out.error = L"Stream directory is out of file bounds.";
        return out;
    }

    out.streams.reserve(out.stream_count);
    std::vector<MINIDUMP_DIRECTORY> directories;
    directories.reserve(out.stream_count);
    for (std::uint32_t i = 0; i < out.stream_count; ++i) {
        const std::size_t off = directory_base + static_cast<std::size_t>(i) * sizeof(MINIDUMP_DIRECTORY);
        MINIDUMP_DIRECTORY dir{};
        if (!ReadStructAt(data, off, &dir)) {
            out.error = L"Stream directory entry parse failed.";
            return out;
        }

        directories.push_back(dir);
        out.streams.push_back(StreamDirectoryEntry{
            dir.StreamType,
            StreamTypeToString(dir.StreamType),
            dir.Location.DataSize,
            dir.Location.Rva
        });
    }

    bool ok = true;
    for (const auto& dir : directories) {
        const std::size_t rva = static_cast<std::size_t>(dir.Location.Rva);
        const std::size_t size = static_cast<std::size_t>(dir.Location.DataSize);
        if (rva + size > data.size()) {
            continue;
        }

        const auto stream_type = static_cast<MINIDUMP_STREAM_TYPE>(dir.StreamType);
        if (stream_type == MINIDUMP_STREAM_TYPE::SystemInfoStream && size >= kSystemInfoMinSize) {
            SystemVersionInfo sys{};
            sys.processor_architecture = ReadU16(data, rva, &ok);
            (void)ReadU16(data, rva + 2, &ok);
            (void)ReadU16(data, rva + 4, &ok);
            sys.major = ReadU32(data, rva + 8, &ok);
            sys.minor = ReadU32(data, rva + 12, &ok);
            sys.build = ReadU32(data, rva + 16, &ok);
            sys.valid = ok;
            if (ok) {
                out.system_info = sys;
            }
            ok = true;
        }

        if (stream_type == MINIDUMP_STREAM_TYPE::ModuleListStream && size >= kModuleListPrefixSize) {
            const std::uint32_t module_count = ReadU32(data, rva, &ok);
            if (!ok) {
                ok = true;
                continue;
            }

            const std::size_t module_base = rva + kModuleListPrefixSize;
            const std::size_t max_possible = (size - kModuleListPrefixSize) / kModuleEntrySize;
            const std::uint32_t safe_count = static_cast<std::uint32_t>(
                std::min<std::size_t>(module_count, max_possible));
            out.modules.reserve(safe_count);

            for (std::uint32_t i = 0; i < safe_count; ++i) {
                const std::size_t m = module_base + static_cast<std::size_t>(i) * kModuleEntrySize;
                ModuleInfo mod{};
                mod.base_address = ReadU64(data, m, &ok);
                mod.size = ReadU32(data, m + 8, &ok);
                const std::uint32_t name_rva = ReadU32(data, m + 20, &ok);
                if (!ok) {
                    ok = true;
                    continue;
                }

                mod.name = ReadMinidumpUtf16String(data, name_rva, &ok);
                if (!ok) {
                    ok = true;
                    mod.name = L"<invalid-name-rva>";
                }
                out.modules.push_back(std::move(mod));
            }
        }

        if (stream_type == MINIDUMP_STREAM_TYPE::Memory64ListStream && size >= 16) {
            const std::uint64_t range_count = ReadU64(data, rva, &ok);
            const std::uint64_t base_rva = ReadU64(data, rva + 8, &ok);
            if (!ok) {
                ok = true;
                continue;
            }

            const std::size_t descriptors_offset = rva + 16;
            const std::size_t available_descriptors = (size - 16) / kMemoryDescriptor64Size;
            const std::uint64_t safe_count = (std::min)(range_count, static_cast<std::uint64_t>(available_descriptors));
            std::uint64_t total_bytes = 0;
            std::uint32_t current_rva = static_cast<std::uint32_t>(base_rva);

            out.memory_ranges.reserve(static_cast<std::size_t>(safe_count));

            for (std::uint64_t i = 0; i < safe_count; ++i) {
                const std::size_t d = descriptors_offset + static_cast<std::size_t>(i) * kMemoryDescriptor64Size;
                const std::uint64_t vva = ReadU64(data, d, &ok);
                const std::uint64_t bytes = ReadU64(data, d + 8, &ok);
                if (!ok) {
                    ok = true;
                    break;
                }
                
                out.memory_ranges.push_back({vva, bytes, current_rva});
                
                total_bytes += bytes;
                current_rva += static_cast<std::uint32_t>(bytes);
            }
            out.memory64_range_count = safe_count;
            out.memory64_total_bytes = total_bytes;
        }

        if (stream_type == MINIDUMP_STREAM_TYPE::MemoryListStream && size >= 4) {
            out.memory_range_count = ReadU32(data, rva, &ok);
            if (!ok) {
                out.memory_range_count = 0;
                ok = true;
            }
        }

        if (stream_type == MINIDUMP_STREAM_TYPE::ThreadListStream && size >= 4) {
            out.thread_count = ReadU32(data, rva, &ok);
            if (!ok) {
                out.thread_count = 0;
                ok = true;
            }
        }

        if (stream_type == MINIDUMP_STREAM_TYPE::ThreadExListStream && size >= 4) {
            out.thread_ex_count = ReadU32(data, rva, &ok);
            if (!ok) {
                out.thread_ex_count = 0;
                ok = true;
            }
        }

        if (stream_type == MINIDUMP_STREAM_TYPE::UnloadedModuleListStream && size >= 12) {
            out.unloaded_module_count = ReadU32(data, rva + 8, &ok);
            if (!ok) {
                out.unloaded_module_count = 0;
                ok = true;
            }
        }

        if (stream_type == MINIDUMP_STREAM_TYPE::HandleDataStream && size >= 12) {
            out.handle_descriptor_count = ReadU32(data, rva + 8, &ok);
            if (!ok) {
                out.handle_descriptor_count = 0;
                ok = true;
            }
        }

        if (stream_type == MINIDUMP_STREAM_TYPE::MemoryInfoListStream && size >= 16) {
            out.memory_info_entry_count = ReadU64(data, rva + 8, &ok);
            if (!ok) {
                out.memory_info_entry_count = 0;
                ok = true;
            }
        }

        if (stream_type == MINIDUMP_STREAM_TYPE::ThreadInfoListStream && size >= 12) {
            out.thread_info_entry_count = ReadU32(data, rva + 8, &ok);
            if (!ok) {
                out.thread_info_entry_count = 0;
                ok = true;
            }
        }
    }

    out.valid = true;
    return out;
}

} // namespace KvcForensic::minidump
