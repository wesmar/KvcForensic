#pragma once

#include "minidump/minidump_parser.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace kvc::core {

// VA -> file-offset resolver backed by Memory64ListStream.
// Builds a VA-sorted index for O(log n) lookups.
class VirtualMemory {
public:
    VirtualMemory(std::span<const std::byte> dump_data,
                  const std::vector<minidump::MemoryRange>& ranges);

    // True iff [va, va+size) is fully inside one mapped range.
    bool contains_va(std::uint64_t va, std::size_t size) const;

    // Map VA to file offset (RVA into dump). nullopt when not mapped or too small.
    std::optional<std::uint64_t> va_to_rva(std::uint64_t va, std::size_t size) const;

    // Read a contiguous chunk by VA. Returns false on partial / out-of-range.
    bool read_bytes(std::uint64_t va, std::size_t size, std::span<std::byte> out) const;

    // Span pointing into the mmap. Empty span if not fully mapped.
    std::span<const std::byte> span_at_va(std::uint64_t va, std::size_t size) const;

    template <typename T>
    bool read_struct(std::uint64_t va, T* out) const {
        return read_bytes(va, sizeof(T),
                          std::span<std::byte>(reinterpret_cast<std::byte*>(out), sizeof(T)));
    }

    std::optional<std::uint64_t> read_u64(std::uint64_t va) const;
    std::optional<std::uint32_t> read_u32(std::uint64_t va) const;
    std::optional<std::uint16_t> read_u16(std::uint64_t va) const;
    std::optional<std::uint8_t> read_u8(std::uint64_t va) const;

    // UTF-8 decoded UNICODE_STRING (16 bytes header) at given VA.
    // Returns empty string on any failure.
    std::string read_unicode_string(std::uint64_t string_header_va, std::size_t cap = 1024) const;

    // SID at VA into Windows "S-1-..." string form. "" if not a valid SID head.
    std::string read_sid(std::uint64_t sid_va) const;

    std::span<const std::byte> dump_data() const { return dump_data_; }
    const std::vector<minidump::MemoryRange>& ranges() const { return ranges_; }
    const std::vector<std::size_t>& sorted_index() const { return sorted_; }

private:
    std::span<const std::byte> dump_data_;
    const std::vector<minidump::MemoryRange>& ranges_;
    std::vector<std::size_t> sorted_; // indices into ranges_, sorted by virtual_address

    // Returns the range index covering va, or ranges_.size() if none.
    std::size_t find_range(std::uint64_t va) const;
};

} // namespace kvc::core
