#include "core/virtual_memory.h"

#include "core/text_utils.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <sstream>

namespace kvc::core {

VirtualMemory::VirtualMemory(std::span<const std::byte> dump_data,
                             const std::vector<minidump::MemoryRange>& ranges)
    : dump_data_(dump_data), ranges_(ranges) {
    sorted_.resize(ranges_.size());
    for (std::size_t i = 0; i < ranges_.size(); ++i) sorted_[i] = i;
    std::sort(sorted_.begin(), sorted_.end(), [&](std::size_t a, std::size_t b) {
        return ranges_[a].virtual_address < ranges_[b].virtual_address;
    });
}

std::size_t VirtualMemory::find_range(std::uint64_t va) const {
    if (sorted_.empty()) return ranges_.size();

    std::size_t lo = 0;
    std::size_t hi = sorted_.size();
    while (lo < hi) {
        const std::size_t mid = lo + (hi - lo) / 2;
        const auto& r = ranges_[sorted_[mid]];
        if (r.virtual_address <= va) lo = mid + 1;
        else hi = mid;
    }
    if (lo == 0) return ranges_.size();
    const std::size_t idx = sorted_[lo - 1];
    const auto& r = ranges_[idx];
    // Overflow-safe containment: r.size <= UINT64_MAX so the only way
    // r.virtual_address + r.size wraps is if the range itself is malformed.
    // Reject those ranges instead of trusting the addition.
    if (r.size == 0 || r.size > std::numeric_limits<std::uint64_t>::max() - r.virtual_address) {
        return ranges_.size();
    }
    if (va >= r.virtual_address && (va - r.virtual_address) < r.size) return idx;
    return ranges_.size();
}

bool VirtualMemory::contains_va(std::uint64_t va, std::size_t size) const {
    const std::size_t idx = find_range(va);
    if (idx >= ranges_.size()) return false;
    const auto& r = ranges_[idx];
    const std::uint64_t off = va - r.virtual_address;
    return size <= r.size - off;
}

std::optional<std::uint64_t> VirtualMemory::va_to_rva(std::uint64_t va, std::size_t size) const {
    const std::size_t idx = find_range(va);
    if (idx >= ranges_.size()) return std::nullopt;
    const auto& r = ranges_[idx];
    const std::uint64_t off = va - r.virtual_address;
    if (size > r.size - off) return std::nullopt;
    // r.file_rva already validated against dump_data_.size() at parse time,
    // but defend against malformed file_rva anyway.
    if (r.file_rva > dump_data_.size()) return std::nullopt;
    if (off > dump_data_.size() - r.file_rva) return std::nullopt;
    const std::uint64_t file_off = r.file_rva + off;
    if (size > dump_data_.size() - file_off) return std::nullopt;
    return file_off;
}

bool VirtualMemory::read_bytes(std::uint64_t va, std::size_t size, std::span<std::byte> out) const {
    if (out.size() < size) return false;
    const auto rva = va_to_rva(va, size);
    if (!rva) return false;
    std::memcpy(out.data(), dump_data_.data() + *rva, size);
    return true;
}

std::span<const std::byte> VirtualMemory::span_at_va(std::uint64_t va, std::size_t size) const {
    const auto rva = va_to_rva(va, size);
    if (!rva) return {};
    return dump_data_.subspan(static_cast<std::size_t>(*rva), size);
}

std::optional<std::uint64_t> VirtualMemory::read_u64(std::uint64_t va) const {
    std::uint64_t v = 0;
    return read_struct(va, &v) ? std::optional<std::uint64_t>{v} : std::nullopt;
}

std::optional<std::uint32_t> VirtualMemory::read_u32(std::uint64_t va) const {
    std::uint32_t v = 0;
    return read_struct(va, &v) ? std::optional<std::uint32_t>{v} : std::nullopt;
}

std::optional<std::uint16_t> VirtualMemory::read_u16(std::uint64_t va) const {
    std::uint16_t v = 0;
    return read_struct(va, &v) ? std::optional<std::uint16_t>{v} : std::nullopt;
}

std::optional<std::uint8_t> VirtualMemory::read_u8(std::uint64_t va) const {
    std::uint8_t v = 0;
    return read_struct(va, &v) ? std::optional<std::uint8_t>{v} : std::nullopt;
}

std::string VirtualMemory::read_unicode_string(std::uint64_t header_va, std::size_t cap) const {
    // UNICODE_STRING64: u16 Length, u16 MaxLen, u32 pad, u64 Buffer
    std::uint16_t len = 0;
    if (!read_struct(header_va, &len)) return {};
    if (len == 0) return {};
    std::uint64_t buf = 0;
    if (!read_struct(header_va + 8, &buf)) return {};
    if (buf == 0) return {};
    const std::size_t safe_len = std::min<std::size_t>(len, cap);
    std::vector<std::byte> bytes(safe_len);
    if (!read_bytes(buf, safe_len, bytes)) return {};
    return utf16le_to_utf8(bytes);
}

std::string VirtualMemory::read_sid(std::uint64_t sid_va) const {
    if (sid_va == 0) return {};
    const auto rev = read_u8(sid_va);
    if (!rev) return {};
    auto sub_count = read_u8(sid_va + 1);
    if (!sub_count) return {};
    std::uint8_t cnt = std::min<std::uint8_t>(*sub_count, 15);

    std::vector<std::byte> ia(6);
    if (!read_bytes(sid_va + 2, 6, ia)) return {};
    std::uint64_t auth = 0;
    for (int i = 0; i < 6; ++i) {
        auth = (auth << 8) | static_cast<unsigned char>(ia[static_cast<std::size_t>(i)]);
    }

    std::ostringstream ss;
    ss << "S-" << static_cast<int>(*rev) << "-" << auth;
    for (int i = 0; i < cnt; ++i) {
        const auto sa = read_u32(sid_va + 8 + static_cast<std::uint64_t>(i) * 4);
        if (!sa) break;
        ss << "-" << *sa;
    }
    return ss.str();
}

} // namespace kvc::core
