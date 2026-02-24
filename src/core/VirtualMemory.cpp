#include "core/VirtualMemory.h"

#include <cstring>

namespace KvcForensic::core {

VirtualMemory::VirtualMemory(std::span<const std::byte> dump_data, const std::vector<minidump::MemoryRange>& ranges)
    : dump_data_(dump_data), ranges_(ranges) {
}

std::optional<std::uint32_t> VirtualMemory::VaToRva(std::uint64_t va, std::size_t size) const {
    for (const auto& range : ranges_) {
        if (va >= range.start_vva && va < range.start_vva + range.size) {
            std::uint64_t offset_in_range = va - range.start_vva;
            if (offset_in_range + size <= range.size) {
                return range.file_rva + static_cast<std::uint32_t>(offset_in_range);
            }
        }
    }
    return std::nullopt;
}

bool VirtualMemory::ReadBytes(std::uint64_t va, std::size_t size, std::span<std::byte> out_buffer) const {
    if (out_buffer.size() < size) return false;
    
    auto rva_opt = VaToRva(va, size);
    if (!rva_opt) return false;
    
    std::uint32_t rva = rva_opt.value();
    if (rva + size > dump_data_.size()) return false;
    
    std::memcpy(out_buffer.data(), dump_data_.data() + rva, size);
    return true;
}

std::optional<std::uint64_t> VirtualMemory::ReadPointer(std::uint64_t va) const {
    std::uint64_t ptr = 0;
    if (ReadStruct(va, &ptr)) {
        return ptr;
    }
    return std::nullopt;
}

std::optional<std::uint32_t> VirtualMemory::ReadU32(std::uint64_t va) const {
    std::uint32_t val = 0;
    if (ReadStruct(va, &val)) {
        return val;
    }
    return std::nullopt;
}

} // namespace KvcForensic::core
