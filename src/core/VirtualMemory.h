#pragma once

#include "minidump/MinidumpParser.h"

#include <cstdint>
#include <cstddef>
#include <span>
#include <optional>
#include <vector>

namespace KvcForensic::core {

class VirtualMemory {
public:
    VirtualMemory(std::span<const std::byte> dump_data, const std::vector<minidump::MemoryRange>& ranges);

    std::optional<std::uint32_t> VaToRva(std::uint64_t va, std::size_t size) const;

    bool ReadBytes(std::uint64_t va, std::size_t size, std::span<std::byte> out_buffer) const;
    
    std::optional<std::uint64_t> ReadPointer(std::uint64_t va) const;
    std::optional<std::uint32_t> ReadU32(std::uint64_t va) const;
    
    template <typename T>
    bool ReadStruct(std::uint64_t va, T* out) const {
        return ReadBytes(va, sizeof(T), std::span<std::byte>(reinterpret_cast<std::byte*>(out), sizeof(T)));
    }

private:
    std::span<const std::byte> dump_data_;
    const std::vector<minidump::MemoryRange>& ranges_;
};

} // namespace KvcForensic::core
