#pragma once

#include "core/module_index.h"
#include "core/virtual_memory.h"

#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace kvc::core {

// Bare exact-byte scanner across a module's resident slices.
// Returns VA hits (not file offsets).
std::vector<std::uint64_t> scan_module(
    const VirtualMemory& vmem,
    const ModuleSlices& module,
    std::span<const std::uint8_t> needle);

// First hit only. 0 when not found.
std::uint64_t scan_module_first(
    const VirtualMemory& vmem,
    const ModuleSlices& module,
    std::span<const std::uint8_t> needle);

// Convenience: locate-by-name then scan_module_first.
std::uint64_t scan_module_first(
    const VirtualMemory& vmem,
    const ModuleIndex& index,
    std::string_view module_substring,
    std::span<const std::uint8_t> needle);

} // namespace kvc::core
