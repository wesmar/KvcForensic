#pragma once

#include "core/virtual_memory.h"
#include "minidump/minidump_parser.h"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kvc::core {

// A single contiguous chunk of a module that survives inside the dump's
// Memory64ListStream. Multiple slices may exist per module if the module
// spans several memory ranges.
struct ModuleMemorySlice {
    std::uint64_t va = 0;        // start VA
    std::uint64_t rva = 0;       // file offset
    std::size_t size = 0;        // bytes resident in dump
};

// Per-module summary plus its mapped slices.
struct ModuleSlices {
    const minidump::ModuleInfo* module = nullptr;
    std::vector<ModuleMemorySlice> slices;
    std::size_t total_resident_bytes = 0;
};

class ModuleIndex {
public:
    ModuleIndex(const minidump::DumpMetadata& metadata,
                const VirtualMemory& vmem);

    // Case-insensitive lookup of a module whose name *contains* the given
    // substring (e.g. "lsasrv.dll"). nullptr when none.
    const ModuleSlices* find(std::string_view needle) const;

    // Same but exposes the mutable module info wrapper. nullptr when missing.
    const ModuleSlices* find_exact(std::string_view filename) const;

    const std::vector<ModuleSlices>& all() const { return modules_; }

private:
    const minidump::DumpMetadata& metadata_;
    const VirtualMemory& vmem_;
    std::vector<ModuleSlices> modules_;

    void build();
};

} // namespace kvc::core
