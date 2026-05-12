#include "core/module_index.h"

#include "core/text_utils.h"

#include <algorithm>
#include <limits>

namespace kvc::core {

ModuleIndex::ModuleIndex(const minidump::DumpMetadata& metadata,
                         const VirtualMemory& vmem)
    : metadata_(metadata), vmem_(vmem) {
    build();
}

void ModuleIndex::build() {
    modules_.reserve(metadata_.modules.size());
    const std::uint64_t kU64Max = std::numeric_limits<std::uint64_t>::max();
    const std::uint64_t dump_size = vmem_.dump_data().size();

    for (const auto& mod : metadata_.modules) {
        ModuleSlices ms;
        ms.module = &mod;
        const std::uint64_t mod_start = mod.base_address;
        // Reject pathological module entries (overflow on mod_start+mod.size).
        if (mod.size != 0 && mod.size > kU64Max - mod_start) {
            modules_.push_back(std::move(ms));
            continue;
        }
        const std::uint64_t mod_end = mod_start + mod.size;

        for (const auto& range : metadata_.memory_ranges) {
            if (range.size == 0 || range.size > kU64Max - range.virtual_address) continue;
            const std::uint64_t range_end = range.virtual_address + range.size;
            const std::uint64_t lo = std::max<std::uint64_t>(range.virtual_address, mod_start);
            const std::uint64_t hi = std::min<std::uint64_t>(range_end, mod_end);
            if (lo >= hi) continue;
            const std::uint64_t off_in_range = lo - range.virtual_address;
            if (range.file_rva > dump_size) continue;
            if (off_in_range > dump_size - range.file_rva) continue;
            const std::uint64_t file_off = range.file_rva + off_in_range;
            const std::uint64_t slice_size = hi - lo;
            if (slice_size > dump_size - file_off) continue;
            ModuleMemorySlice s{lo, file_off, static_cast<std::size_t>(slice_size)};
            ms.total_resident_bytes += s.size;
            ms.slices.push_back(s);
        }
        std::sort(ms.slices.begin(), ms.slices.end(),
                  [](const auto& a, const auto& b) { return a.va < b.va; });
        modules_.push_back(std::move(ms));
    }
}

const ModuleSlices* ModuleIndex::find(std::string_view needle) const {
    for (const auto& ms : modules_) {
        if (icontains(ms.module->name, needle)) return &ms;
    }
    return nullptr;
}

const ModuleSlices* ModuleIndex::find_exact(std::string_view filename) const {
    const auto target = to_lower(filename);
    for (const auto& ms : modules_) {
        // Compare basename only (the dump stores full paths).
        std::string_view name = ms.module->name;
        const auto slash = name.find_last_of("\\/");
        if (slash != std::string_view::npos) name.remove_prefix(slash + 1);
        if (to_lower(name) == target) return &ms;
    }
    return nullptr;
}

} // namespace kvc::core
