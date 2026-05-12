#include "core/signature_scanner.h"

#include <cstring>

namespace kvc::core {

namespace {

// Boyer-Moore-Horoosp would be faster, but for ~10-byte patterns and
// ~few-MB module windows the difference is negligible. Keep memcmp loop.
std::vector<std::size_t> find_all(std::span<const std::byte> hay,
                                  std::span<const std::uint8_t> needle) {
    std::vector<std::size_t> hits;
    if (needle.empty() || needle.size() > hay.size()) return hits;
    const std::size_t end = hay.size() - needle.size();
    for (std::size_t i = 0; i <= end; ++i) {
        if (std::memcmp(hay.data() + i, needle.data(), needle.size()) == 0) {
            hits.push_back(i);
        }
    }
    return hits;
}

} // namespace

std::vector<std::uint64_t> scan_module(
    const VirtualMemory& vmem,
    const ModuleSlices& module,
    std::span<const std::uint8_t> needle) {
    std::vector<std::uint64_t> out;
    if (needle.empty()) return out;
    const auto dump = vmem.dump_data();
    for (const auto& s : module.slices) {
        if (s.size < needle.size()) continue;
        const auto win = dump.subspan(static_cast<std::size_t>(s.rva), s.size);
        const auto hits = find_all(win, needle);
        for (auto idx : hits) {
            out.push_back(s.va + idx);
        }
    }
    return out;
}

std::uint64_t scan_module_first(
    const VirtualMemory& vmem,
    const ModuleSlices& module,
    std::span<const std::uint8_t> needle) {
    if (needle.empty()) return 0;
    const auto dump = vmem.dump_data();
    for (const auto& s : module.slices) {
        if (s.size < needle.size()) continue;
        const auto win = dump.subspan(static_cast<std::size_t>(s.rva), s.size);
        const std::size_t end = win.size() - needle.size();
        for (std::size_t i = 0; i <= end; ++i) {
            if (std::memcmp(win.data() + i, needle.data(), needle.size()) == 0) {
                return s.va + i;
            }
        }
    }
    return 0;
}

std::uint64_t scan_module_first(
    const VirtualMemory& vmem,
    const ModuleIndex& index,
    std::string_view module_substring,
    std::span<const std::uint8_t> needle) {
    const auto* m = index.find(module_substring);
    if (!m) return 0;
    return scan_module_first(vmem, *m, needle);
}

} // namespace kvc::core
