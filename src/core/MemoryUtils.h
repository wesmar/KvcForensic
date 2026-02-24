#pragma once

#include "lsa/LsaStructures.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <unordered_set>

namespace KvcForensic::core {

inline std::optional<std::size_t> VirtualAddressToOffset(
    const std::uint64_t virtual_address,
    const std::uint64_t image_base,
    const std::size_t mapped_size) {
    if (virtual_address < image_base) {
        return std::nullopt;
    }
    const std::uint64_t delta = virtual_address - image_base;
    if (delta >= mapped_size) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(delta);
}

template <typename T>
std::optional<T> ReadTrivialAt(
    const std::span<const std::byte> memory,
    const std::size_t offset) {
    static_assert(std::is_trivially_copyable_v<T>, "ReadTrivialAt requires trivially copyable T");
    if (offset + sizeof(T) > memory.size()) {
        return std::nullopt;
    }
    std::array<std::byte, sizeof(T)> raw{};
    std::copy_n(memory.begin() + static_cast<std::ptrdiff_t>(offset), sizeof(T), raw.begin());
    return std::bit_cast<T>(raw);
}

template <typename T, typename Callback>
bool WalkLinkedList64(
    const std::span<const std::byte> memory,
    const std::uint64_t list_head_va,
    const std::uint64_t image_base,
    const std::size_t list_entry_offset_in_record,
    const std::size_t max_nodes,
    Callback&& on_record,
    std::wstring* error) {
    static_assert(std::is_trivially_copyable_v<T>, "WalkLinkedList64 requires trivially copyable T");

    if (max_nodes == 0) {
        if (error != nullptr) {
            *error = L"max_nodes must be greater than zero.";
        }
        return false;
    }

    const auto head_offset_opt = VirtualAddressToOffset(list_head_va, image_base, memory.size());
    if (!head_offset_opt.has_value()) {
        if (error != nullptr) {
            *error = L"List head virtual address is outside mapped view.";
        }
        return false;
    }

    const auto head_entry = ReadTrivialAt<lsa::LIST_ENTRY64>(memory, head_offset_opt.value());
    if (!head_entry.has_value()) {
        if (error != nullptr) {
            *error = L"Cannot read LIST_ENTRY head.";
        }
        return false;
    }

    std::unordered_set<std::uint64_t> visited;
    visited.reserve(max_nodes);

    std::uint64_t current_va = head_entry->Flink;
    std::size_t traversed = 0;
    while (current_va != 0 && current_va != list_head_va) {
        if (traversed >= max_nodes) {
            if (error != nullptr) {
                *error = L"Reached max_nodes limit while traversing list.";
            }
            return false;
        }

        if (!visited.insert(current_va).second) {
            if (error != nullptr) {
                *error = L"Detected cycle/duplicate node address in list.";
            }
            return false;
        }

        const auto list_entry_offset_opt = VirtualAddressToOffset(current_va, image_base, memory.size());
        if (!list_entry_offset_opt.has_value()) {
            if (error != nullptr) {
                *error = L"Node LIST_ENTRY virtual address is outside mapped view.";
            }
            return false;
        }

        const std::size_t list_entry_offset = list_entry_offset_opt.value();
        if (list_entry_offset < list_entry_offset_in_record) {
            if (error != nullptr) {
                *error = L"LIST_ENTRY offset is smaller than list_entry_offset_in_record.";
            }
            return false;
        }

        const std::size_t record_offset = list_entry_offset - list_entry_offset_in_record;
        const auto record = ReadTrivialAt<T>(memory, record_offset);
        if (!record.has_value()) {
            if (error != nullptr) {
                *error = L"Cannot read list record object.";
            }
            return false;
        }

        const auto node = ReadTrivialAt<lsa::LIST_ENTRY64>(memory, list_entry_offset);
        if (!node.has_value()) {
            if (error != nullptr) {
                *error = L"Cannot read node LIST_ENTRY.";
            }
            return false;
        }

        on_record(record.value(), record_offset, current_va);
        current_va = node->Flink;
        ++traversed;
    }

    return true;
}

} // namespace KvcForensic::core
