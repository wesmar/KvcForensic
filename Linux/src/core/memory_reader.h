#pragma once

#include <cstddef>
#include <filesystem>
#include <span>
#include <string>

namespace kvc::core {

// RAII wrapper around POSIX mmap. Read-only view of an entire file.
class MemoryReader {
public:
    MemoryReader() = default;
    ~MemoryReader();

    MemoryReader(const MemoryReader&) = delete;
    MemoryReader& operator=(const MemoryReader&) = delete;
    MemoryReader(MemoryReader&&) noexcept;
    MemoryReader& operator=(MemoryReader&&) noexcept;

    bool open(const std::filesystem::path& path);
    void close();

    bool is_open() const { return base_ != nullptr && size_ > 0; }
    std::size_t size() const { return size_; }
    std::span<const std::byte> view() const;

    const std::string& last_error() const { return error_; }

private:
    int fd_ = -1;
    const std::byte* base_ = nullptr;
    std::size_t size_ = 0;
    std::string error_;
};

} // namespace kvc::core
