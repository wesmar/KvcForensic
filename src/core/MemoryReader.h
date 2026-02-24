#pragma once

#include <Windows.h>

#include <cstddef>
#include <span>
#include <string>

namespace KvcForensic::core {

class MemoryReader {
public:
    MemoryReader() = default;
    ~MemoryReader();

    MemoryReader(const MemoryReader&) = delete;
    MemoryReader& operator=(const MemoryReader&) = delete;

    bool Open(const std::wstring& path);
    void Close();

    bool IsOpen() const;
    std::size_t Size() const;
    std::span<const std::byte> View() const;

    const std::wstring& LastError() const;

private:
    HANDLE file_ = INVALID_HANDLE_VALUE;
    HANDLE mapping_ = nullptr;
    const std::byte* base_ = nullptr;
    std::size_t size_ = 0;
    std::wstring error_;
};

} // namespace KvcForensic::core
