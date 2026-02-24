#include "core/MemoryReader.h"

#include <sstream>

namespace KvcForensic::core {

namespace {

std::wstring BuildLastErrorText(const wchar_t* prefix) {
    const DWORD code = ::GetLastError();
    std::wstringstream ss;
    ss << prefix << L" (GetLastError=" << code << L")";
    return ss.str();
}

} // namespace

MemoryReader::~MemoryReader() {
    Close();
}

bool MemoryReader::Open(const std::wstring& path) {
    Close();
    error_.clear();

    file_ = ::CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file_ == INVALID_HANDLE_VALUE) {
        error_ = BuildLastErrorText(L"CreateFileW failed");
        return false;
    }

    LARGE_INTEGER size{};
    if (!::GetFileSizeEx(file_, &size) || size.QuadPart <= 0) {
        error_ = BuildLastErrorText(L"GetFileSizeEx failed");
        Close();
        return false;
    }
    size_ = static_cast<std::size_t>(size.QuadPart);

    mapping_ = ::CreateFileMappingW(file_, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (mapping_ == nullptr) {
        error_ = BuildLastErrorText(L"CreateFileMappingW failed");
        Close();
        return false;
    }

    void* view = ::MapViewOfFile(mapping_, FILE_MAP_READ, 0, 0, 0);
    if (view == nullptr) {
        error_ = BuildLastErrorText(L"MapViewOfFile failed");
        Close();
        return false;
    }
    base_ = static_cast<const std::byte*>(view);
    return true;
}

void MemoryReader::Close() {
    if (base_ != nullptr) {
        (void)::UnmapViewOfFile(base_);
        base_ = nullptr;
    }
    if (mapping_ != nullptr) {
        (void)::CloseHandle(mapping_);
        mapping_ = nullptr;
    }
    if (file_ != INVALID_HANDLE_VALUE) {
        (void)::CloseHandle(file_);
        file_ = INVALID_HANDLE_VALUE;
    }
    size_ = 0;
}

bool MemoryReader::IsOpen() const {
    return base_ != nullptr && size_ > 0;
}

std::size_t MemoryReader::Size() const {
    return size_;
}

std::span<const std::byte> MemoryReader::View() const {
    if (!IsOpen()) {
        return {};
    }
    return std::span<const std::byte>(base_, size_);
}

const std::wstring& MemoryReader::LastError() const {
    return error_;
}

} // namespace KvcForensic::core
