#include "core/memory_reader.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace kvc::core {

namespace {

std::string errno_text(const char* prefix) {
    return std::string(prefix) + ": " + std::strerror(errno);
}

} // namespace

MemoryReader::~MemoryReader() {
    close();
}

MemoryReader::MemoryReader(MemoryReader&& other) noexcept
    : fd_(other.fd_), base_(other.base_), size_(other.size_), error_(std::move(other.error_)) {
    other.fd_ = -1;
    other.base_ = nullptr;
    other.size_ = 0;
}

MemoryReader& MemoryReader::operator=(MemoryReader&& other) noexcept {
    if (this != &other) {
        close();
        fd_ = other.fd_;
        base_ = other.base_;
        size_ = other.size_;
        error_ = std::move(other.error_);
        other.fd_ = -1;
        other.base_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

bool MemoryReader::open(const std::filesystem::path& path) {
    close();
    error_.clear();

    fd_ = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd_ < 0) {
        error_ = errno_text("open failed");
        return false;
    }

    struct stat st{};
    if (::fstat(fd_, &st) != 0) {
        error_ = errno_text("fstat failed");
        close();
        return false;
    }
    if (st.st_size <= 0) {
        error_ = "file is empty";
        close();
        return false;
    }
    size_ = static_cast<std::size_t>(st.st_size);

    void* p = ::mmap(nullptr, size_, PROT_READ, MAP_PRIVATE, fd_, 0);
    if (p == MAP_FAILED) {
        error_ = errno_text("mmap failed");
        close();
        return false;
    }
    base_ = static_cast<const std::byte*>(p);
    ::madvise(const_cast<void*>(static_cast<const void*>(base_)), size_, MADV_RANDOM);
    return true;
}

void MemoryReader::close() {
    if (base_ != nullptr) {
        ::munmap(const_cast<void*>(static_cast<const void*>(base_)), size_);
        base_ = nullptr;
    }
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    size_ = 0;
}

std::span<const std::byte> MemoryReader::view() const {
    if (!is_open()) return {};
    return std::span<const std::byte>(base_, size_);
}

} // namespace kvc::core
