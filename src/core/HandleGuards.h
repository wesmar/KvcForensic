#pragma once

#include <windows.h>

namespace KvcForensic::core {

struct HandleTraits {
    using Type = HANDLE;
    static Type Invalid() { return nullptr; }
    static bool IsValid(Type h) { return h != nullptr && h != INVALID_HANDLE_VALUE; }
    static void Close(Type h) { if (h && h != INVALID_HANDLE_VALUE) ::CloseHandle(h); }
};

struct ScHandleTraits {
    using Type = SC_HANDLE;
    static Type Invalid() { return nullptr; }
    static bool IsValid(Type h) { return h != nullptr; }
    static void Close(Type h) { if (h) ::CloseServiceHandle(h); }
};

template <typename Traits>
class GenericGuard {
public:
    using Type = typename Traits::Type;

    GenericGuard(Type h = Traits::Invalid()) : handle_(h) {}
    ~GenericGuard() { Close(); }

    GenericGuard(const GenericGuard&) = delete;
    GenericGuard& operator=(const GenericGuard&) = delete;

    GenericGuard(GenericGuard&& other) noexcept : handle_(other.handle_) {
        other.handle_ = Traits::Invalid();
    }
    GenericGuard& operator=(GenericGuard&& other) noexcept {
        if (this != &other) {
            Close();
            handle_ = other.handle_;
            other.handle_ = Traits::Invalid();
        }
        return *this;
    }

    Type get() const { return handle_; }
    Type* addressof() { return &handle_; }
    explicit operator bool() const { return Traits::IsValid(handle_); }

    Type release() {
        Type h = handle_;
        handle_ = Traits::Invalid();
        return h;
    }

    void reset(Type h = Traits::Invalid()) {
        Close();
        handle_ = h;
    }

private:
    void Close() {
        if (Traits::IsValid(handle_)) {
            Traits::Close(handle_);
            handle_ = Traits::Invalid();
        }
    }
    Type handle_;
};

using HandleGuard = GenericGuard<HandleTraits>;
using ScHandleGuard = GenericGuard<ScHandleTraits>;

class ImpersonationGuard {
public:
    ImpersonationGuard() = default;
    ~ImpersonationGuard() {
        if (active_) {
            ::RevertToSelf();
        }
    }

    void adopt() { active_ = true; }
    void release() { active_ = false; }

private:
    bool active_ = false;
};

} // namespace KvcForensic::core
