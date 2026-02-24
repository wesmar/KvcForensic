#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace KvcForensic::security {

struct BuildLayout {
    std::uint32_t build_number = 0;

    std::size_t lsa_context_offset = 0;
    std::size_t logon_list_offset = 0;
    std::size_t logon_count_offset = 0;
    std::size_t wdigest_list_offset = 0;
    std::size_t kerberos_list_offset = 0;
    std::size_t msv_list_offset = 0;

    std::wstring notes;

    bool HasPlaceholderOffsets() const {
        constexpr std::size_t kPlaceholderOffset = 0x1337;
        return lsa_context_offset == kPlaceholderOffset &&
            logon_list_offset == kPlaceholderOffset &&
            logon_count_offset == kPlaceholderOffset &&
            wdigest_list_offset == kPlaceholderOffset &&
            kerberos_list_offset == kPlaceholderOffset &&
            msv_list_offset == kPlaceholderOffset;
    }

    bool IsConfigured() const {
        if (HasPlaceholderOffsets()) {
            return false;
        }
        return lsa_context_offset != 0 ||
            logon_list_offset != 0 ||
            logon_count_offset != 0 ||
            wdigest_list_offset != 0 ||
            kerberos_list_offset != 0 ||
            msv_list_offset != 0;
    }
};

const BuildLayout& ResolveBuildLayout(std::uint32_t build_number);

} // namespace KvcForensic::security
