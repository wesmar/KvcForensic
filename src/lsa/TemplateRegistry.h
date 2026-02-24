#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace KvcForensic::lsa::templates {

struct MsvTemplateSpec {
    const wchar_t* name = L"";
    std::uint32_t min_build = 0;
    std::uint32_t max_build = 0;
    std::vector<std::uint8_t> signature;
    int first_entry_offset = 0;
    int offset2 = 0;
    int first_entry_offset_correction = 0;

    // Session layout offsets (only valid when parser_support is true).
    std::size_t session_luid_offset = 0;
    std::size_t session_username_offset = 0;
    std::size_t session_domain_offset = 0;
    std::size_t session_sid_ptr_offset = 0;
    std::size_t session_credentials_ptr_offset = 0;

    bool parser_support = false;
};

struct WdigestTemplateSpec {
    const wchar_t* name = L"";
    std::uint32_t min_build = 0;
    std::uint32_t max_build = 0;
    std::vector<std::uint8_t> signature;
    int first_entry_offset = 0;
    std::size_t primary_offset = 0;
};

struct KerberosTemplateSpec {
    const wchar_t* name = L"";
    std::uint32_t min_build = 0;
    std::uint32_t max_build = 0;
    std::vector<std::uint8_t> signature;
    int first_entry_offset = 0;
};

struct DpapiTemplateSpec {
    const wchar_t* name = L"";
    std::uint32_t min_build = 0;
    std::uint32_t max_build = 0;
    std::vector<std::uint8_t> signature;
    int first_entry_offset = 0;
};

const MsvTemplateSpec* SelectMsvTemplateX64(std::uint32_t build_number);
const WdigestTemplateSpec* SelectWdigestTemplateX64(std::uint32_t build_number);
const KerberosTemplateSpec* SelectKerberosTemplateX64(std::uint32_t build_number);
const DpapiTemplateSpec* SelectDpapiTemplateX64(std::uint32_t build_number);

} // namespace KvcForensic::lsa::templates

