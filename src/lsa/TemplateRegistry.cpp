#include "lsa/TemplateRegistry.h"

#include <array>
#include <limits>

namespace KvcForensic::lsa::templates {

namespace {

constexpr std::uint32_t kBuildMax = std::numeric_limits<std::uint32_t>::max();

const std::array<MsvTemplateSpec, 10> kMsvX64Templates{{
    { L"MSV_x64_61", 7600, 9199, { 0x33, 0xf6, 0x45, 0x89, 0x2f, 0x4c, 0x8b, 0xf3, 0x85, 0xff, 0x0f, 0x84 }, 19, -4, 0, 0, 0, 0, 0, 0, false },
    { L"MSV_x64_62", 9200, 9599, { 0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74 }, 16, -4, 0, 0, 0, 0, 0, 0, false },
    { L"MSV_x64_63", 9600, 10239, { 0x8b, 0xde, 0x48, 0x8d, 0x0c, 0x5b, 0x48, 0xc1, 0xe1, 0x05, 0x48, 0x8d, 0x05 }, 36, -6, 0, 0, 0, 0, 0, 0, false },
    { L"MSV_x64_10_1507_1607", 10240, 15062, { 0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74 }, 16, -4, 0, 0, 0, 0, 0, 0, false },
    { L"MSV_x64_1703", 15063, 17133, { 0x33, 0xff, 0x45, 0x89, 0x37, 0x48, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74 }, 23, -4, 0, 0, 0, 0, 0, 0, false },
    { L"MSV_x64_1803_22H2", 17134, 20347, { 0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74 }, 23, -4, 0, 0, 0, 0, 0, 0, false },
    { L"MSV_x64_11_2022", 20348, 22099, { 0x45, 0x89, 0x34, 0x24, 0x4c, 0x8b, 0xff, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74 }, 24, -4, 0, 0, 0, 0, 0, 0, false },
    { L"MSV_x64_11_2023", 22100, 26099, { 0x45, 0x89, 0x37, 0x4c, 0x8b, 0xf7, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x0f }, 27, -4, 0, 0, 0, 0, 0, 0, false },
    { L"MSV_x64_11_24H2", 26100, 26199, { 0x45, 0x89, 0x34, 0x24, 0x8b, 0xfb, 0x45, 0x85, 0xc0, 0x0f }, 25, -16, 34, 0x70, 0xA0, 0xB0, 0xE0, 0x118, true },
    { L"MSV_x64_11_25H2", 26200, kBuildMax, { 0x45, 0x89, 0x34, 0x24, 0x8b, 0xfb, 0x45, 0x85, 0xc0, 0x0f }, 25, -16, 34, 0x70, 0xA0, 0xB0, 0xE0, 0x118, true },
}};

const std::array<WdigestTemplateSpec, 2> kWdigestX64Templates{{
    { L"WDigest_x64_pre11", 6000, 21999, { 0x48, 0x3b, 0xd9, 0x74 }, -4, 48 },
    { L"WDigest_x64_11plus", 22000, kBuildMax, { 0x48, 0x3b, 0xc6, 0x74, 0x11, 0x8b, 0x4b, 0x20, 0x39, 0x48 }, -4, 48 },
}};

const std::array<KerberosTemplateSpec, 1> kKerberosX64Templates{{
    { L"Kerberos_x64_vista_plus", 6000, kBuildMax, { 0x48, 0x8b, 0x18, 0x48, 0x8d, 0x0d }, 6 },
}};

// DPAPI template signatures from pypykatz
// Reference: pypykatz/lsadecryptor/packages/dpapi/templates.py
// pypykatz uses the same signature for ALL builds >= WIN_10_1607 (14393),
// including Windows 11 24H2/25H2 (builds 26100+).
const std::array<DpapiTemplateSpec, 1> kDpapiX64Templates{{
    // WIN_10_1607+ through 25H2 and beyond: 48 89 4F 08 48 89 78 08 (MOV [RDI+8],RCX / MOV [RAX+8],RDI)
    { L"Dpapi_x64_win10_plus", 14393, kBuildMax, { 0x48, 0x89, 0x4f, 0x08, 0x48, 0x89, 0x78, 0x08 }, 11 },
}};

template <typename TSpec, std::size_t N>
const TSpec* SelectByBuild(const std::array<TSpec, N>& table, const std::uint32_t build_number) {
    for (const auto& spec : table) {
        if (build_number >= spec.min_build && build_number <= spec.max_build) {
            return &spec;
        }
    }
    return nullptr;
}

} // namespace

const MsvTemplateSpec* SelectMsvTemplateX64(const std::uint32_t build_number) {
    return SelectByBuild(kMsvX64Templates, build_number);
}

const WdigestTemplateSpec* SelectWdigestTemplateX64(const std::uint32_t build_number) {
    return SelectByBuild(kWdigestX64Templates, build_number);
}

const KerberosTemplateSpec* SelectKerberosTemplateX64(const std::uint32_t build_number) {
    return SelectByBuild(kKerberosX64Templates, build_number);
}

const DpapiTemplateSpec* SelectDpapiTemplateX64(const std::uint32_t build_number) {
    return SelectByBuild(kDpapiX64Templates, build_number);
}

} // namespace KvcForensic::lsa::templates

