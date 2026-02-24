#pragma once

#include <cstdint>
#include <string>

namespace KvcForensic::template_select {

struct LsaTemplateMetadata {
    std::wstring template_name;
    std::uint32_t min_supported_build;
    std::wstring description;
};

LsaTemplateMetadata SelectTemplateForWindows11(std::uint32_t build_number);
LsaTemplateMetadata SelectTemplateForBuild(std::uint32_t build_number);

} // namespace KvcForensic::template_select
