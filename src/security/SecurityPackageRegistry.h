#pragma once

#include "security/ISecurityPackage.h"

#include <memory>
#include <vector>

namespace KvcForensic::security {

class SecurityPackageRegistry {
public:
    static std::vector<std::unique_ptr<ISecurityPackage>> CreateDefaultPackages();
};

} // namespace KvcForensic::security
