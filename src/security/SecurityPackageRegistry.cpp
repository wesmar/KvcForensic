#include "security/SecurityPackageRegistry.h"

#include "security/DpapiPackage.h"
#include "security/KerberosPackage.h"
#include "security/MsvPackage.h"
#include "security/WDigestPackage.h"

namespace KvcForensic::security {

std::vector<std::unique_ptr<ISecurityPackage>> SecurityPackageRegistry::CreateDefaultPackages() {
    std::vector<std::unique_ptr<ISecurityPackage>> packages;
    packages.emplace_back(std::make_unique<WDigestPackage>());
    packages.emplace_back(std::make_unique<KerberosPackage>());
    packages.emplace_back(std::make_unique<MsvPackage>());
    packages.emplace_back(std::make_unique<DpapiPackage>());
    return packages;
}

} // namespace KvcForensic::security
