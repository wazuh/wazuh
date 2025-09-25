#include <ctistore/cm.hpp>

namespace cti::store
{
// Dummy implementations to allow compilation. Actual implementations should be provided.
std::vector<base::Name> ContentManager::getAssetList(cti::store::AssetType type) const
{
    return {};
}

json::Json ContentManager::getAsset(const base::Name& name) const
{
    return json::Json();
}

bool ContentManager::assetExists(const base::Name& name) const
{
    return false;
}

std::vector<std::string> ContentManager::listKVDB() const
{
    return {};
}

std::vector<std::string> ContentManager::listKVDB(const base::Name& integrationName) const
{
    return {};
}
bool ContentManager::kvdbExists(const std::string& kdbName) const
{
    return false;
}

json::Json ContentManager::kvdbDump(const std::string& kdbName) const
{
    return json::Json();
}

std::vector<base::Name> ContentManager::getPolicyIntegrationList() const
{
    return {};
}

base::Name ContentManager::getPolicyDefaultParent() const
{
    return base::Name();
}

/************************************************************************************
 * Other method implementations can be added here
 ************************************************************************************/
} // namespace cti::store
