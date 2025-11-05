#include "storens.hpp"

namespace cm::store
{




const NamespaceId& CMStoreNS::getNamespaceId() const { return m_namespaceId; }
std::vector<std::tuple<std::string, std::string>> CMStoreNS::getCollection(ResourceType) const { return {}; }
std::tuple<std::string, ResourceType> CMStoreNS::resolveNameFromUUID(const std::string&) const { return {"", ResourceType{}}; }
std::string CMStoreNS::resolveUUIDFromName(const std::string&, ResourceType) const { return ""; }

dataType::Policy CMStoreNS::getPolicy() const { return {}; }
void CMStoreNS::upsertPolicy(const dataType::Policy&) {}
void CMStoreNS::deletePolicy() {}

dataType::Integration CMStoreNS::getIntegrationByName(const std::string&) const { return {}; }
dataType::Integration CMStoreNS::getIntegrationByUUID(const std::string&) const { return {}; }
bool CMStoreNS::integrationExistsByName(const std::string&) const { return false; }
bool CMStoreNS::integrationExistsByUUID(const std::string&) const { return false; }
std::string CMStoreNS::createIntegration(const dataType::Integration&) { return ""; }
void CMStoreNS::updateIntegration(const dataType::Integration&) {}
void CMStoreNS::deleteIntegrationByName(const std::string&) {}
void CMStoreNS::deleteIntegrationByUUID(const std::string&) {}

json::Json CMStoreNS::getKVDBByName(const std::string&) const { return {}; }
json::Json CMStoreNS::getKVDBByUUID(const std::string&) const { return {}; }
bool CMStoreNS::kvdbExistsByName(const base::Name&) const { return false; }
bool CMStoreNS::kvdbExistsByUUID(const std::string&) const { return false; }
std::string CMStoreNS::createKVDB(const dataType::KVDB&) { return ""; }
void CMStoreNS::updateKVDB(const dataType::KVDB&) {}
void CMStoreNS::deleteKVDBByName(const std::string&) {}
void CMStoreNS::deleteKVDBByUUID(const std::string&) {}

json::Json CMStoreNS::getAssetByName(const base::Name&) const { return {}; }
json::Json CMStoreNS::getAssetByUUID(const std::string&) const { return {}; }
bool CMStoreNS::assetExistsByName(const base::Name&) const { return false; }
bool CMStoreNS::assetExistsByUUID(const std::string&) const { return false; }
std::string CMStoreNS::createAsset(const json::Json&) { return ""; }
void CMStoreNS::updateAsset(const json::Json&) {}
void CMStoreNS::deleteAssetByName(const base::Name&) {}
void CMStoreNS::deleteAssetByUUID(const std::string&) {}
} // namespace cm::store
