#include <base/logging.hpp>

#include <cmstore/types.hpp>

#include "storecti.hpp"

namespace cm::store
{

/***********************************  General Methods ************************************/
const NamespaceId& CMStoreCTI::getNamespaceId() const
{
    return m_namespaceId;
}

std::vector<std::tuple<std::string, std::string>> CMStoreCTI::getCollection(ResourceType rType) const
{
    return {};
}

std::tuple<std::string, ResourceType> CMStoreCTI::resolveNameFromUUID(const std::string& uuid) const
{
   return {};
}

std::string CMStoreCTI::resolveUUIDFromName(const std::string& name, ResourceType type) const
{
   return {};
}

bool CMStoreCTI::assetExistsByName(const base::Name& name) const
{
   return {};
}

bool CMStoreCTI::assetExistsByUUID(const std::string& uuid) const
{
   return {};
}

/*********************************** General Resource ************************************/

std::string CMStoreCTI::createResource(const std::string& name, ResourceType type, const std::string& ymlContent)
{
    throw std::runtime_error("This space is Read-Only. Resource creation is not allowed.");
}

void CMStoreCTI::updateResourceByName(const std::string& name, ResourceType type, const std::string& ymlContent)
{
    throw std::runtime_error("This space is Read-Only. Resource update is not allowed.");
}

void CMStoreCTI::updateResourceByUUID(const std::string& uuid, const std::string& ymlContent)
{
    throw std::runtime_error("This space is Read-Only. Resource update is not allowed.");
}

void CMStoreCTI::deleteResourceByName(const std::string& name, ResourceType type)
{
    throw std::runtime_error("This space is Read-Only. Resource deletion is not allowed.");
}

void CMStoreCTI::deleteResourceByUUID(const std::string& uuid)
{
    throw std::runtime_error("This space is Read-Only. Resource deletion is not allowed.");
}

/**************************************** Policy ****************************************/

dataType::Policy CMStoreCTI::getPolicy() const
{
    // throw std::runtime_error("Policy retrieval not implemented yet.");
    return dataType::Policy::fromJson({});
}

void CMStoreCTI::upsertPolicy(const dataType::Policy& policy)
{
    throw std::runtime_error("This space is Read-Only. Policy upsert is not allowed.");
}

void CMStoreCTI::deletePolicy()
{
    throw std::runtime_error("This space is Read-Only. Policy deletion is not allowed.");
}

/************************************* INTEGRATIONS *************************************/

dataType::Integration CMStoreCTI::getIntegrationByName(const std::string& name) const
{
    return dataType::Integration::fromJson(json::Json{});
}

dataType::Integration CMStoreCTI::getIntegrationByUUID(const std::string& uuid) const
{
    return dataType::Integration::fromJson(json::Json{});
}

/**************************************** KVDB ******************************************/

dataType::KVDB CMStoreCTI::getKVDBByName(const std::string& name) const
{
    return dataType::KVDB::fromJson(json::Json{});
}

dataType::KVDB CMStoreCTI::getKVDBByUUID(const std::string& uuid) const
{
    return dataType::KVDB::fromJson(json::Json{});
}

/**************************************** ASSETS ****************************************/

json::Json CMStoreCTI::getAssetByName(const base::Name& name) const
{
    return json::Json{};
}

json::Json CMStoreCTI::getAssetByUUID(const std::string& uuid) const
{
    return json::Json{};
}

} // namespace cm::store
