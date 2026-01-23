#ifndef _MOCKS_CM_ISYNC_HPP
#define _MOCKS_CM_ISYNC_HPP

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cmsync/icmsync.hpp>

namespace cm::sync
{
class MockICmsyncNSReader : public ICmsyncNSReader
{
public:
    MOCK_METHOD(const NamespaceId&, getNamespaceId, (), (const, override));
    MOCK_METHOD((std::vector<std::tuple<std::string, std::string>>),
                getCollection,
                (ResourceType type),
                (const, override));
    MOCK_METHOD((std::tuple<std::string, ResourceType>),
                resolveNameFromUUID,
                (const std::string& uuid),
                (const, override));
    MOCK_METHOD(std::string, resolveHashFromUUID, (const std::string& uuid), (const, override));
    MOCK_METHOD(std::string, resolveUUIDFromName, (const std::string& name, ResourceType type), (const, override));
    MOCK_METHOD(bool, assetExistsByName, (const base::Name& name), (const, override));
    MOCK_METHOD(bool, assetExistsByUUID, (const std::string& uuid), (const, override));
    MOCK_METHOD(dataType::Policy, getPolicy, (), (const, override));
    MOCK_METHOD(dataType::Integration, getIntegrationByName, (const std::string& name), (const, override));
    MOCK_METHOD(dataType::Integration, getIntegrationByUUID, (const std::string& uuid), (const, override));
    MOCK_METHOD(dataType::KVDB, getKVDBByName, (const std::string& name), (const, override));
    MOCK_METHOD(dataType::KVDB, getKVDBByUUID, (const std::string& uuid), (const, override));
    MOCK_METHOD(json::Json, getAssetByName, (const base::Name& name), (const, override));
    MOCK_METHOD(json::Json, getAssetByUUID, (const std::string& uuid), (const, override));
    MOCK_METHOD((const std::vector<json::Json>), getDefaultOutputs, (), (const, override));
};

class MockICmsyncNS : public ICmsyncNS
{
public:
    // ICmsyncNSReader methods
    MOCK_METHOD(const NamespaceId&, getNamespaceId, (), (const, override));
    MOCK_METHOD((std::vector<std::tuple<std::string, std::string>>),
                getCollection,
                (ResourceType type),
                (const, override));
    MOCK_METHOD((std::tuple<std::string, ResourceType>),
                resolveNameFromUUID,
                (const std::string& uuid),
                (const, override));
    MOCK_METHOD(std::string, resolveHashFromUUID, (const std::string& uuid), (const, override));
    MOCK_METHOD(std::string, resolveUUIDFromName, (const std::string& name, ResourceType type), (const, override));
    MOCK_METHOD(bool, assetExistsByName, (const base::Name& name), (const, override));
    MOCK_METHOD(bool, assetExistsByUUID, (const std::string& uuid), (const, override));
    MOCK_METHOD(dataType::Policy, getPolicy, (), (const, override));
    MOCK_METHOD(dataType::Integration, getIntegrationByName, (const std::string& name), (const, override));
    MOCK_METHOD(dataType::Integration, getIntegrationByUUID, (const std::string& uuid), (const, override));
    MOCK_METHOD(dataType::KVDB, getKVDBByName, (const std::string& name), (const, override));
    MOCK_METHOD(dataType::KVDB, getKVDBByUUID, (const std::string& uuid), (const, override));
    MOCK_METHOD(json::Json, getAssetByName, (const base::Name& name), (const, override));
    MOCK_METHOD(json::Json, getAssetByUUID, (const std::string& uuid), (const, override));
    MOCK_METHOD((const std::vector<json::Json>), getDefaultOutputs, (), (const, override));

    // ICmsyncNS methods
    MOCK_METHOD(std::string,
                createResource,
                (const std::string& name, ResourceType type, const std::string& ymlContent),
                (override));
    MOCK_METHOD(void,
                updateResourceByName,
                (const std::string& name, ResourceType type, const std::string& ymlContent),
                (override));
    MOCK_METHOD(void, updateResourceByUUID, (const std::string& uuid, const std::string& ymlContent), (override));
    MOCK_METHOD(void, deleteResourceByName, (const std::string& name, ResourceType type), (override));
    MOCK_METHOD(void, deleteResourceByUUID, (const std::string& uuid), (override));
    MOCK_METHOD(void, upsertPolicy, (const dataType::Policy& policy), (override));
    MOCK_METHOD(void, deletePolicy, (), (override));
};

class MockICmsync : public ICmsync
{
public:
    MOCK_METHOD(std::shared_ptr<ICmsyncNSReader>, getNSReader, (const NamespaceId& nsId), (const, override));
    MOCK_METHOD(std::shared_ptr<ICmsyncNS>, getNS, (const NamespaceId& nsId), (override));

    MOCK_METHOD(std::shared_ptr<ICmsyncNS>, createNamespace, (const NamespaceId& nsId), (override));
    MOCK_METHOD(void, deleteNamespace, (const NamespaceId& nsId), (override));
    MOCK_METHOD(void, renameNamespace, (const NamespaceId& from, const NamespaceId& to), (override));
    MOCK_METHOD(bool, existsNamespace, (const NamespaceId& nsId), (const, override));
    MOCK_METHOD(std::vector<NamespaceId>, getNamespaces, (), (const, override));
};

} // namespace cm::sync

#endif // _MOCKS_CM_ISYNC_HPP
