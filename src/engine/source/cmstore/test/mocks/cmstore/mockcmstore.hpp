#ifndef _MOCKS_CM_ISYNC_HPP
#define _MOCKS_CM_ISYNC_HPP

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cmstore/icmstore.hpp>

namespace cm::store
{
class MockICMStoreNSReader : public ICMStoreNSReader
{
public:
    MOCK_METHOD(dataType::Policy, getPolicy, (), (const, override));
    MOCK_METHOD(const NamespaceId&, getNamespaceId, (), (const, override));
    MOCK_METHOD(dataType::Integration, getIntegrationByName, (const std::string& name), (const, override));
    MOCK_METHOD(dataType::Integration, getIntegrationByUUID, (const std::string& uuid), (const, override));
    MOCK_METHOD(json::Json, getKVDBByName, (const std::string& name), (const, override));
    MOCK_METHOD(json::Json, getKVDBByUUID, (const std::string& uuid), (const, override));
    MOCK_METHOD(json::Json, getAssetByName, (const base::Name& name), (const, override));
    MOCK_METHOD(json::Json, getAssetByUUID, (const std::string& uuid), (const, override));
    MOCK_METHOD(std::vector<std::tuple<std::string, std::string>>,
                getCollection,
                (ResourceType type),
                (const, override));
    MOCK_METHOD(std::tuple<std::string, ResourceType>,
                resolveNameFromUUID,
                (const std::string& uuid),
                (const, override));
    MOCK_METHOD(std::string, resolveUUIDFromName, (const std::string& name, ResourceType type), (const, override));
    MOCK_METHOD(bool, isCustomResource, (const std::string& uuid), (const, override));
    MOCK_METHOD(bool, isCustomResource, (const std::string& name, ResourceType type), (const, override));
};

class MockICMstoreNS : public ICMstoreNS

{
public:
    MOCK_METHOD(dataType::Policy, getPolicy, (), (const, override));
    MOCK_METHOD(const NamespaceId&, getNamespaceId, (), (const, override));
    MOCK_METHOD(dataType::Integration, getIntegrationByName, (const std::string& name), (const, override));
    MOCK_METHOD(dataType::Integration, getIntegrationByUUID, (const std::string& uuid), (const, override));
    MOCK_METHOD(json::Json, getKVDBByName, (const std::string& name), (const, override));
    MOCK_METHOD(json::Json, getKVDBByUUID, (const std::string& uuid), (const, override));
    MOCK_METHOD(json::Json, getAssetByName, (const base::Name& name), (const, override));
    MOCK_METHOD(json::Json, getAssetByUUID, (const std::string& uuid), (const, override));
    MOCK_METHOD(std::vector<std::tuple<std::string, std::string>>,
                getCollection,
                (ResourceType type),
                (const, override));
    MOCK_METHOD(std::tuple<std::string, ResourceType>,
                resolveNameFromUUID,
                (const std::string& uuid),
                (const, override));
    MOCK_METHOD(std::string, resolveUUIDFromName, (const std::string& name, ResourceType type), (const, override));
    MOCK_METHOD(bool, isCustomResource, (const std::string& uuid), (const, override));
    MOCK_METHOD(bool, isCustomResource, (const std::string& name, ResourceType type), (const, override));
};

class MockICMstore : public ICMstore
{
public:
    MOCK_METHOD(std::shared_ptr<ICMStoreNSReader>, getNSReader, (const NamespaceId& nsId), (const, override));
    MOCK_METHOD(std::shared_ptr<ICMstoreNS>, getNS, (const NamespaceId& nsId), (override));
    MOCK_METHOD(void, createNamespace, (const NamespaceId& nsId), (override));
    MOCK_METHOD(void, deleteNamespace, (const NamespaceId& nsId), (override));
};

} // namespace cm::store

#endif // _MOCKS_CM_ISYNC_HPP
