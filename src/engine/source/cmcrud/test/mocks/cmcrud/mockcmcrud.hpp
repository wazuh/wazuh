#ifndef _MOCKS_CMCRUD_CRUD_SERVICE_HPP
#define _MOCKS_CMCRUD_CRUD_SERVICE_HPP
#include <gmock/gmock.h>

#include <cmcrud/icmcrudservice.hpp>
#include <cmcrud/icontentvalidator.hpp>

namespace cm::crud
{

class MockCrudService : public ICrudService
{
public:
    MOCK_METHOD(std::vector<cm::store::NamespaceId>, listNamespaces, (), (const, override));
    MOCK_METHOD(void, createNamespace, (std::string_view nsName), (override));
    MOCK_METHOD(void, deleteNamespace, (std::string_view nsName), (override));

    MOCK_METHOD(void, upsertPolicy, (std::string_view nsName, std::string_view document), (override));
    MOCK_METHOD(void, deletePolicy, (std::string_view nsName), (override));

    MOCK_METHOD(std::vector<ResourceSummary>,
                listResources,
                (std::string_view nsName, cm::store::ResourceType type),
                (const, override));

    MOCK_METHOD(std::string, getResourceByUUID, (std::string_view nsName, const std::string& uuid), (const, override));

    MOCK_METHOD(void,
                upsertResource,
                (std::string_view nsName, cm::store::ResourceType type, std::string_view document),
                (override));

    MOCK_METHOD(void, deleteResourceByUUID, (std::string_view nsName, const std::string& uuid), (override));
};

class MockContentValidator : public IContentValidator
{
public:
    MOCK_METHOD(void,
                validatePolicy,
                (const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                 const cm::store::dataType::Policy& policy),
                (const, override));

    MOCK_METHOD(void,
                validateIntegration,
                (const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                 const cm::store::dataType::Integration& integration),
                (const, override));

    MOCK_METHOD(void,
                validateKVDB,
                (const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader, const cm::store::dataType::KVDB& kvdb),
                (const, override));

    MOCK_METHOD(void,
                validateAsset,
                (const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader, const json::Json& asset),
                (const, override));
};

} // namespace cm::crud

#endif // _MOCKS_CMCRUD_CRUD_SERVICE_HPP
