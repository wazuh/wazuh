#ifndef _MOCKS_CMCRUD_CRUD_SERVICE_HPP
#define _MOCKS_CMCRUD_CRUD_SERVICE_HPP
#include <gmock/gmock.h>

#include <cmcrud/icmcrudservice.hpp>
namespace cm::crud
{

class MockCrudService : public ICrudService
{
public:
    MOCK_METHOD(std::vector<cm::store::NamespaceId>, listNamespaces, (), (const, override));
    MOCK_METHOD(void, createNamespace, (const cm::store::NamespaceId& nsId), (override));
    MOCK_METHOD(bool, existsNamespace, (const cm::store::NamespaceId& nsId), (const, override));
    MOCK_METHOD(void, deleteNamespace, (const cm::store::NamespaceId& nsId), (override));
    MOCK_METHOD(void,
                importNamespace,
                (const cm::store::NamespaceId& nsId, std::string_view jsonDocument, bool force),
                (override));
    MOCK_METHOD(void,
                importNamespace,
                (const cm::store::NamespaceId& nsId,
                 const std::vector<json::Json>& kvdbs,
                 const std::vector<json::Json>& decoders,
                 const std::vector<json::Json>& integrations,
                 const json::Json& policy,
                 bool softValidation),
                (override));

    MOCK_METHOD(void, upsertPolicy, (const cm::store::NamespaceId& nsId, std::string_view document), (override));
    MOCK_METHOD(void, deletePolicy, (const cm::store::NamespaceId& nsId), (override));

    MOCK_METHOD(std::vector<ResourceSummary>,
                listResources,
                (const cm::store::NamespaceId& nsId, cm::store::ResourceType type),
                (const, override));

    MOCK_METHOD(std::string,
                getResourceByUUID,
                (const cm::store::NamespaceId& nsId, const std::string& uuid, bool asJson),
                (const, override));

    MOCK_METHOD(void,
                upsertResource,
                (const cm::store::NamespaceId& nsId, cm::store::ResourceType type, std::string_view document),
                (override));

    MOCK_METHOD(void, deleteResourceByUUID, (const cm::store::NamespaceId& nsId, const std::string& uuid), (override));
    MOCK_METHOD(void, validateResource, (cm::store::ResourceType type, const json::Json& resource), (override));
};

} // namespace cm::crud

#endif // _MOCKS_CMCRUD_CRUD_SERVICE_HPP
