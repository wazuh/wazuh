#ifndef _API_CATALOG_MOCKCATALOG_HPP
#define _API_CATALOG_MOCKCATALOG_HPP

#include <api/catalog/icatalog.hpp>
#include <gmock/gmock.h>

namespace api::catalog::mocks
{
class MockCatalog : public ICatalog
{
public:
    MOCK_METHOD(base::OptError,
                postResource,
                (const Resource& collection, const std::string& namespaceStr, const std::string& content),
                (override));
    MOCK_METHOD(base::OptError,
                putResource,
                (const Resource& item, const std::string& content, const std::string& namespaceId),
                (override));
    MOCK_METHOD(base::RespOrError<std::string>,
                getResource,
                (const Resource& resource, const std::string& namespaceId),
                (const, override));
    MOCK_METHOD(base::OptError, deleteResource, (const Resource& resource, const std::string& namespaceId), (override));
    MOCK_METHOD(base::OptError,
                validateResource,
                (const Resource& item, const std::string& namespaceId, const std::string& content),
                (const, override));
    MOCK_METHOD(std::vector<store::NamespaceId>, getAllNamespaces, (), (const, override));
};
} // namespace api::catalog::mocks

#endif // _API_CATALOG_MOCKCATALOG_HPP
