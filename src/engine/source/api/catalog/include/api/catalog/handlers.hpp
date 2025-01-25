#ifndef _API_CATALOG_HANDLERS_HPP
#define _API_CATALOG_HANDLERS_HPP

#include <api/adapter/adapter.hpp>
#include <api/catalog/icatalog.hpp>

#include <memory>

namespace api::catalog::handlers
{

/* Resource Endpoint */
adapter::RouteHandler resourcePost(const std::shared_ptr<ICatalog>& catalog);
adapter::RouteHandler resourceGet(const std::shared_ptr<ICatalog>& catalog);
adapter::RouteHandler resourceDelete(const std::shared_ptr<ICatalog>& catalog);
adapter::RouteHandler resourcePut(const std::shared_ptr<ICatalog>& catalog);
adapter::RouteHandler resourceValidate(const std::shared_ptr<ICatalog>& catalog);
adapter::RouteHandler getNamespaces(const std::shared_ptr<ICatalog>& catalog);

inline void registerHandlers(const std::shared_ptr<ICatalog>& catalog, const std::shared_ptr<httpsrv::Server>& server)
{
    server->addRoute(httpsrv::Method::POST, "/catalog/resource/post", resourcePost(catalog));
    server->addRoute(httpsrv::Method::POST, "/catalog/resource/get", resourceGet(catalog));
    server->addRoute(httpsrv::Method::POST, "/catalog/resource/delete", resourceDelete(catalog));
    server->addRoute(httpsrv::Method::POST, "/catalog/resource/put", resourcePut(catalog));
    server->addRoute(httpsrv::Method::POST, "/catalog/resource/validate", resourceValidate(catalog));
    server->addRoute(httpsrv::Method::POST, "/catalog/namespaces/get", getNamespaces(catalog));
}

} // namespace api::catalog::handlers

#endif // _API_CATALOG_HANDLERS_HPP
