#ifndef _API_CMCRUD_HANDLERS_HPP
#define _API_CMCRUD_HANDLERS_HPP

#include <memory>

#include <cmcrud/icmcrudservice.hpp>

#include <api/adapter/adapter.hpp>
#include <router/iapi.hpp>

namespace api::cmcrud::handlers
{

/*************** Namespace ***************/
adapter::RouteHandler namespaceList(std::shared_ptr<cm::crud::ICrudService> crud);
adapter::RouteHandler namespaceCreate(std::shared_ptr<cm::crud::ICrudService> crud);
adapter::RouteHandler namespaceDelete(std::shared_ptr<cm::crud::ICrudService> crud);
adapter::RouteHandler namespaceImport(std::shared_ptr<cm::crud::ICrudService> crud);

/*************** Policy ***************/
adapter::RouteHandler policyUpsert(std::shared_ptr<cm::crud::ICrudService> crud);
adapter::RouteHandler policyDelete(std::shared_ptr<cm::crud::ICrudService> crud);
adapter::RouteHandler policyValidate(std::shared_ptr<cm::crud::ICrudService> crud,
                                     const std::shared_ptr<::router::ITesterAPI>& tester);

/*************** Resources ***************/
adapter::RouteHandler resourceList(std::shared_ptr<cm::crud::ICrudService> crud);
adapter::RouteHandler resourceGet(std::shared_ptr<cm::crud::ICrudService> crud);
adapter::RouteHandler resourceUpsert(std::shared_ptr<cm::crud::ICrudService> crud);
adapter::RouteHandler resourceDelete(std::shared_ptr<cm::crud::ICrudService> crud);

/*************** Public Resources ***************/
adapter::RouteHandler resourceValidate(std::shared_ptr<cm::crud::ICrudService> crud,
                                       int64_t maxResourcePayloadBytes,
                                       int64_t maxKvdbPayloadBytes);

/*************** Registration helper ***************/
inline void registerHandlers(std::shared_ptr<cm::crud::ICrudService> crud,
                             const std::shared_ptr<::router::ITesterAPI>& tester,
                             const std::shared_ptr<httpsrv::Server>& server,
                             int64_t maxResourcePayloadBytes,
                             int64_t maxKvdbPayloadBytes)
{
    // Namespace
    server->addRoute(httpsrv::Method::POST, "/_internal/content/namespace/list", namespaceList(crud));
    server->addRoute(httpsrv::Method::POST, "/_internal/content/namespace/create", namespaceCreate(crud));
    server->addRoute(httpsrv::Method::POST, "/_internal/content/namespace/delete", namespaceDelete(crud));
    server->addRoute(httpsrv::Method::POST, "/_internal/content/namespace/import", namespaceImport(crud));

    // Policy
    server->addRoute(httpsrv::Method::POST, "/_internal/content/policy/upsert", policyUpsert(crud));
    server->addRoute(httpsrv::Method::POST, "/_internal/content/policy/delete", policyDelete(crud));
    server->addRoute(httpsrv::Method::POST, "/content/validate/policy", policyValidate(crud, tester));

    // Resources (internal)
    server->addRoute(httpsrv::Method::POST, "/_internal/content/list", resourceList(crud));
    server->addRoute(httpsrv::Method::POST, "/_internal/content/get", resourceGet(crud));
    server->addRoute(httpsrv::Method::POST, "/_internal/content/upsert", resourceUpsert(crud));
    server->addRoute(httpsrv::Method::POST, "/_internal/content/delete", resourceDelete(crud));

    // Resources (public)
    server->addRoute(httpsrv::Method::POST,
                     "/content/validate/resource",
                     resourceValidate(crud, maxResourcePayloadBytes, maxKvdbPayloadBytes));
}

} // namespace api::cmcrud::handlers

#endif // _API_CMCRUD_HANDLERS_HPP
