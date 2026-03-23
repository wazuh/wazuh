#ifndef _API_ROUTER_HANDLERS_HPP
#define _API_ROUTER_HANDLERS_HPP

#include <api/adapter/adapter.hpp>
#include <router/iapi.hpp>
#include <cmstore/icmstore.hpp>
namespace api::router::handlers
{

adapter::RouteHandler routePost(const std::shared_ptr<::router::IRouterAPI>& router);
adapter::RouteHandler routeDelete(const std::shared_ptr<::router::IRouterAPI>& router);
adapter::RouteHandler routeGet(const std::shared_ptr<::router::IRouterAPI>& router,
                               const std::shared_ptr<cm::store::ICMStore>& store);
adapter::RouteHandler routeReload(const std::shared_ptr<::router::IRouterAPI>& router);
adapter::RouteHandler routePatchPriority(const std::shared_ptr<::router::IRouterAPI>& router);

adapter::RouteHandler tableGet(const std::shared_ptr<::router::IRouterAPI>& router,
                               const std::shared_ptr<cm::store::ICMStore>& store);

inline void registerHandlers(const std::shared_ptr<::router::IRouterAPI>& router,
                             const std::shared_ptr<cm::store::ICMStore>& store,
                             const std::shared_ptr<httpsrv::Server>& server)
{
    server->addRoute(httpsrv::Method::POST, "/router/route/post", routePost(router));
    server->addRoute(httpsrv::Method::POST, "/router/route/delete", routeDelete(router));
    server->addRoute(httpsrv::Method::POST, "/router/route/get", routeGet(router, store));
    server->addRoute(httpsrv::Method::POST, "/router/route/reload", routeReload(router));
    server->addRoute(httpsrv::Method::POST, "/router/route/patchPriority", routePatchPriority(router));

    server->addRoute(httpsrv::Method::POST, "/router/table/get", tableGet(router, store));
}

} // namespace api::router::handlers

#endif // _API_ROUTER_HANDLERS_HPP
