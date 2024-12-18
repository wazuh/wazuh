#ifndef _API_ROUTER_HANDLERS_HPP
#define _API_ROUTER_HANDLERS_HPP

#include <api/adapter/adapter.hpp>
#include <api/policy/ipolicy.hpp>
#include <router/iapi.hpp>

namespace api::router::handlers
{

adapter::RouteHandler routePost(const std::shared_ptr<::router::IRouterAPI>& router);
adapter::RouteHandler routeDelete(const std::shared_ptr<::router::IRouterAPI>& router);
adapter::RouteHandler routeGet(const std::shared_ptr<::router::IRouterAPI>& router,
                               const std::shared_ptr<api::policy::IPolicy>& policy);
adapter::RouteHandler routeReload(const std::shared_ptr<::router::IRouterAPI>& router);
adapter::RouteHandler routePatchPriority(const std::shared_ptr<::router::IRouterAPI>& router);

adapter::RouteHandler tableGet(const std::shared_ptr<::router::IRouterAPI>& router,
                               const std::shared_ptr<api::policy::IPolicy>& policy);
adapter::RouteHandler queuePost(const std::shared_ptr<::router::IRouterAPI>& router);

adapter::RouteHandler changeEpsSettings(const std::shared_ptr<::router::IRouterAPI>& router);
adapter::RouteHandler getEpsSettings(const std::shared_ptr<::router::IRouterAPI>& router);
adapter::RouteHandler activateEpsLimiter(const std::shared_ptr<::router::IRouterAPI>& router);
adapter::RouteHandler deactivateEpsLimiter(const std::shared_ptr<::router::IRouterAPI>& router);
} // namespace api::router::handlers

#endif // _API_ROUTER_HANDLERS_HPP
