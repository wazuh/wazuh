#ifndef _API_ROUTER_HANDLERS_HPP
#define _API_ROUTER_HANDLERS_HPP

#include <api/api.hpp>
#include <api/policy/ipolicy.hpp>

#include <router/iapi.hpp>


namespace api::router::handlers
{

// Handler for router commands, returns a handler that will call the router
api::HandlerSync routePost(const std::weak_ptr<::router::IRouterAPI>& router);
api::HandlerSync routeDelete(const std::weak_ptr<::router::IRouterAPI>& router);
api::HandlerSync routeGet(const std::weak_ptr<::router::IRouterAPI>& router,
                      const std::weak_ptr<api::policy::IPolicy>& policy);
api::HandlerSync routeReload(const std::weak_ptr<::router::IRouterAPI>& router);
api::HandlerSync routePatchPriority(const std::weak_ptr<::router::IRouterAPI>& router);

api::HandlerSync tableGet(const std::weak_ptr<::router::IRouterAPI>& router,
                      const std::weak_ptr<api::policy::IPolicy>& policy);
api::HandlerSync queuePost(const std::weak_ptr<::router::IRouterAPI>& router);

api::HandlerSync changeEpsSettings(const std::weak_ptr<::router::IRouterAPI>& router);
api::HandlerSync getEpsSettings(const std::weak_ptr<::router::IRouterAPI>& router);
api::HandlerSync activateEpsLimiter(const std::weak_ptr<::router::IRouterAPI>& router);
api::HandlerSync deactivateEpsLimiter(const std::weak_ptr<::router::IRouterAPI>& router);

/**
 * @brief Register all router commands
 *
 * @param router Router to use for commands
 * @param api API to register the handlers
 */
void registerHandlers(const std::weak_ptr<::router::IRouterAPI>& router,
                      const std::weak_ptr<api::policy::IPolicy>& policy,
                      const std::shared_ptr<api::Api> api);
}

#endif // _API_ROUTER_HANDLERS_HPP
