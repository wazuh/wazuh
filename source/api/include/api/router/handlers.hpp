#ifndef _API_ROUTER_HANDLERS_HPP
#define _API_ROUTER_HANDLERS_HPP

#include <api/api.hpp>
#include <router/iapi.hpp>

namespace api::router::handlers
{

// Handler for router commands, returns a handler that will call the router
api::Handler routePost(const std::weak_ptr<::router::IRouterAPI>& router);
api::Handler routeDelete(const std::weak_ptr<::router::IRouterAPI>& router);
api::Handler routeGet(const std::weak_ptr<::router::IRouterAPI>& router);
api::Handler routeReload(const std::weak_ptr<::router::IRouterAPI>& router);
api::Handler routePatchPriority(const std::weak_ptr<::router::IRouterAPI>& router);

api::Handler tableGet(const std::weak_ptr<::router::IRouterAPI>& router);
api::Handler queuePost(const std::weak_ptr<::router::IRouterAPI>& router);

/**
 * @brief Register all router commands
 *
 * @param router Router to use for commands
 * @param api API to register the handlers
 */
void registerHandlers(const std::weak_ptr<::router::IRouterAPI>& router,
                      std::shared_ptr<api::Api> api);
}

#endif // _API_ROUTER_HANDLERS_HPP
