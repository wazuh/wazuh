#ifndef _API_ROUTER_HANDLERS_HPP
#define _API_ROUTER_HANDLERS_HPP

#include <api/registry.hpp>
#include <router/router.hpp>

namespace api::router::handlers
{

api::Handler routeGet(std::shared_ptr<::router::Router> router);
api::Handler routePost(std::shared_ptr<::router::Router> router);
api::Handler routePatch(std::shared_ptr<::router::Router> router);
api::Handler routeDelete(std::shared_ptr<::router::Router> router);
api::Handler tableGet(std::shared_ptr<::router::Router> router);
api::Handler queuePost(std::shared_ptr<::router::Router> router);

/**
 * @brief Register all router commands
 *
 * @param registry Registry to register commands to
 * @param router Router to use for commands
 */
void registerHandlers(std::shared_ptr<::router::Router> router, std::shared_ptr<api::Registry> registry);

}

#endif // _API_ROUTER_HANDLERS_HPP
