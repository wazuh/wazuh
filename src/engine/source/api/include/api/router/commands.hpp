#ifndef _API_ROUTER_COMMANDS_HPP
#define _API_ROUTER_COMMANDS_HPP

#include <api/registry.hpp>
#include <router/router.hpp>

namespace {

}

namespace api::router::cmds
{

api::CommandFn routeGet(std::shared_ptr<::router::Router> router);
api::CommandFn routePost(std::shared_ptr<::router::Router> router);
api::CommandFn routePatch(std::shared_ptr<::router::Router> router);
api::CommandFn routeDelete(std::shared_ptr<::router::Router> router);
api::CommandFn tableGet(std::shared_ptr<::router::Router> router);
api::CommandFn queuePost(std::shared_ptr<::router::Router> router);

/**
 * @brief Register all router commands
 *
 * @param registry Registry to register commands to
 * @param router Router to use for commands
 */
void registerCommands(std::shared_ptr<::router::Router> router, std::shared_ptr<api::Registry> registry);

}

#endif // _API_ROUTER_COMMANDS_HPP
