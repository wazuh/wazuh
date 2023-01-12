#ifndef _ROUTER_ROUTER_HPP
#define _ROUTER_ROUTER_HPP

#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

#include <baseTypes.hpp>
#include <expression.hpp>
#include <registry.hpp>

namespace router
{

class Router
{

private:
    std::size_t m_threads; // Todo const?
    std::mutex m_mutexRoutes;
    std::unordered_map<std::string, std::vector<base::Expression>> m_routes;
    std::shared_ptr<builder::internals::Registry> m_registry;

public:
    Router(std::shared_ptr<builder::internals::Registry> registry, std::size_t threads = 1)
        : m_mutexRoutes()
        , m_routes()
        , m_registry(registry)
        , m_threads(threads)
    {
        if (threads == 0)
        {
            throw std::runtime_error("Number of threads can't be 0");
        }
    };

    /**
     * #TODO: Change whens expression can be copied
     * @brief Get the expression of the router (all threads)
     *
     * @return const std::vector<base::Expression>
     */
    std::vector<base::Expression> getExpression();

    /**
     * @brief Get the list of route names
     *
     * @return std::unordered_set<std::string>
     */
    std::vector<std::string> getRouteNames();

    /**
     * @brief add a new route to the router
     *
     * @param jsonDefinition json definition of the route (asset)
     * @return A error with description if the route can't be added
     */
    std::optional<base::Error> addRoute(const json::Json& jsonDefinition);

    /**
     * @brief remove a route from the router
     *
     * @param name name of the route
     * @return A error with description if the route can't be removed
     * #TODO: implement
     */
    std::optional<base::Error> removeRoute(const std::string& name);

    /**
     * @brief List all the routes
     *
     * @return A json with the list of routes
     * #TODO: Format of the json
     * #TODO: implement
     */
    json::Json jListRoutes();
};
} // namespace router
#endif // _ROUTER_ROUTER_HPP
