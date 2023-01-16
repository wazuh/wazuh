#ifndef _ROUTER_ROUTER_HPP
#define _ROUTER_ROUTER_HPP

#include <atomic>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>

#include <blockingconcurrentqueue.h>

#include <baseTypes.hpp>
#include <expression.hpp>
#include <registry.hpp>

/*************************************
TODO:
- Add list route
- delete route
- Refresh routes (pipeline)
- Check if destination is valid ?
- check if destination is in the router and his route is up
- check routes aviable and the states
- check if the route is valid
- Implement all api callbacks

*************************************/

namespace router
{

class Router
{

private:
    using concurrentQueue = moodycamel::BlockingConcurrentQueue<base::Event>;

    std::size_t m_numThreads;        ///< Number of threads for the router
    std::shared_mutex m_mutexRoutes; ///< Mutex to protect the routes map

    std::unordered_map<std::string, std::vector<base::Expression>> m_routes;

    std::shared_ptr<builder::internals::Registry> m_registry; ///< Registry for builders
    std::atomic_bool m_isRunning;       ///< Flag to know if the router is running
    std::vector<std::thread> m_threads; ///< Vector of threads for the router

public:
    Router(std::shared_ptr<builder::internals::Registry> registry, std::size_t threads = 1)
        : m_mutexRoutes()
        , m_routes()
        , m_isRunning(false)
        , m_registry(registry)
        , m_numThreads(threads)
        , m_threads {}
    {
        if (threads == 0)
        {
            throw std::runtime_error("Number of threads of the router can't be 0");
        }

        if (registry == nullptr)
        {
            throw std::runtime_error("Registry can't be null");
        }
    };

    /**
     * #TODO: Change whens expression can be copied
     * @brief Get the expression of the router (all threads)
     *
     * @return const std::vector<base::Expression>
     */
    std::vector<base::Expression> getExpression(); // TODO: Move to private

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
     * @brief Launch in a new threads the router to ingest data from the queue
     *
     */
    std::optional<base::Error> run(std::shared_ptr<concurrentQueue> queue);

    /**
     * @brief Stop the router
     *
     * Returns when all threads are stopped
     */
    void stop();
};
} // namespace router
#endif // _ROUTER_ROUTER_HPP
