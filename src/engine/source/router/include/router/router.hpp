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

namespace router
{

class Router
{

private:
    using concurrentQueue = moodycamel::BlockingConcurrentQueue<base::Event>;

    std::size_t m_numThreads; // Todo const?
    std::shared_mutex m_mutexRoutes;
    std::atomic_bool m_isRunning;
    std::vector<std::thread> m_threads;

    std::unordered_map<std::string, std::vector<base::Expression>> m_routes;
    std::shared_ptr<builder::internals::Registry> m_registry;

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
            throw std::runtime_error("Number of threads can't be 0");
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
