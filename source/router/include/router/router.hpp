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
#include <route.hpp>

#include "environmentManager.hpp"

namespace router
{

/**
 * @brief Router class to manage routes and events
 *
 * The router is the main class of the router module. It manages the routes and has the logic to route the events to the
 * correct environment. Also it has the thread pool to process the events, and the environment manager to manage the
 * runtime environments (creation, destruction, and interaction).
 * Get the events from the queue, select the correct environment (with the route priority and conditions), and send the
 * event to the environment.
 */
class Router
{

private:
    using concurrentQueue = moodycamel::BlockingConcurrentQueue<base::Event>;

    /* Status */
    /**
     * @brief Map of routes, each route is a vector of expressions, each expression for each thread
     */
    std::unordered_map<std::string, std::size_t> m_namePriority;
    std::map<std::size_t, std::vector<builder::Route>> m_priorityRoute;
    std::shared_mutex m_mutexRoutes;    ///< Mutex to protect the routes map
    std::atomic_bool m_isRunning;       ///< Flag to know if the router is running
    std::vector<std::thread> m_threads; ///< Vector of threads for the router

    /* Resources */
    std::shared_ptr<EnvironmentManager> m_environmentManager; ///< Environment manager
    std::shared_ptr<builder::Builder> m_builder;              ///< Builder
    std::shared_ptr<concurrentQueue> m_queue;                 ///< Queue to get events

    /* Config */
    std::size_t m_numThreads; ///< Number of threads for the router

    /* Api callbacks */
    /**
     * @brief API callback for route creation
     *
     * @param params Parameters for route creation ("/name"), optional priority ("/priority") to override the default
     * @return api::WazuhResponse with the result of the operation
     */
    api::WazuhResponse apiSetRoute(const json::Json& params);

    /**
     * @brief API callback for list routes
     * @param params none
     * @return api::WazuhResponse with the result of the operation, a list of  entries with the name, priority and target
     *
     */
    api::WazuhResponse apiGetRoutes(const json::Json& params);

    /**
     * @brief API callback for route deletion
     *
     * @param params Parameters for route deletion ("/name")
     * @return api::WazuhResponse with the result of the operation
     */
    api::WazuhResponse apiDeleteRoute(const json::Json& params);

    api::WazuhResponse apiChangeRoutePriority(const json::Json& params);

public:
    Router(std::shared_ptr<builder::Builder> builder,
           std::size_t threads = 1)
        : m_mutexRoutes {}
        , m_namePriority {}
        , m_priorityRoute {}
        , m_isRunning {false}
        , m_numThreads {threads}
        , m_threads {}
        , m_builder {builder}
    {
        if (threads == 0)
        {
            throw std::runtime_error("Router: The number of threads must be greater than 0.");
        }

        if (builder == nullptr)
        {
            throw std::runtime_error("Router: Builder can't be null.");
        }

        m_environmentManager = std::make_shared<EnvironmentManager>(builder, threads);
    };

    /**
     * @brief Get the list of route names, priority and target
     *
     * @return std::unordered_set<std::string>
     */
    std::vector<std::tuple<std::string, std::size_t, std::string>> getRouteTable();

    /**
     * @brief Change the priority of a route
     *
     * @param name name of the route
     * @param priority new priority
     * @return std::optional<base::Error> A error with description if the route can't be changed
     */
    std::optional<base::Error> changeRoutePriority(const std::string& name, int priority);

    /**
     * @brief Add a new route to the router.
     *
     * Optionally, the priority can be specified. If not, the priority is the especified in the route.
     * If the route already exists or the priority is already used, the route is not
     * added.
     * @param name name of the route
     * @return A error with description if the route can't be added
     */
    std::optional<base::Error> addRoute(const std::string& name, std::optional<int> optPriority = std::nullopt);

    /**
     * @brief Delete a route from the router
     *
     * @param name name of the route
     * @return A error with description if the route can't be deleted
     */
    std::optional<base::Error> removeRoute(const std::string& name);

    /**
     * @brief Launch in a new threads the router to ingest data from the queue.
     */
    std::optional<base::Error> run(std::shared_ptr<concurrentQueue> queue);

    /**
     * @brief Stop the router
     *
     * Send a stop signal to the router and wait for the threads to finish.
     */
    void stop();

    /**
     * @brief Main API callback for environment management
     *
     * @return api::CommandFn
     */
    api::CommandFn apiCallbacks();
};
} // namespace router
#endif // _ROUTER_ROUTER_HPP
