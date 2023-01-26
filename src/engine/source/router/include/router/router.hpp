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
    std::optional<std::string> m_floodFile;               ///< File to log floods

    /* Config */
    std::size_t m_numThreads; ///< Number of threads for the router

    /* Api callbacks */
    /**
     * @brief API callback for route creation
     *
     * @param params Parameters for route creation ("/name")
     * @return api::WazuhResponse with the result of the operation
     */
    api::WazuhResponse apiSetRoute(const json::Json& params);

    /**
     * @brief API callback for list routes
     * @param params
     * @return api::WazuhResponse with the result of the operation
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
    Router(std::shared_ptr<builder::Builder> builder, std::size_t threads = 1, std::optional<std::string> floodFile = std::nullopt)
        : m_mutexRoutes {}
        , m_namePriority {}
        , m_priorityRoute {}
        , m_isRunning {false}
        , m_numThreads {threads}
        , m_threads {}
        , m_builder {builder}
        , m_floodFile {floodFile}
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
     * @brief Get the list of route names
     *
     * @return std::unordered_set<std::string>
     */
    std::vector<std::tuple<std::string, std::size_t, std::string>> getRouteTable();

    std::optional<base::Error> changeRoutePriority(const std::string& name, int priority);

    /**
     * @brief add a new route to the router
     *
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
     *
     */
    std::optional<base::Error> run(std::shared_ptr<concurrentQueue> queue);

    /**
     * @brief Stop the router
     *
     * Returns when all threads are stopped
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
