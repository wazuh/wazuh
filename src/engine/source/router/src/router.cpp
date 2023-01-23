#include <router/router.hpp>

#include <builder.hpp>

namespace router
{
constexpr auto WAIT_DEQUEUE_TIMEOUT_USEC = 1 * 1000000;

std::optional<base::Error> Router::addRoute(const std::string& name)
{

    try
    {
        // Build the same route for each thread
        std::vector<builder::Route> routeInstances {};
        routeInstances.reserve(m_numThreads);
        for (std::size_t i = 0; i < m_numThreads; ++i)
        {
            // routeInstances[i] = builder::Route {jsonDefinition, m_registry};
            auto r = m_builder->buildRoute(name);
            routeInstances.push_back(r);
        }
        const auto routeName = routeInstances.front().getName();
        const auto envName = routeInstances.front().getTarget();

        // Add the environment
        auto err = m_environmentManager->addEnvironment(envName);
        if (err)
        {
            return base::Error {err.value()};
        }

        // Link the route to the environment
        {
            std::unique_lock lock {m_mutexRoutes};
            // Check if the route already exists, should we update it?
            if (m_routes.find(routeName) != m_routes.end())
            {
                lock.unlock();
                m_environmentManager->deleteEnvironment(envName);
                return base::Error {fmt::format("Route '{}' already exists", routeName)};
            }
            m_routes.insert(std::make_pair(routeName, std::move(routeInstances)));
        }
    }
    catch (const std::exception& e)
    {
        return base::Error {e.what()};
    }
    return std::nullopt;
}

std::optional<base::Error> Router::removeRoute(const std::string& routeName)
{
    std::unique_lock lock {m_mutexRoutes};

    auto it = m_routes.find(routeName);
    if (it == m_routes.end())
    {
        return base::Error {fmt::format("Route '{}' not found", routeName)};
    }

    const auto envName = it->second.front().getTarget();
    m_routes.erase(it);
    lock.unlock();

    return m_environmentManager->deleteEnvironment(envName);
}

std::vector<std::string> Router::listRoutes()
{
    std::shared_lock lock {m_mutexRoutes};
    std::vector<std::string> names {};
    names.reserve(m_routes.size());
    std::transform(
        m_routes.begin(), m_routes.end(), std::back_inserter(names), [](auto& route) { return route.first; });
    return names;
}

std::optional<base::Error> Router::run(std::shared_ptr<concurrentQueue> queue)
{
    std::shared_lock lock {m_mutexRoutes};

    if (m_isRunning.load())
    {
        return base::Error {"The router is already running"};
    }
    // if (m_routes.empty())
    //{
    //     return base::Error {"No routes to run"};
    // }
    m_queue = queue; // Update queue
    m_isRunning.store(true);

    for (std::size_t i = 0; i < m_numThreads; ++i)
    {
        m_threads.emplace_back(
            [this, queue, i]()
            {
                while (m_isRunning.load())
                {
                    base::Event event {};
                    if (queue->wait_dequeue_timed(event, WAIT_DEQUEUE_TIMEOUT_USEC))
                    {
                        std::shared_lock lock {m_mutexRoutes};
                        // TODO: SHould we check if the event is routed?
                        for (auto& route : m_routes)
                        {
                            if (route.second[i].accept(event))
                            {
                                const auto& target = route.second[i].getTarget();
                                lock.unlock();
                                // TODO: Send event to target
                                m_environmentManager->forwardEvent(target, i, std::move(event));
                                break;
                            }
                        }
                    }
                }
                WAZUH_LOG_DEBUG("Thread [{}] router finished.", i);
            });
    };

    return std::nullopt;
}

void Router::stop()
{
    if (!m_isRunning.load())
    {
        return;
    }
    m_isRunning.store(false);
    for (auto& thread : m_threads)
    {
        thread.join();
    }
    m_threads.clear();

    WAZUH_LOG_DEBUG("Router stopped.");
}

/********************************************************************
 *                  callback API Request
 ********************************************************************/

api::CommandFn Router::apiCallbacks()
{
    return [this](const json::Json params)
    {
        api::WazuhResponse response {};
        const auto action = params.getString("/action");

        if (!action)
        {
            response.message(R"(Missing "action" parameter)");
        }
        else if (action.value() == "set")
        {
            response = apiSetRoute(params);
        }
        else if (action.value() == "get")
        {
            response = apiGetRoutes(params);
        }
        else if (action.value() == "delete")
        {
            response = apiDeleteRoute(params);
        }
        else
        {
            response.message(fmt::format("Invalid action '{}'", action.value()));
        }
        return response;
    };
}

/********************************************************************
 *                  private callback API Request
 ********************************************************************/

api::WazuhResponse Router::apiSetRoute(const json::Json& params)
{
    api::WazuhResponse response {};
    const auto name = params.getString("/name");
    if (!name)
    {
        response.message(R"(Missing "name" parameter)");
    }
    else
    {
        const auto err = addRoute(name.value());
        if (err)
        {
            response.message(err.value().message);
        }
        else
        {
            response.message(fmt::format("Route '{}' added", name.value()));
        }
    }
    return response;
}

api::WazuhResponse Router::apiGetRoutes(const json::Json& params)
{
    json::Json data {};
    data.setArray();

    const auto names = listRoutes();
    for (const auto& name : names)
    {
        data.appendString(name);
    }

    return api::WazuhResponse {data, "List of routes"};
}

api::WazuhResponse Router::apiDeleteRoute(const json::Json& params)
{
    api::WazuhResponse response {};
    const auto name = params.getString("/name");
    if (!name)
    {
        response.message(R"(Missing "name" parameter)");
    }
    else
    {
        const auto err = removeRoute(name.value());
        if (err)
        {
            response.message(err.value().message);
        }
        else
        {
            response.message(fmt::format("Route '{}' deleted", name.value()));
        }
    }
    return response;
}
} // namespace router
