#include <router/router.hpp>

#include <fstream>
#include <iostream>

#include <builder.hpp>

namespace router
{
constexpr auto WAIT_DEQUEUE_TIMEOUT_USEC = 1 * 1000000;

namespace
{
struct dumpFile
{
    static const auto flags = std::ios::out | std::ios::app | std::ios::ate;
    std::ofstream m_file;
    std::string m_fileName;
    std::shared_mutex m_mutex; // Protects m_file, only one thread can write to it at a time

    explicit dumpFile(std::string filePath)
        : m_mutex {}
        , m_fileName {filePath}
    {
        m_file = std::ofstream {filePath, flags};
        if (!m_file.good())
        {
            throw std::runtime_error {fmt::format("Cannot open dump file: '{}', flooded events will be lost", filePath)};
        }
    }

    /**
     * @brief Write a string to the file
     * @param strRequest String to write
     * @return true if write failed, false otherwise
    */
    bool write(const std::string& strRequest)
    {
        std::unique_lock lock {m_mutex};
        if (m_file.good()) {
            m_file << strRequest.c_str() << std::endl;
            return false;
        }
        return true;
    }
};
} // namespace

std::optional<base::Error> Router::addRoute(const std::string& name, std::optional<int> optPriority)
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
            if (optPriority)
            {
                r.setPriority(optPriority.value());
            }
            routeInstances.push_back(r);
        }
        const auto routeName = routeInstances.front().getName();
        const auto envName = routeInstances.front().getTarget();
        const auto priority = routeInstances.front().getPriority();

        // Add the environment
        auto err = m_environmentManager->addEnvironment(envName);
        if (err)
        {
            return base::Error {err.value()};
        }
        // Link the route to the environment
        {
            std::unique_lock lock {m_mutexRoutes};
            std::optional<base::Error> err = std::nullopt;
            // Check if the route already exists, should we update it?
            if (m_namePriority.find(routeName) != m_namePriority.end())
            {
                err = base::Error {fmt::format("Route '{}' already exists", routeName)};
            }
            // Check if the priority is already taken
            if (m_priorityRoute.find(priority) != m_priorityRoute.end())
            {
                err = base::Error {fmt::format("Priority '{}' already taken", priority)};
            }
            // check error
            if (err)
            {
                lock.unlock();
                m_environmentManager->deleteEnvironment(envName);
                return err;
            }
            m_namePriority.insert(std::make_pair(routeName, priority));
            m_priorityRoute.insert(std::make_pair(priority, std::move(routeInstances)));
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

    auto it = m_namePriority.find(routeName);
    if (it == m_namePriority.end())
    {
        return base::Error {fmt::format("Route '{}' not found", routeName)};
    }
    const auto priority = it->second;

    auto it2 = m_priorityRoute.find(priority);
    if (it2 == m_priorityRoute.end())
    {
        return base::Error {fmt::format("Priority '{}' not found", priority)}; // Should never happen
    }
    const auto envName = it2->second.front().getTarget();
    // Remove from maps
    m_namePriority.erase(it);
    m_priorityRoute.erase(it2);
    lock.unlock();

    return m_environmentManager->deleteEnvironment(envName);
}

std::vector<std::tuple<std::string, std::size_t, std::string>> Router::getRouteTable()
{
    std::shared_lock lock {m_mutexRoutes};
    std::vector<std::tuple<std::string, std::size_t, std::string>> table {};
    table.reserve(m_namePriority.size());
    try
    {
        for (const auto& route : m_namePriority)
        {
            const auto& name = route.first;
            const auto& priority = route.second;
            const auto& envName = m_priorityRoute.at(priority).front().getTarget();
            table.emplace_back(name, priority, envName);
        }
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("Error getting route table: {}", e.what()); // Should never happen
    }

    // Sort by priority
    std::sort(table.begin(), table.end(), [](const auto& a, const auto& b) { return std::get<1>(a) < std::get<1>(b); });

    return table;
}

std::optional<base::Error> Router::changeRoutePriority(const std::string& name, int priority)
{
    std::unique_lock lock {m_mutexRoutes};

    auto it = m_namePriority.find(name);
    if (it == m_namePriority.end())
    {
        return base::Error {fmt::format("Route '{}' not found", name)};
    }
    const auto oldPriority = it->second;

    if (oldPriority == priority)
    {
        return std::nullopt;
    }

    auto it2 = m_priorityRoute.find(oldPriority);
    if (it2 == m_priorityRoute.end())
    {
        return base::Error {fmt::format("Priority '{}' not found", oldPriority)}; // Should never happen
    }

    // Check if the priority is already taken
    if (m_priorityRoute.find(priority) != m_priorityRoute.end())
    {
        return base::Error {fmt::format("Priority '{}' already taken", priority)};
    }

    // update the route priority
    try
    {
        for (auto& route : it2->second)
        {
            route.setPriority(priority);
        }
    }
    catch (const std::exception& e)
    {
        return base::Error {e.what()};
    }

    // Update maps
    it->second = priority;
    m_priorityRoute.insert(std::make_pair(priority, std::move(it2->second)));
    m_priorityRoute.erase(it2);

    return std::nullopt;
}

std::optional<base::Error> Router::run(std::shared_ptr<concurrentQueue> queue)
{
    std::shared_lock lock {m_mutexRoutes};

    if (m_isRunning.load())
    {
        return base::Error {"The router is already running"};
    }
    m_queue = queue; // Update queue
    m_isRunning.store(true);

    std::shared_ptr<struct dumpFile> dumpFile {nullptr};
    if (m_floodFile)
    {
        try
        {
            dumpFile = std::make_shared<struct dumpFile>(m_floodFile.value());
        }
        catch (const std::exception& e)
        {
            WAZUH_LOG_WARN("Error opening dump file: {}", e.what());
        }
    }

    for (std::size_t i = 0; i < m_numThreads; ++i)
    {
        m_threads.emplace_back(
            [this, queue, i, dumpFile]()
            {
                while (m_isRunning.load())
                {
                    base::Event event {};
                    if (queue->wait_dequeue_timed(event, WAIT_DEQUEUE_TIMEOUT_USEC))
                    {
                        std::shared_lock lock {m_mutexRoutes};

                        if (m_priorityRoute.empty() && dumpFile && dumpFile->write(event->str()))
                        {
                            WAZUH_LOG_WARN("Flood detected. Dumping events to file failed. Events will be lost.");
                            continue;
                        }
                        for (auto& route : m_priorityRoute)
                        {
                            if (route.second[i].accept(event))
                            {
                                const auto& target = route.second[i].getTarget();
                                lock.unlock();
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
        else if (action.value() == "change_priority")
        {
            response = apiChangeRoutePriority(params);
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
    const auto priority = params.getInt("/priority");
    if (!name)
    {
        response.message(R"(Missing "name" parameter)");
    }
    else
    {

        const auto err = addRoute(name.value(), priority);
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

    const std::string pathName {json::Json::formatJsonPath("name")};
    const std::string pathPriority {json::Json::formatJsonPath("priority")};
    const std::string pathTarget {json::Json::formatJsonPath("target")};

    const auto table = getRouteTable();
    for (const auto& [name, priority, envName] : table)
    {
        json::Json entry {};
        entry.setString(name, pathName);
        entry.setInt(priority, pathPriority);
        entry.setString(envName, pathTarget);
        data.appendJson(entry);
    }
    return api::WazuhResponse {data, "Ok"};
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

api::WazuhResponse Router::apiChangeRoutePriority(const json::Json& params)
{
    api::WazuhResponse response {};
    const auto name = params.getString("/name");
    const auto priority = params.getInt("/priority");

    if (!name)
    {
        response.message(R"(Missing "name" parameter)");
    }
    else if (!priority)
    {
        response.message(R"(Missing "priority" parameter)");
    }
    else
    {
        const auto err = changeRoutePriority(name.value(), priority.value());
        if (err)
        {
            response.message(err.value().message);
        }
        else
        {
            response.message(fmt::format("Route '{}' priority changed to '{}'", name.value(), priority.value()));
        }
    }

    return response;
}
} // namespace router
