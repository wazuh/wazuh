#include <router/router.hpp>

#include <fstream>
#include <iostream>

#include <builder.hpp>

#include <parseEvent.hpp>

namespace router
{
constexpr auto WAIT_DEQUEUE_TIMEOUT_USEC = 1 * 1000000;

Router::Router(std::shared_ptr<builder::Builder> builder, std::shared_ptr<store::IStore> store, std::size_t threads)
    : m_mutexRoutes {}
    , m_namePriorityFilter {}
    , m_priorityRoute {}
    , m_isRunning {false}
    , m_numThreads {threads}
    , m_store {store}
    , m_threads {}
    , m_builder {builder}
{
    if (0 == threads || 128 < threads)
    {
        throw std::runtime_error("Router: The number of threads must be between 1 and 128");
    }

    if (nullptr == builder)
    {
        throw std::runtime_error("Router: Builder cannot be null");
    }

    if (nullptr == store)
    {
        throw std::runtime_error("Router: Store cannot be null");
    }

    m_environmentManager = std::make_shared<EnvironmentManager>(builder, threads);

    auto result = m_store->get(ROUTES_TABLE_NAME);
    if (std::holds_alternative<base::Error>(result))
    {
        const auto error = std::get<base::Error>(result);
        WAZUH_LOG_DEBUG("Router: Routes table not found in store. Creating new table. {}", error.message);
        m_store->add(ROUTES_TABLE_NAME, json::Json {"[]"});
        return;
    }
    else
    {
        const auto table = std::get<json::Json>(result).getArray();
        if (!table.has_value())
        {
            throw std::runtime_error("Can not get routes table from store. Invalid table format.");
        }

        for (const auto& jRoute : *table)
        {
            const auto name = jRoute.getString(JSON_PATH_NAME);
            const auto priority = jRoute.getInt(JSON_PATH_PRIORITY);
            const auto filter = jRoute.getString(JSON_PATH_FILTER);
            const auto target = jRoute.getString(JSON_PATH_TARGET);
            if (!name.has_value() || !priority.has_value() || !target.has_value() || !filter.has_value())
            {
                throw std::runtime_error("Router: Cannot get routes table from store. Invalid table format");
            }

            const auto err = addRoute(name.value(), priority.value(), filter.value(), target.value());
            if (err.has_value())
            {
                WAZUH_LOG_WARN("Router: couldn't add route " + name.value() + " to the router: {}",
                               err.value().message);
            }
        }
    }
    // check if the table is empty
    if (getRouteTable().empty())
    {
        // Add default route
        WAZUH_LOG_WARN("There is no environment loaded. Events will be written in disk once the queue is full.");
    }
};

std::optional<base::Error>
Router::addRoute(const std::string& routeName, int priority, const std::string& filterName, const std::string& envName)
{
    // Validate route name
    if (routeName.empty())
    {
        return base::Error {"Route name cannot be empty"};
    }
    // Validate Filter name
    if (filterName.empty())
    {
        return base::Error {"Filter name cannot be empty"};
    }
    // Validate environment name
    if (envName.empty())
    {
        return base::Error {"Environment name cannot be empty"};
    }
    try
    {
        // Build the same route for each thread
        std::vector<Route> routeInstances {};
        routeInstances.reserve(m_numThreads);
        for (std::size_t i = 0; i < m_numThreads; ++i)
        {
            auto filter = m_builder->buildFilter(filterName);
            routeInstances.emplace_back(Route {routeName, filter, envName, priority});
        }

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
            if (m_namePriorityFilter.find(routeName) != m_namePriorityFilter.end())
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
            m_namePriorityFilter.insert(std::make_pair(routeName, std::make_tuple(priority, filterName)));
            m_priorityRoute.insert(std::make_pair(priority, std::move(routeInstances)));
        }
    }
    catch (const std::exception& e)
    {
        return base::Error {e.what()};
    }
    dumpTableToStorage();
    return std::nullopt;
}

std::optional<base::Error> Router::removeRoute(const std::string& routeName)
{
    std::unique_lock lock {m_mutexRoutes};

    auto it = m_namePriorityFilter.find(routeName);
    if (it == m_namePriorityFilter.end())
    {
        return base::Error {fmt::format("Route '{}' not found", routeName)};
    }
    const auto priority = std::get<0>(it->second);

    auto it2 = m_priorityRoute.find(priority);
    if (it2 == m_priorityRoute.end())
    {
        return base::Error {fmt::format("Priority '{}' not found", priority)}; // Should never happen
    }
    const auto envName = it2->second.front().getTarget();
    // Remove from maps
    m_namePriorityFilter.erase(it);
    m_priorityRoute.erase(it2);
    lock.unlock();

    dumpTableToStorage();
    return m_environmentManager->deleteEnvironment(envName);
}

std::vector<Router::Entry> Router::getRouteTable()
{
    std::shared_lock lock {m_mutexRoutes};
    std::vector<Entry> table {};
    table.reserve(m_namePriorityFilter.size());
    try
    {
        for (const auto& route : m_namePriorityFilter)
        {
            const auto& name = route.first;
            const auto& priority = std::get<0>(route.second);
            const auto& filterName = std::get<1>(route.second);
            const auto& envName = m_priorityRoute.at(priority).front().getTarget();
            table.emplace_back(name, priority, filterName, envName);
        }
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("Error getting route table: {}", e.what()); // Should never happen
    }
    lock.unlock();

    // Sort by priority
    std::sort(table.begin(), table.end(), [](const auto& a, const auto& b) { return std::get<1>(a) < std::get<1>(b); });

    return table;
}

std::optional<Router::Entry> Router::getEntry(const std::string& name)
{
    std::shared_lock lock {m_mutexRoutes};
    auto it = m_namePriorityFilter.find(name);
    if (it == m_namePriorityFilter.end())
    {
        return std::nullopt;
    }
    const auto& [priority, filterName] = it->second;
    const auto& envName = m_priorityRoute.at(priority).front().getTarget();

    return Entry {name, priority, filterName, envName};
}

std::optional<base::Error> Router::changeRoutePriority(const std::string& name, int priority)
{
    std::unique_lock lock {m_mutexRoutes};

    auto it = m_namePriorityFilter.find(name);
    if (it == m_namePriorityFilter.end())
    {
        return base::Error {fmt::format("Route '{}' not found", name)};
    }
    const auto oldPriority = std::get<0>(it->second);

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
    std::get<0>(it->second) = priority;
    m_priorityRoute.insert(std::make_pair(priority, std::move(it2->second)));
    m_priorityRoute.erase(it2);
    lock.unlock();

    dumpTableToStorage();
    return std::nullopt;
}

std::optional<base::Error> Router::enqueueEvent(base::Event event)
{
    if (!m_isRunning.load() || !m_queue)
    {
        return base::Error {"The router queue is not initialized"};
    }
    if (m_queue->try_enqueue(std::move(event)))
    {
        return std::nullopt;
    }
    return base::Error {"The router queue is in high load"};
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

/*
base::utils::wazuhProtocol::WazuhResponse Router::apiGetRoutes(const json::Json& params)
{
    json::Json data {};
    // Filter by name
    const auto name = params.getString(JSON_PATH_NAME);
    if (name)
    {
        auto entry = getEntry(name.value());
        if (entry)
        {
            data.setString(std::get<0>(entry.value()), JSON_PATH_NAME);
            data.setInt(std::get<1>(entry.value()), JSON_PATH_PRIORITY);
            data.setString(std::get<2>(entry.value()), JSON_PATH_FILTER);
            data.setString(std::get<3>(entry.value()), JSON_PATH_TARGET);
        }
        else
        {
            data.setObject();
        }
    }
    else
    {
        data = tableToJson();
    }

    return base::utils::wazuhProtocol::WazuhResponse {data, "Ok"};
}

base::utils::wazuhProtocol::WazuhResponse Router::apiDeleteRoute(const json::Json& params)
{
    base::utils::wazuhProtocol::WazuhResponse response {};
    const auto name = params.getString(JSON_PATH_NAME);
    if (!name)
    {
        response.message(R"(Error: Error: Missing "priority" parameter)");
    }
    else
    {
        const auto err = removeRoute(name.value());
        if (err)
        {
            response.message(std::string {"Error: "} + err.value().message);
        }
        else
        {
            response.message(fmt::format("Route '{}' deleted", name.value()));
        }
    }
    return response;
}

base::utils::wazuhProtocol::WazuhResponse Router::apiChangeRoutePriority(const json::Json& params)
{
    base::utils::wazuhProtocol::WazuhResponse response {};
    const auto name = params.getString(JSON_PATH_NAME);
    const auto priority = params.getInt(JSON_PATH_PRIORITY);

    if (!name)
    {
        response.message(R"(Error: Error: Missing "priority" parameter)");
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

base::utils::wazuhProtocol::WazuhResponse Router::apiEnqueueEvent(const json::Json& params)
{
    base::utils::wazuhProtocol::WazuhResponse response {};
    const auto event = params.getString(JSON_PATH_EVENT);
    if (!event)
    {
        response.message(R"(Error: Missing "event" parameter)");
    }
    else
    {
        try
        {
            base::Event ev = base::parseEvent::parseOssecEvent(event.value());
            auto err = enqueueEvent(ev);
            if (err)
            {
                response.message(err.value().message);
            }
            else
            {
                response.message("Ok");
            }
        }
        catch (const std::exception& e)
        {
            response.message(fmt::format("Error: {} ", e.what()));
        }
    }
    return response;
}
*/
json::Json Router::tableToJson()
{
    json::Json data {};
    data.setArray();

    const auto table = getRouteTable();
    for (const auto& [name, priority, filterName, envName] : table)
    {
        json::Json entry {};
        entry.setString(name, JSON_PATH_NAME);
        entry.setInt(priority, JSON_PATH_PRIORITY);
        entry.setString(filterName, JSON_PATH_FILTER);
        entry.setString(envName, JSON_PATH_TARGET);
        data.appendJson(entry);
    }
    return data;
}

void Router::dumpTableToStorage()
{
    const auto err = m_store->update(ROUTES_TABLE_NAME, tableToJson());
    if (err)
    {
        WAZUH_LOG_ERROR("Error updating routes table: {}", err.value().message);
        exit(10);
        // TODO: throw exception and exit program (Review when the exit policy is implemented)
    }
}

void Router::clear()
{
    {
        std::unique_lock lock {m_mutexRoutes};
        m_namePriorityFilter.clear();
        m_priorityRoute.clear();
    }

    dumpTableToStorage();
    m_environmentManager->delAllEnvironments();
}

} // namespace router
