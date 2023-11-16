#include <functional>
#include <chrono>

#include <logging/logging.hpp>

#include "router.hpp"

namespace {
/**
 * @brief Return the current time in seconds since epoch
 */
int64_t getStartTime()
{
    auto startTime = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::seconds>(startTime.time_since_epoch()).count();
}
} // namespace
namespace router
{

base::OptError Router::addEntry(const prod::EntryPost& entryPost)
{
    // Create the environment
    auto entry = RuntimeEntry(entryPost);
    try
    {
        auto uniqueEnv = m_envBuilder->create(entry.policy(), entry.filter());
        entry.setEnvironment(std::move(uniqueEnv));
        entry.status(env::State::DISABLED); // It is disabled until all routes are ready
        entry.lastUpdate(getStartTime());
    }
    catch (const std::exception& e)
    {
        return base::Error {fmt::format("Failed to create the environment: {}", e.what())};
    }

    // Add the entry to the table
    {
        std::unique_lock<std::shared_mutex> lock {m_mutex};
        if (m_table.nameExists(entryPost.name()))
        {
            return base::Error {"The name of the route is already in use"};
        }

        if (m_table.priorityExists(entryPost.priority()))
        {
            return base::Error {"The priority of the route  is already in use"};
        }
        m_table.insert(entryPost.name(), entryPost.priority(), std::move(entry));
    }

    return std::nullopt;;
}

base::OptError Router::removeEntry(const std::string& name)
{
    std::unique_lock lock {m_mutex};
    if (!m_table.nameExists(name))
    {
        return base::Error {"The route not exist"};
    }
    m_table.erase(name);
    return std::nullopt;
}

base::OptError Router::rebuildEntry(const std::string& name)
{
    std::unique_lock lock {m_mutex};
    if (!m_table.nameExists(name))
    {
        return base::Error {"The route not exist"};
    }
    auto& entry = m_table.get(name);
    try
    {
        auto uniqueEnv = m_envBuilder->create(entry.policy(), entry.filter());
        entry.setEnvironment(std::move(uniqueEnv));
        entry.lastUpdate(getStartTime());
        // Mantaing the status of the environment
    }
    catch (const std::exception& e)
    {
        return base::Error {fmt::format("Failed to reload the route: {}", e.what())};
    }

    return std::nullopt;
}

base::OptError Router::enableEntry(const std::string& name) {
    std::unique_lock lock {m_mutex};
    if (!m_table.nameExists(name))
    {
        return base::Error {"The route not exist"};
    }
    auto& entry = m_table.get(name);
    if (entry.environment() == nullptr)
    {
        return base::Error {"The route is not buided"}; // bad init in startup
    }
    entry.status(env::State::ENABLED);
    return {};
}

base::OptError Router::changePriority(const std::string& name, size_t priority)
{

    if (priority == 0)
    {
        return base::Error {"Priority of the route cannot be 0"};
    }

    std::unique_lock lock {m_mutex};

    if (!m_table.nameExists(name))
    {
        return base::Error {"The route not exist"};
    }

    if (!m_table.setPriority(name, priority))
    {
        return base::Error {"Failed to change the priority, it is already in use"};
    }
    // Sync the priority
    m_table.get(name).priority(priority);

    return {};
}

std::list<prod::Entry> Router::getEntries() const
{
    std::shared_lock lock {m_mutex};
    std::list<prod::Entry> entries;

    for (const auto& entry : m_table)
    {
        entries.push_back(entry);
        // TODO Update states
    }
    return entries;
}

base::RespOrError<prod::Entry> Router::getEntry(const std::string& name) const
{
    std::shared_lock lock {m_mutex};
    if (!m_table.nameExists(name))
    {
        return base::Error {"The route not exist"};
    }
    return m_table.get(name);
}

void Router::ingest(base::Event&& event)
{
    std::shared_lock lock {m_mutex};

    for (const auto& entry : m_table)
    {
        if (entry.status() == env::State::ENABLED && entry.environment()->isAccepted(event))
        {
            entry.environment()->ingest(std::move(event));
            event = nullptr;
            break;
        }
    }

    if (event)
    {
        LOG_WARNING("Event not processed: {}", event->str());
    }
}

/*
base::RespOrError<test::Output>
Router::ingestTest(base::Event event, const std::string& name, const std::vector<std::string>& assets)
{
    std::shared_lock lock {m_mutex};
    if (!m_table.nameExists(name))
    {
        return base::Error {"The environment not exist"};
    }

    auto& entry = m_table.get(name);
    if (entry.getStatus() != env::State::ENABLED)
    {
        return base::Error {"The environment is not active"};
    }

    if (!entry.isTesting())
    {
        return base::Error {"The environment is not for testing"};
    }

    // Get the environment to ingest the event
    auto& env = entry.environment();

    // Create a return value
    test::Output output;

    // Suscribe to traces
    if (!assets.empty())
    {
        auto addTraceFn = std::bind(&test::TraceStorage::addTrace,
                                    &output.m_tracingObj,
                                    std::placeholders::_1,
                                    std::placeholders::_2,
                                    std::placeholders::_3);
        auto err = env->subscribeTrace(addTraceFn, assets);

        if (err)
        {
            return base::Error {fmt::format("Failed to running the test mode: {}", base::getError(err).message)};
        }
    }
    // Ingest the event
    output.m_event = env->ingestGet(std::move(event));

    env->cleanSubscriptions();
    return output;
}
*/


} // namespace router
