#include <functional>
#include <chrono>

#include <logging/logging.hpp>

#include "router.hpp"

namespace router
{

base::OptError Router::addEnvironment(const EntryPost& entryPost)
{
    std::unique_lock lock {m_mutex};
    // Create the environment
    auto entry = RuntimeEntry(entryPost);

    if (m_table.nameExists(entry.name()))
    {
        return base::Error {"The name is already in use"};
    }

    if (entry.isTesting())
    {
        return base::Error {"TODO The environment is for testing"};
    }
    else if (m_table.priorityExists(entry.priority()))
    {
        return base::Error {"The priority is already in use"};
    }

    // Create the environment
    try
    {
        auto uniqueEnv = m_envBuilder->create(entry.policy(), entry.filter().value());
        entry.setEnvironment(std::move(uniqueEnv));
        entry.setStatus(env::State::ACTIVE);
    }
    catch (const std::exception& e)
    {
        return base::Error {fmt::format("Failed to create the environment: {}", e.what())};
    }

    if(entry.getCreated() == 0)
    {
        auto startTime = std::chrono::system_clock::now();
        auto epochTime = std::chrono::duration_cast<std::chrono::seconds>(startTime.time_since_epoch()).count();
        entry.setCreated(epochTime);
    }

    // Add the environment to the table
    auto name = entry.name();
    auto priority = entry.priority();
    if (!m_table.insert(name, priority, std::move(entry)))
    {
        return base::Error {"Failed to insert the environment into the table"};
    }
    return {};
}

base::OptError Router::removeEnvironment(const std::string& name)
{
    std::unique_lock lock {m_mutex};
    if (!m_table.nameExists(name))
    {
        return base::Error {"The environment not exist"};
    }
    else
    {
        if (!m_table.erase(name))
        {
            return base::Error {"Failed to delete the environment from the table"};
        }
    }

    return std::nullopt;
}

base::OptError Router::disabledEnvironment(const std::string& name)
{
    std::unique_lock lock {m_mutex};
    try
    {
        auto& entry = m_table.get(name);
        entry.setStatus(env::State::INACTIVE);
    }
    catch (const std::exception& e)
    {
        return base::Error {"The environment not exist"};
    }

    return {};
}

base::OptError Router::changePriority(const std::string& name, size_t priority)
{
    std::unique_lock lock {m_mutex};
    // Check if the priority is valid only for production environments
    if (Priority::validate(priority, false))
    {
        return base::Error {fmt::format("The priority '{}' is not in the valid range [{}-{}]",
                                        priority,
                                        static_cast<size_t>(Priority::Limits::MinProd),
                                        static_cast<size_t>(Priority::Limits::MaxProd))};
    }

    if (!m_table.nameExists(name))
    {
        return base::Error {"The environment not exist"};
    }

    auto& entry = m_table.get(name);
    if (entry.isTesting())
    {
        return base::Error {"Cannot change the priority of a testing environment"};
    }

    if (!m_table.setPriority(name, priority))
    {
        return base::Error {"Failed to change the priority, it is already in use"};
    }
    // Sync the priority
    entry.setPriority(priority);

    return {};
}

std::list<Entry> Router::getEntries() const
{
    std::shared_lock lock {m_mutex};
    std::list<Entry> entries;

    for (const auto& entry : m_table)
    {
        entries.push_back(entry);
    }

    return entries;
}

void Router::ingest(base::Event event)
{
    std::shared_lock lock {m_mutex};
    bool processed = false; // Remove this when the router is ready
    for (const auto& entry : m_table)
    {
        if (entry.getStatus() != env::State::ACTIVE)
        {
            continue;
        }
        if (entry.environment()->isAccepted(event))
        {
            event = entry.environment()->ingestGet(std::move(event));
            processed = true;
            break;
        }
    }

    if (!processed)
    {
        LOG_WARNING("Event not processed: {}", event->str());
    }
}

base::RespOrError<test::Output>
Router::ingestTest(base::Event event, const std::string& name, const std::vector<std::string>& assets)
{
    std::shared_lock lock {m_mutex};
    if (!m_table.nameExists(name))
    {
        return base::Error {"The environment not exist"};
    }

    auto& entry = m_table.get(name);
    if (entry.getStatus() != env::State::ACTIVE)
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
} // namespace router
