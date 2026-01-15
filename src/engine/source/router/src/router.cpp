#include <chrono>
#include <functional>

#include <base/logging.hpp>

#include "router.hpp"
#include <builder/ibuilder.hpp>

namespace
{
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

base::OptError Router::addEntry(const prod::EntryPost& entryPost, bool ignoreFail)
{
    // Create the environment
    auto entry = RuntimeEntry(entryPost);
    try
    {
        auto uniqueEnv = m_envBuilder->create(entry.namespaceId(), entry.filter());
        entry.hash(uniqueEnv->hash());
        entry.environment() = std::move(uniqueEnv);
    }
    catch (const std::exception& e)
    {
        if (!ignoreFail)
        {
            return base::Error {fmt::format("Failed to create the route: {}", e.what())};
        }
        entry.environment() = nullptr;
        entry.hash("");
        entry.lastUpdate(0);
    }
    entry.status(env::State::DISABLED); // It is disabled until all routes are ready

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

    return std::nullopt;
    ;
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
        auto uniqueEnv = m_envBuilder->create(entry.namespaceId(), entry.filter());
        entry.environment() = std::move(uniqueEnv);
        entry.lastUpdate(getStartTime());
        entry.hash(entry.environment()->hash());
        // Mantaing the status of the environment
    }
    catch (const std::exception& e)
    {
        return base::Error {fmt::format("Failed to reload the route: {}", e.what())};
    }

    return std::nullopt;
}

base::OptError Router::enableEntry(const std::string& name)
{
    std::unique_lock lock {m_mutex};
    if (!m_table.nameExists(name))
    {
        return base::Error {"The route not exist"};
    }
    auto& entry = m_table.get(name);
    if (entry.environment() == nullptr)
    {
        return base::Error {"The route is not buided"};
    }
    entry.status(env::State::ENABLED);
    entry.lastUpdate(getStartTime());
    return {};
}

base::OptError Router::changePriority(const std::string& name, size_t priority)
{

    if (priority == 0)
    {
        return base::Error {"Priority of the route cannot be 0"};
    }

    if (priority > prod::Entry::maxPriority())
    {
        return base::Error {"Priority of the route cannot be greater than "
                            + std::to_string(prod::Entry::maxPriority())};
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

base::OptError Router::hotSwapNamespace(const std::string& name, const cm::store::NamespaceId& newNamespace)
{
    // Step 1: Get entry info (filter)
    base::Name filter;
    {
        std::shared_lock lock {m_mutex};
        if (!m_table.nameExists(name))
        {
            return base::Error {"The route does not exist"};
        }
        const auto& entry = m_table.get(name);
        filter = entry.filter();
    }

    // Step 2: Create new environment WITHOUT any lock
    std::unique_ptr<Environment> newEnv;
    try
    {
        newEnv = m_envBuilder->create(newNamespace, filter);
    }
    catch (const std::exception& e)
    {
        return base::Error {
            fmt::format("Failed to create environment with new namespace '{}': {}", newNamespace.toStr(), e.what())};
    }

    // Step 3: Atomically swap the environment
    {
        std::unique_lock lock {m_mutex};

        // Verify entry still exists
        if (!m_table.nameExists(name))
        {
            return base::Error {"The route was removed during hot swap"};
        }

        auto& entry = m_table.get(name);

        // Swap the environment and enable it
        entry.environment() = std::move(newEnv);
        entry.lastUpdate(getStartTime());
        entry.hash(entry.environment()->hash());
        entry.status(env::State::ENABLED); // Always enable after successful hot swap
    }

    return std::nullopt;
}

void Router::ingest(base::Event&& event)
{
    std::shared_lock lock {m_mutex};
    bool processed {false};

    auto copies = m_table.size(); // best approximation of copies needed without really counting

    for (const auto& entry : m_table)
    {
        // TODO: Remove filtering here and do it in the Environment
        if (entry.status() == env::State::ENABLED && entry.environment()->isAccepted(event))
        {
            processed = true;
            if (copies > 1)
            {
                entry.environment()->ingest(std::make_shared<json::Json>(*event));
                copies--;
            }
            else
            {
                entry.environment()->ingest(std::move(event));
                event = nullptr;
                break;
            }
        }
    }

    if (!processed && event)
    {
        LOG_WARNING("Event not processed: {}", event->str());
    }
}

} // namespace router
