#ifndef _ROUTER2_ROUTER_HPP
#define _ROUTER2_ROUTER_HPP

#include <memory>

#include <bk/icontroller.hpp>
#include <logging/logging.hpp>

#include <router/types.hpp>

#include "environmentBuilder.hpp"
#include "table.hpp"

namespace router
{

namespace
{
class RuntimeEntry : public Entry
{

private:
    Environment m_env; ///< The environment
public:
    RuntimeEntry(const EntryPost& entry)
        : Entry(entry) {};

    void setEnvironment(const Environment& env) { m_env = env; }
    // Environment& environment() { return m_env; }
    const Environment& environment() const { return m_env; }

};
} // namespace

template<typename T>
class Router
{
private:
    internal::Table<RuntimeEntry> m_table;
    // TODO: User a mutex to protect the table
    std::shared_ptr<EnvironmentBuilder<T>> m_envBuilder;

public:
    Router(const std::shared_ptr<EnvironmentBuilder<T>>& envBuilder)
        : m_envBuilder(envBuilder)
        , m_table() {};

    /**
     * @brief Add a new environment to the router
     *
     * @param environment The environment to add
     * @return std::size_t The id of the environment
     */
    base::OptError addEnvironment(const EntryPost& entryPost)
    {
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
        auto res = m_envBuilder->create(entry.policy(), entry.filter());
        if (base::isError(res))
        {
            return base::getError(res);
        }
        entry.setEnvironment(getResponse(res));
        entry.setStatus(env::State::ACTIVE);

        // Add metadata to the environment
        // entry.setCreated(std::time(nullptr));

        // Add the environment to the table
        if (!m_table.insert(entry.name(), entry.priority(), entry))
        {
            return base::Error {"Failed to insert the environment into the table"};
        }
        return {};
    }

    base::OptError removeEnvironment(const std::string& name)
    {
        if (!m_table.nameExists(name))
        {
            return base::Error {"The name not exist"};
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

    base::OptError disabledEnvironment(const EntryPost& entryPost)
    {
        auto entry = RuntimeEntry(entryPost);

        if (m_table.nameExists(entry.name()))
        {
            return base::Error {"The name is already in use"};
        }
        else if (m_table.priorityExists(entry.priority()))
        {
            return base::Error {"The priority is already in use"};
        }

        entry.setStatus(env::State::INACTIVE);

        if (!m_table.insert(entry.name(), entry.priority(), entry))
        {
            return base::Error {"Failed to insert the environment into the table"};
        }
    }

    base::OptError changePriority(const std::string& name, size_t priority)
    {
        if (!m_table.nameExists(name))
        {
            return base::Error {"The name not exist"};
        }
        else if (!m_table.priorityExists(priority))
        {
            return base::Error {"The priority not exist"};
        }

        if (!m_table.setPriority(name, priority))
        {
            return base::Error {"Failure when trying to change priority"};
        }

        return std::nullopt;
    }

    /**
     * @brief ingest an event into the router
     */
    void ingest(base::Event event)
    {
        bool processed = false; // Remove this when the router is ready
        for (const auto& entry : m_table)
        {
            if (entry.getStatus() != env::State::ACTIVE)
            {
                continue;
            }
            if (entry.environment().isAccepted(event))
            {
                entry.environment().ingest(std::move(event));
                processed = true;
                break;
            }
        }

        if (!processed)
        {
            LOG_WARNING("Event not processed: {}", event->str());
        }
    }
};

} // namespace router

#endif // ROUTER2_ROUTER_HPP
