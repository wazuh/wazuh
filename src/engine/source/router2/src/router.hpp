#ifndef _ROUTER2_ROUTER_HPP
#define _ROUTER2_ROUTER_HPP

#include <memory>

#include <logging/logging.hpp>

#include <router/types.hpp>

#include "environmentBuilder.hpp"
#include "table.hpp"

namespace router
{


class Router
{
private:
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

    internal::Table<RuntimeEntry> m_table;
    // TODO: User a mutex to protect the table
    std::shared_ptr<EnvironmentBuilder> m_envBuilder;

public:
    Router(const std::shared_ptr<EnvironmentBuilder>& envBuilder)
        : m_envBuilder(envBuilder)
        , m_table() {};

    Router(const std::shared_ptr<IBuilder>& builder)
        : m_envBuilder(std::make_shared<EnvironmentBuilder>(builder))
        , m_table() {};

    /**
     * @copydoc IRouter::addEnvironment
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
        try {
            auto env = m_envBuilder->create(entry.policy(), entry.filter().value());
            entry.setEnvironment(env);
            entry.setStatus(env::State::ACTIVE);
        } catch (const std::exception& e) {
            return base::Error {fmt::format("Failed to create the environment: {}", e.what())};
        }
        
        
        

        // Add metadata to the environment
        // entry.setCreated(std::time(nullptr));

        // Add the environment to the table
        if (!m_table.insert(entry.name(), entry.priority(), entry))
        {
            return base::Error {"Failed to insert the environment into the table"};
        }
        return {};
    }

    /**
     * @copydoc IRouter::removeEnvironment
     */
    base::OptError removeEnvironment(const std::string& name)
    {
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

    /**
     * @copydoc IRouter::disabledEnvironment
     * TODO Refactor this, search and disable the environment only
     * Maybe distroy the environment?
     *
     */
    base::OptError disabledEnvironment(const std::string& name)
    {

        try
        {
            auto& entry = m_table.get(name);
            entry.setStatus(env::State::INACTIVE);
        }
        catch (const std::exception& e)
        {
            return base::Error {"The environment not exist"};
        }
    }

    base::OptError changePriority(const std::string& name, size_t priority)
    {
        // Check if the priority is valid
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
