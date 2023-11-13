#ifndef _ROUTER2_ROUTER_HPP
#define _ROUTER2_ROUTER_HPP

#include <memory>

#include <router/types.hpp>

#include "environmentBuilder.hpp"
#include "table.hpp"

namespace router
{

/**
 * @class Router
 * @brief Manages the routing of events through a dynamic environment configuration.
 *
 * The Router class facilitates runtime management of environments using a dynamic table.
 * Environments are represented by RuntimeEntry objects, which store associated entries and
 * environment information.
 */
class Router {
private:
    /**
     * @class RuntimeEntry
     * @brief Represents a runtime entry with associated environment information.
     *
     * Each RuntimeEntry is a child class of the Entry class and contains an Environment object.
     */
    class RuntimeEntry : public Entry {
    private:
        Environment m_env; ///< The environment associated with the entry.

    public:
        /**
         * @brief Constructs a RuntimeEntry with the provided entry post information.
         * @param entry The entry post information.
         */
        RuntimeEntry(const EntryPost& entry)
            : Entry(entry) {};

        /**
         * @brief Sets the environment for the RuntimeEntry.
         * @param env The environment to be set.
         */
        void setEnvironment(const Environment& env) { m_env = env; }

        /**
         * @brief Retrieves the environment associated with the RuntimeEntry.
         * @return A constant reference to the associated environment.
         */
        const Environment& environment() const { return m_env; }
    };

    internal::Table<RuntimeEntry> m_table; ///< Internal table for managing RuntimeEntry objects.
    // TODO: Use a mutex to protect the table
    std::shared_ptr<EnvironmentBuilder> m_envBuilder; ///< Shared pointer to the environment builder.

public:
    /**
     * @brief Constructs a Router with the specified environment builder.
     * @param envBuilder The shared pointer to the EnvironmentBuilder.
     */
    Router(const std::shared_ptr<EnvironmentBuilder>& envBuilder)
        : m_envBuilder(envBuilder)
        , m_table() {};

    /**
     * @brief Constructs a Router with the specified builder.
     * @param builder The shared pointer to the IBuilder interface.
     */
    Router(const std::shared_ptr<IBuilder>& builder)
        : m_envBuilder(std::make_shared<EnvironmentBuilder>(builder))
        , m_table() {};

    /**
     * @brief Adds an environment to the router based on the provided entry post information.
     * @param entryPost The entry post information.
     * @return An optional error indicating the success or failure of the operation.
     */
    base::OptError addEnvironment(const EntryPost& entryPost);

    /**
     * @brief Removes the environment with the specified name from the router.
     * @param name The name of the environment to be removed.
     * @return An optional error indicating the success or failure of the operation.
     */
    base::OptError removeEnvironment(const std::string& name);

    /**
     * @brief Disables the environment with the specified name in the router.
     * @param name The name of the environment to be disabled.
     * @return An optional error indicating the success or failure of the operation.
     */
    base::OptError disabledEnvironment(const std::string& name);

    /**
     * @brief Changes the priority of the environment with the specified name.
     * @param name The name of the environment to change the priority for.
     * @param priority The new priority value.
     * @return An optional error indicating the success or failure of the operation.
     */
    base::OptError changePriority(const std::string& name, size_t priority);

    /**
     * @brief Ingests an event into the router for processing.
     * @param event The event to be ingested.
     */
    void ingest(base::Event event);
};

} // namespace router

#endif // ROUTER2_ROUTER_HPP
