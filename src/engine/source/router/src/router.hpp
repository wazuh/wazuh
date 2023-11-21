#ifndef _ROUTER_ROUTER_HPP
#define _ROUTER_ROUTER_HPP

#include <memory>
#include <shared_mutex>

#include <router/types.hpp>

#include "environmentBuilder.hpp"
#include "table.hpp"

namespace router
{

/**
 * @class Router
 * @brief Manages the routing of events through a dynamic environment and policies configuration.
 *
 * An environment is a policy + filter combination.
 * A filter is a set of rules that determine which events are processed by a policy
 */
class Router
{
private:
    class RuntimeEntry : public prod::Entry
    {
    private:
        std::unique_ptr<Environment> m_env; ///< The environment associated with the entry.

    public:
        explicit RuntimeEntry(const prod::EntryPost& entry)
            : prod::Entry(entry) {};

        void setEnvironment(std::unique_ptr<Environment>&& env) { m_env = std::move(env); }

        const std::unique_ptr<Environment>& environment() const { return m_env; }
        std::unique_ptr<Environment>& environment() { return m_env; }
    };

    internal::Table<RuntimeEntry> m_table; ///< Internal table for managing Production Environments.
    mutable std::shared_mutex m_mutex;     ///< Mutex for the table.

    std::shared_ptr<EnvironmentBuilder> m_envBuilder; ///< Shared pointer to the environment builder.

public:
    /**
     * @brief Constructs a Router with the specified environment builder.
     * @param envBuilder The shared pointer to the EnvironmentBuilder.
     */
    Router(const std::shared_ptr<EnvironmentBuilder>& envBuilder)
        : m_table()
        , m_mutex()
        , m_envBuilder(envBuilder) {};

    /**
     * @brief Constructs a Router with the specified builder.
     * @param builder The shared pointer to the IBuilder interface.
     */
    Router(const std::shared_ptr<IBuilder>& builder, std::shared_ptr<bk::IControllerMaker> controllerMaker)
        : m_table()
        , m_mutex()
        , m_envBuilder(std::make_shared<EnvironmentBuilder>(builder, controllerMaker)) {};

    /**
     * @brief Add a new environment to the router. The environment is disabled by default.
     * @param entryPost The entry information for the environment.
     * @return An optional error if the operation failed.
     */
    base::OptError addEntry(const prod::EntryPost& entryPost);

    /**
     * @brief Removes the environment
     * @param name The name of the environment to be removed.
     * @return An optional error if the operation failed.
     */
    base::OptError removeEntry(const std::string& name);

    /**
     * @brief Rebuilds the environment with the specified name.
     *
     * @note state of the environment is not changed.
     * @param name The name of the environment to be reloaded.
     * @return An optional error if the operation failed.
     */
    base::OptError rebuildEntry(const std::string& name);

    /**
     * @brief Enables the environment if it is builded.
     *
     * @param name
     * @return base::OptError
     */
    base::OptError enableEntry(const std::string& name);

    /**
     * @brief Changes the priority of the environment with the specified name.
     * @param name The name of the environment to change the priority for.
     * @param priority The new priority value.
     * @return An optional error indicating the success or failure of the operation.
     */
    base::OptError changePriority(const std::string& name, size_t priority);

    /**
     * @brief dumps the router table.
     *
     * @return std::list<Entry> The list of entries in the router table.
     */
    std::list<prod::Entry> getEntries() const;

    /**
     * @brief Get an environment by name.
     *
     */
    base::RespOrError<prod::Entry> getEntry(const std::string& name) const;

    /**
     * @brief Ingests an event into the router for processing.
     * @param event The event to be ingested.
     */
    void ingest(base::Event&& event);

    // /**
    //  * @brief Ingests an event into the router for processing and returns the result.
    //  * // TODO Move to private
    //  * @param event The event to be ingested.
    //  * @param opt The optional parameters for the ingest operation.
    //  * @return test::Output The result
    //  */
    //   base::RespOrError<test::Output>
    //   ingestTest(base::Event&& event, const std::string& name, const std::vector<std::string>& assets);
};

} // namespace router

#endif // ROUTER_ROUTER_HPP
