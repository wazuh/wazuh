#ifndef ROUTER_TESTER_HPP
#define ROUTER_TESTER_HPP

#include <list>
#include <memory>
#include <shared_mutex>
#include <unordered_map>

#include <bk/icontroller.hpp>

#include <router/types.hpp>

#include "environmentBuilder.hpp"

namespace router
{

/**
 * @brief Represents a tester instance, for testing events
 *
 * This instance should have a all testing controllers used for testing, and provide a way to manipulate them
 * and test the events with a specific configuration in particular controller.
 *
 */
class Tester
{
private:
    class RuntimeEntry : public test::Entry
    {
    private:
        std::shared_ptr<bk::IController> m_controller;

    public:
        explicit RuntimeEntry(const test::EntryPost& entry)
            : test::Entry(entry) {};

        ~RuntimeEntry()
        {
            if (m_controller)
            {
                m_controller->stop();
            }
        }

        void setController(std::shared_ptr<bk::IController>&& controller) { m_controller = std::move(controller); }

        const std::shared_ptr<bk::IController>& controller() const { return m_controller; }
        std::shared_ptr<bk::IController>& controller() { return m_controller; }
    };

    std::shared_ptr<bk::IController> createController(const base::Name& policy);

    std::shared_ptr<EnvironmentBuilder> m_envBuilder;      ///< Shared pointer to the controller builder.
    std::unordered_map<std::string, RuntimeEntry> m_table; ///< Internal table for managing Testing Environments.
    mutable std::shared_mutex m_mutex;                     ///< Mutex for the table.

public:
    Tester(const std::shared_ptr<EnvironmentBuilder>& envBuilder)
        : m_envBuilder(envBuilder) {};
    /**
     * @brief Add a new entry (policy) to the tester
     * @param entryPost The entry information for testing policy
     * @return An optional error if the operation failed.
     */
    base::OptError addEntry(const test::EntryPost& entryPost);

    /**
     * @brief Removes a entry (testing policy) from the tester
     * @param name The name of the environment to be removed.
     * @return An optional error if the operation failed.
     */
    base::OptError removeEntry(const std::string& name);

    /**
     * @brief Rebuilds the entry (testing policy) with the specified entry name.
     *
     * @note State of the environment is not changed.
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
     * @brief dumps the router table.
     *
     * @return std::list<Entry> The list of entries in the router table.
     */
    std::list<test::Entry> getEntries() const;

    /**
     * @brief Get an environment by name.
     *
     */
    base::RespOrError<test::Entry> getEntry(const std::string& name) const;

    /**
     * @brief Ingests an event into the router for processing and returns the result.
     *
     * @param event The event to be ingested.
     * @param opt The parameters for the ingest operation.
     * @return test::Output The result
     */
    base::RespOrError<test::Output> ingestTest(base::Event&& event, const test::Options& opt);

    /**
     * @brief get the assets of the policy of the entry.
     * @param name The name of the entry.
     * @return base::RespOrError<std::unordered_set<std::string>> The assets of the policy.
     */
    base::RespOrError<std::unordered_set<std::string>> getAssets(const std::string& name) const;
};
} // namespace router

#endif // ROUTER_TESTER_HPP