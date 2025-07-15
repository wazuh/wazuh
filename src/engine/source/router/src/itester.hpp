#ifndef ROUTER_ITESTER_HPP
#define ROUTER_ITESTER_HPP

#include <base/baseTypes.hpp>
#include <base/error.hpp>
#include <list>
#include <router/types.hpp>
#include <string>
#include <unordered_map>

namespace router
{

/**
 * @brief Represents a tester instance, for testing events
 *
 * This instance should have a all testing controllers used for testing, and provide a way to manipulate them
 * and test the events with a specific configuration in particular controller.
 *
 */
class ITester
{
public:
    virtual ~ITester() = default;

    /**
     * @brief Add a new entry (policy) to the tester
     * @param entryPost The entry information for testing policy
     * @param ignoreFail If true, if the operation fails the entry is added in disabled state.
     * @return An optional error if the operation failed.
     */
    virtual base::OptError addEntry(const test::EntryPost& entryPost, bool ignoreFail = false) = 0;

    /**
     * @brief Removes a entry (testing policy) from the tester
     * @param name The name of the environment to be removed.
     * @return An optional error if the operation failed.
     */
    virtual base::OptError removeEntry(const std::string& name) = 0;

    /**
     * @brief Rebuilds the entry (testing policy) with the specified entry name.
     *
     * @note State of the environment is not changed.
     * @param name The name of the environment to be reloaded.
     * @return An optional error if the operation failed.
     */
    virtual base::OptError rebuildEntry(const std::string& name) = 0;

    /**
     * @brief Enables the environment if it is builded.
     *
     * @param name The name of the environment to be enabled
     * @return base::OptError
     */
    virtual base::OptError enableEntry(const std::string& name) = 0;

    /**
     * @brief dumps the router table.
     *
     * @return std::list<Entry> The list of entries in the router table.
     */
    virtual std::list<test::Entry> getEntries() const = 0;

    /**
     * @brief Get an environment by name.
     *
     * @param name The name of the environment to get
     * @return base::RespOrError<test::Entry> An entry or error
     */
    virtual base::RespOrError<test::Entry> getEntry(const std::string& name) const = 0;

    /**
     * @brief Ingests an event into the router for processing and returns the result.
     *
     * @param event The event to be ingested.
     * @param opt The parameters for the ingest operation.
     * @return test::Output The result or Error
     */
    virtual base::RespOrError<test::Output> ingestTest(base::Event&& event, const test::Options& opt) = 0;

    /**
     * @brief get the assets of the policy of the entry.
     * @param name The name of the entry.
     * @return base::RespOrError<std::unordered_set<std::string>> The assets of the policy.
     */
    virtual base::RespOrError<std::unordered_set<std::string>> getAssets(const std::string& name) const = 0;

    /**
     * @brief Update the last time the entry was used.
     * @param name The name of the entry.
     * @param lastUsed Last time the environment was used.
     * @return false if the entry does not exist.
     */
    virtual bool updateLastUsed(const std::string& name, uint64_t lastUsed = std::numeric_limits<uint64_t>::max()) = 0;
};

} // namespace router

#endif // ROUTER_ITESTER_HPP
