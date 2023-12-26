#ifndef _ROUTER_IROUTER_HPP
#define _ROUTER_IROUTER_HPP

#include <list>
#include <memory>
#include <string>

#include <router/types.hpp>

#include "environmentBuilder.hpp"

namespace router {

/**
 * @class Router
 * @brief Manages the routing of events through a dynamic environment and policies configuration.
 *
 * An environment is a policy + filter combination.
 * A filter is a set of rules that determine which events are processed by a policy
 */
class IRouter {
public:
    virtual ~IRouter() = default;

    /**
     * @brief Add a new environment to the router. The environment is disabled by default.
     * @param entryPost The entry information for the environment.
     * @paran ignoreFail
     * @return An optional error if the operation failed.
     */
    virtual base::OptError addEntry(const prod::EntryPost& entryPost, bool ignoreFail = false) = 0;

    /**
     * @brief Removes the environment
     * @param name The name of the environment to be removed.
     * @return An optional error if the operation failed.
     */
    virtual base::OptError removeEntry(const std::string& name) = 0;

    /**
     * @brief Rebuilds the environment with the specified name.
     *
     * @note state of the environment is not changed.
     * @param name The name of the environment to be reloaded.
     * @return An optional error if the operation failed.
     */
    virtual base::OptError rebuildEntry(const std::string& name) = 0;

    /**
     * @brief Enables the environment if it is builded.
     *
     * @param name The name of the environment to be enabled.
     * @return base::OptError
     */
    virtual base::OptError enableEntry(const std::string& name) = 0;

    /**
     * @brief Changes the priority of the environment with the specified name.
     * @param name The name of the environment to change the priority for.
     * @param priority The new priority value.
     * @return An optional error indicating the success or failure of the operation.
     */
    virtual base::OptError changePriority(const std::string& name, size_t priority) = 0;

    /**
     * @brief dumps the router table.
     *
     * @return std::list<Entry> The list of entries in the router table.
     */
    virtual std::list<prod::Entry> getEntries() const = 0;

    /**
     * @brief Get an environment by name.
     * @param name The name of the environment to change the priority for.
     * @return An entry or error.
     */
    virtual base::RespOrError<prod::Entry> getEntry(const std::string& name) const = 0;

    /**
     * @brief Ingest an event into the router.
     * @param event The event to be ingested.
     */
    virtual void ingest(base::Event&& event) = 0;
};

} // namespace router

#endif // _ROUTER_IROUTER_HPP
