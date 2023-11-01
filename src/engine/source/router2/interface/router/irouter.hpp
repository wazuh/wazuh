#ifndef _ROUTER2_IROUTER_HPP
#define _ROUTER2_IROUTER_HPP

#include <optional>
#include <string>

#include <name.hpp>
#include <error.hpp>

namespace router
{
using Entry = std::string; // Represent a human readable entry of the routing table
using EnvID = std::size_t; // Represent a unique id of an environment


class Environment
{
public:
    using Filter = std::string; // base::Name or DynamicFilter
    enum class Status
    {
        INACTIVE, ///< Environment is inactive, it's not being used
        BUILDED,  ///< Environment is builded, it's ready to be used
        ACTIVE,   ///< Environment is active, it's being used
        ERROR     ///< Environment is in error state (not used), (If can't be builded or activated)
    };

    enum class PolicySync
    {
        UPDATED,  ///< Policy is updated
        OUTDATED, ///< Policy is outdated respect to the store
        DELETED,  ///< Policy is deleted not exist in the store
        ERROR     ///< Error, can't get the policy status
    };

private:
    // Environment
    std::size_t m_id;    ///< Unique id of the environment
    Filter m_filter;     ///< Filter of of the environment (base::Name or dynamic filter)
    std::size_t m_prior; ///< Priority of the environment
    base::Name m_policy; ///< Policy of the environment

    // Status
    Status m_status;                         ///< Status of the environment
    std::optional<std::uint64_t> m_lifetime; ///< Lifetime of the environment
    bool isTesting;                          ///< True if the environment is in testing mode

    // Metadata
    std::uint64_t m_created;                  ///< Timestamp of the creation of the environment
    std::string m_name;                       ///< Name of the environment
    std::optional<std::string> m_description; ///< Description of the environment

public:
    // Getters
    // Setters

    // Dump and load
    json::Json toJson() const;
    base::OptError fromJson(const json::Json& json);
};

class IRouterAPI
{
public:

// An environment is a session
base::OptError postEnvironment(const Entry& environment) = 0;

base::OptError patchEnvironment(const Entry& environment) = 0;

base::OptError deleteEnvironment(const std::string& id) = 0;

base::RespOrError<Entry> getEnvironment(const std::string& id) const = 0;

// Table entries
base::RespOrError<std::list<Entry>> getEntries() const = 0;


};

} // namespace router

#endif // _ROUTER2_IROUTER_HPP
