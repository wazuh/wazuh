#ifndef _ROUTER2_TYPES_HPP
#define _ROUTER2_TYPES_HPP

#include <optional>
#include <string>
#include <functional>

#include <baseTypes.hpp>
#include <error.hpp>
#include <name.hpp>

namespace router
{

namespace env
{
using Id = std::string; // String or id number

enum class State
{
    INACTIVE, ///< Environment is inactive, it's not being used
    BUILDED,  ///< Environment is builded, it's ready to be used
    ACTIVE,   ///< Environment is active, it's being used
    ERROR     ///< Environment is in error state (not used), (If can't be builded or activated)
};

enum class Sync
{
    UPDATED,  ///< Policy is updated
    OUTDATED, ///< Policy is outdated respect to the store
    DELETED,  ///< Policy is deleted not exist in the store
    ERROR     ///< Error, can't get the policy status
};

} // namespace env

namespace test
{

//
enum class TraceLevel : std::uint8_t
{
    NONE = 0,
    ASSET_ONLY,
    ALL
};

struct Output
{
    base::Event m_event;
    std::string m_tracingObj;
};

using OutputFn = std::function<void(Output&&)>;


class Opt
{
private:
    OutputFn m_callback;
    TraceLevel m_traceLevel;
    env::Id m_envId;

// Missing namespace and asset list
public:
    Opt(OutputFn callback, TraceLevel traceLevel, env::Id envId)
        : m_callback {std::move(callback)}
        , m_traceLevel {traceLevel}
        , m_envId {std::move(envId)}
    {
        // validate();
    }

};

} // namespace test

struct EntryPost
{

    // Environment build parameters
    base::Name m_policy;                ///< Policy of the environment
    std::optional<base::Name> m_filter; ///< Filter of the environment (Empty if it's a dynamic filter based on id)
    bool m_isTesting = true;            ///< True if the environment is in testing mode

    // Router parameters
    std::size_t m_prior = 0;                 ///< Priority of the environment (0 is the highest priority aviailable)
    std::optional<std::uint64_t> m_lifetime; ///< Lifetime of the environment (in seconds from the last use)

    // Metadata
    std::string m_name;                       ///< Name of the environment
    std::optional<std::string> m_description; ///< Description of the environment

    base::OptError validate() const
    {
        if (m_policy.parts().size() == 0)
        {
            return base::Error {"Policy cannot be empty"};
        }
        if (m_name.empty())
        {
            return base::Error {"Name cannot be empty"};
        }
    }
};

// class EntryPut : public EntryPost

struct Entry : public EntryPost
{
    // Entry
    std::size_t m_id; ///< Unique id of the environment
    std::uint64_t m_created;

    // Policy
    env::Sync m_policySync; ///< Policy sync status
    env::State m_status;    ///< Status of the environment

    // Status
    std::optional<std::uint64_t> m_lastUsed; ///< Timestamp of the last use of the environment
    base::OptError m_error;                  ///< Error of the environment (if any)
};

} // namespace router

#endif // _ROUTER2_TYPES_HPP
