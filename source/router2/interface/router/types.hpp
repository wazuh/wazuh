#ifndef _ROUTER2_TYPES_HPP
#define _ROUTER2_TYPES_HPP

#include <functional>
#include <optional>
#include <string>

#include <baseTypes.hpp>
#include <error.hpp>
#include <logging/logging.hpp>
#include <name.hpp>

namespace router
{

namespace env
{
enum class State
{
    UNKNOWN,  ///< Unset state
    INACTIVE, ///< Environment is inactive, it's not being used or error
    ACTIVE,   ///< Environment is active, it's being used
};

enum class Sync
{
    UNKNOWN,  ///< Unset sync status
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
    std::string m_envId;

    // Missing namespace and asset list
public:
    Opt(OutputFn callback, TraceLevel traceLevel, const std::string& envId)
        : m_callback {std::move(callback)}
        , m_traceLevel {traceLevel}
        , m_envId {std::move(envId)}
    {
        // validate();
    }
};

} // namespace test

/**
 * @brief The priority of an environment, 0 is the biggest priority.
 * The test environments have priority over the production ones.
 *
 */
namespace Priority
{
enum class Limits : std::size_t
{
    MaxTest = 0,            // 0 is the highest priority
    MinTest = 50,           // 50 sessions at most for testing
    MaxProd = MinTest + 1,  // 51 is the lowest priority
    MinProd = MaxProd + 100 // 151 sessions at most for production
};

inline bool validate(std::size_t priority, bool isTesting)
{
    if (isTesting)
    {
        return priority <= static_cast<std::size_t>(Limits::MinTest);
    }
    else
    {
        return priority >= static_cast<std::size_t>(Limits::MaxProd)
               && priority <= static_cast<std::size_t>(Limits::MinProd);
    }
}
} // namespace Priority

class EntryPost
{
protected:
    // Environment build parameters
    base::Name m_policy; ///< Policy of the environment
    std::optional<base::Name>
        m_filter; ///< Filter of the environment (Empty if it's a dynamic filter based on id [testing mode])

    // Router parameters
    std::size_t m_prior = 0;      ///< Priority of the environment (0 is the lowest priority available)
    std::uint64_t m_lifetime = 0; ///< Lifetime of the environment (in seconds from the last use)

    // Metadata
    std::string m_name;                       ///< Name of the environment
    std::optional<std::string> m_description; ///< Description of the environment

    bool _isTesting() const { return !m_filter.has_value(); }

    base::OptError validate() const
    {
        if (m_policy.parts().size() == 0)
        {
            return base::Error {"Policy cannot be empty"};
        }
        else if (!_isTesting() && m_filter.value().parts().size() == 0)
        {
            return base::Error {"Filter cannot be empty"};
        }
        else if (m_name.empty())
        {
            return base::Error {"Name cannot be empty"};
        }
        else if (Priority::validate(m_prior, _isTesting()))
        {
            return base::Error {fmt::format("Invalid priority: {}, its out of range [{} - {}]",
                                            m_prior,
                                            _isTesting() ? static_cast<std::size_t>(Priority::Limits::MaxTest)
                                                         : static_cast<std::size_t>(Priority::Limits::MaxProd),
                                            _isTesting() ? static_cast<std::size_t>(Priority::Limits::MinTest)
                                                         : static_cast<std::size_t>(Priority::Limits::MinProd))};
        }

        return base::OptError {};
    }

    EntryPost(const std::string& name, const base::Name& policy, std::size_t lifetime)
        : m_name {name}
        , m_policy {policy}
        , m_lifetime {lifetime}
    {
        validate();
    }

    EntryPost(std::string_view name, const base::Name& policy, const base::Name& filter, std::size_t priority)
        : m_name {name}
        , m_policy {policy}
        , m_filter {filter}
        , m_prior {priority}
    {
        validate();
    }

public:
    static EntryPost
    createEntryPost(const std::string& name, const base::Name& policy, const base::Name& filter, std::size_t priority)
    {
        return EntryPost {name, policy, filter, priority};
    }

    static EntryPost createEntryTestPost(const std::string& name, const base::Name& policy, std::size_t lifetime)
    {
        return EntryPost {name, policy, lifetime};
    }

    bool isTesting() const { return _isTesting(); }

    // Setters
    void setDescription(std::string_view description) { m_description = description; }

    // Getters
    const std::string& name() const { return m_name; }
    const base::Name& policy() const { return m_policy; }
    std::size_t priority() const { return m_prior; }
    std::uint64_t lifetime() const { return m_lifetime; }
    const std::optional<base::Name>& filter() const { return m_filter; }
    const std::optional<std::string>& description() const { return m_description; }
};

// class EntryPut : public EntryPost

class Entry : public EntryPost
{
protected:
    // Entry
    std::uint64_t m_created;

    // Policy
    env::Sync m_policySync; ///< Policy sync status
    env::State m_status;    ///< Status of the environment

    // Status
    std::optional<std::uint64_t> m_lastUsed; ///< Timestamp of the last use of the environment
public:
    Entry(const EntryPost& entryPost)
        : EntryPost {entryPost}
        , m_created {0}
        , m_policySync {env::Sync::UNKNOWN}
        , m_status {env::State::UNKNOWN} {};
};

} // namespace router

#endif // _ROUTER2_TYPES_HPP
