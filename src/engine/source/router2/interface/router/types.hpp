#ifndef _ROUTER2_TYPES_HPP
#define _ROUTER2_TYPES_HPP

#include <functional>
#include <list>
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

inline std::string stateToString(const env::State state)
{
    switch (state)
    {
        case env::State::UNKNOWN: return "UNKNOWN";
        case env::State::INACTIVE: return "INACTIVE";
        case env::State::ACTIVE: return "ACTIVE";
        default: return "INVALID_STATE";
    }
}

// Function to convert Sync enum to string  // TODO move/delete this
inline std::string syncToString(const env::Sync sync)
{
    switch (sync)
    {
        case env::Sync::UNKNOWN: return "UNKNOWN";
        case env::Sync::UPDATED: return "UPDATED";
        case env::Sync::OUTDATED: return "OUTDATED";
        case env::Sync::DELETED: return "DELETED";
        case env::Sync::ERROR: return "ERROR";
        default: return "INVALID_SYNC";
    }
}

} // namespace env

namespace test
{

enum class TraceLevel : std::uint8_t
{
    NONE = 0,
    ASSET_ONLY,
    ALL
};

class TraceStorage
{
public:
    using TraceList = std::vector<std::string>;
    struct AssetData
    {
        TraceList traces;
        bool success = false; ///< False if the asset has failed
    };

    using DataPair = std::pair<std::string, AssetData>;
    using DataList = std::list<DataPair>;

private:
    DataList m_dataList;
    std::unordered_map<std::string, DataList::iterator> m_dataMap;

public:
    TraceStorage()
        : m_dataList()
        , m_dataMap()
    {
    }

    void ingest(const std::string& asset, const std::string& traceContent, bool result)
    {
        if (traceContent.empty())
        {
            return;
        }

        // Try inserting the asset into the map.
        auto [it, inserted] = m_dataMap.try_emplace(asset, m_dataList.end());

        // If is new, insert it into the list.
        if (inserted)
        {
            m_dataList.emplace_back(asset, AssetData {});
            it->second = std::prev(m_dataList.end());
        }

        auto& data = it->second->second;

        if (traceContent == "SUCCESS")
        {
            data.success = true;
        }
        else
        {
            data.traces.push_back(traceContent);
        }
    }

    void clearData()
    {
        m_dataList.clear();
        m_dataMap.clear();
    }

    const DataList& getDataList() const { return m_dataList; }
};

struct Output
{
    base::Event m_event;
    TraceStorage m_tracingObj;
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

    OutputFn getOutputFn () const
    {
        return m_callback;
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

/**
 * @brief Defines the Limits enum class to validate priority based on whether it is for testing or production.
 */
enum class Limits : std::size_t
{
    MaxTest = 0,            // 0 is the highest priority
    MinTest = 50,           // 50 sessions at most for testing
    MaxProd = MinTest + 1,  // 51 is the lowest priority
    MinProd = MaxProd + 100 // 151 sessions at most for production
};

/**
 * @brief Validates the priority based on whether it is for testing or production.
 *
 * @param priority The priority to be validated.
 * @param isTesting A boolean indicating whether the priority is for testing or not.
 * @return true if the priority is valid, false otherwise.
 */
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

/**
 * @brief The EntryPost class is used to create an environment.
 *
 */
class EntryPost
{
protected:
    // Environment build parameters
    base::Name m_policy;                ///< Policy of the environment
    std::optional<base::Name> m_filter; ///< Filter of the environment (Empty if it's a dynamic filter)

    // Router parameters
    std::size_t m_priority = 0;   ///< Priority of the environment (0 is the lowest priority available)
    std::uint64_t m_lifetime = 0; ///< Lifetime of the environment (in seconds from the last use)

    // Metadata
    std::string m_name;                       ///< Name of the environment
    std::optional<std::string> m_description; ///< Description of the environment

    // Test
    bool _isTesting() const { return !m_filter.has_value(); }

    /**
     * @brief Validates the environment parameters.
     *
     * @return base::OptError An optional error if the environment parameters are invalid.
     */
    base::OptError validate() const
    {
        if (m_policy.parts().size() == 0 || m_policy.parts()[0] != "policy")
        {
            return base::Error {"Policy name is empty or it is not a policy"};
        }
        else if (!_isTesting() && (m_filter.value().parts().size() == 0 || m_filter.value().parts()[0] != "filter"))
        {
            return base::Error {"Filter name is empty or it is not a filter"};
        }
        else if (m_name.empty())
        {
            return base::Error {"Name cannot be empty"};
        }
        else if (Priority::validate(m_priority, _isTesting()))
        {
            return base::Error {fmt::format("Invalid priority: {}, its out of range [{} - {}]",
                                            m_priority,
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
        , m_priority {priority}
    {
        validate();
    }

public:
    EntryPost() = delete;

    /**
     * @brief Create a Entry Post for production environments.
     *
     * @param name Name to identify the environment
     * @param policy Policy to use in the environment
     * @param filter Filter to use in the environment
     * @param priority Priority of the environment
     * @return EntryPost The created EntryPost
     */
    static EntryPost
    createEntryPost(const std::string& name, const base::Name& policy, const base::Name& filter, std::size_t priority)
    {
        return EntryPost {name, policy, filter, priority};
    }

    /**
     * @brief Create a Entry Post for testing environments.
     *
     * @param name Name to identify the environment
     * @param policy Policy to use in the environment
     * @param lifetime Lifetime of the environment // TODO: Check description
     * @return EntryPost The created EntryPost
     */
    static EntryPost createEntryTestPost(const std::string& name, const base::Name& policy, std::size_t lifetime)
    {
        return EntryPost {name, policy, lifetime};
    }

    /**
     * @brief Check if the environment is for testing.
     * @return true if the environment is for testing, false otherwise.
     */
    bool isTesting() const { return _isTesting(); }

    // Setters
    void setDescription(std::string_view description) { m_description = description; }

    // Getters
    const std::string& name() const { return m_name; }
    const base::Name& policy() const { return m_policy; }
    std::size_t priority() const { return m_priority; }
    std::uint64_t lifetime() const { return m_lifetime; }
    const std::optional<base::Name>& filter() const { return m_filter; }
    const std::optional<std::string>& description() const { return m_description; }
};

// TODO: class EntryPut : public EntryPost

class Entry : public EntryPost
{
protected:
    // Entry
    std::uint64_t m_created;
    // std::uint64_t m_id;

    // Runtime configuration
    env::Sync m_policySync; ///< Policy sync status
    env::State m_status;    ///< Status of the environment

    // Status
    std::optional<std::uint64_t> m_lastUsed; ///< Timestamp of the last use of the environment (only for testing env)

public:
    Entry(const EntryPost& entryPost)
        : EntryPost {entryPost}
        , m_created {0}
        , m_policySync {env::Sync::UNKNOWN}
        , m_status {env::State::UNKNOWN} {};

    // Setters
    void setCreated(std::uint64_t created) { m_created = created; }
    void setPolicySync(env::Sync policySync) { m_policySync = policySync; }
    void setStatus(env::State status) { m_status = status; }
    void setLastUsed(std::uint64_t lastUsed) { m_lastUsed = lastUsed; }
    void setPriority(std::size_t priority) { m_priority = priority; }

    // Getters
    std::uint64_t getCreated() const { return m_created; }
    env::Sync getPolicySync() const { return m_policySync; }
    env::State getStatus() const { return m_status; }
    const std::optional<std::uint64_t>& getLastUsed() const { return m_lastUsed; }
};

} // namespace router

#endif // _ROUTER2_TYPES_HPP
