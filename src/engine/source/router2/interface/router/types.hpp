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
enum class State : std::uint8_t
{
    UNKNOWN,  ///< Unset state
    DISABLED, ///< Environment is inactive, it's not being used or error
    ENABLED,  ///< Environment is active, it's being used
};

enum class Sync : std::uint8_t
{
    UNKNOWN,  ///< Unset sync status
    UPDATED,  ///< Policy is updated
    OUTDATED, ///< Policy is outdated respect to the store
    DELETED,  ///< Policy is deleted not exist in the store
    ERROR     ///< Error, can't get the policy status
};

} // namespace env


// Production namespace
namespace prod
{
/**
 * @brief Request for adding a new entry in production
 */
class EntryPost
{
private:
    std::string m_name;                       ///< Name of the environment
    base::Name m_policy;                      ///< Policy of the environment
    base::Name m_filter;                      ///< Filter of the environment
    std::size_t m_priority;                   ///< Priority of the environment
    std::optional<std::string> m_description; ///< Description of the environment


public:
    EntryPost() = delete;

    EntryPost(std::string name, base::Name policy, base::Name filter, std::size_t priority)
        : m_name {std::move(name)}
        , m_policy {std::move(policy)}
        , m_description {}
        , m_filter {std::move(filter)}
        , m_priority {priority}
    {
    }

    base::OptError validate() const
    {
        if (m_name.empty())
        {
            return base::Error {"Name cannot be empty"};
        }
        if (m_policy.parts().size() == 0)
        {
            return base::Error {"Policy name is empty"};
        }
        if (m_filter.parts().size() == 0)
        {
            return base::Error {"Filter name is empty"};
        }
        if (m_priority == 0)
        {
            return base::Error {"Priority cannot be 0"};
        }
        return base::OptError {};
    }

    // Setters and getters
    const std::string& name() const { return m_name; }
    const base::Name& policy() const { return m_policy; }

    const std::optional<std::string>& description() const { return m_description; }
    void description(std::string_view description) { m_description = description; }

    const base::Name& filter() const { return m_filter; }
    void filter(base::Name filter) { m_filter = filter; }

    std::size_t priority() const { return m_priority; }
    void priority(std::size_t priority) { m_priority = priority; }
};

/**
 * @brief Response for get an entry in production
 */
class Entry : public EntryPost
{
private:
    env::Sync m_policySync;     ///< Policy sync status
    env::State m_status;        ///< Status of the environment
    std::uint64_t m_lastUpdate; /// Last update of the environment

public:
    Entry(const EntryPost& entryPost)
        : EntryPost {entryPost}
        , m_lastUpdate {0}
        , m_policySync {env::Sync::UNKNOWN}
        , m_status {env::State::UNKNOWN} {};

    // Setters and getters
    std::uint64_t lastUpdate() const { return m_lastUpdate; }
    void lastUpdate(std::uint64_t lastUpdate) { m_lastUpdate = lastUpdate; }

    env::Sync policySync() const { return m_policySync; }
    void policySync(env::Sync policySync) { m_policySync = policySync; }

    env::State status() const { return m_status; }
    void status(env::State status) { m_status = status; }
};

}

namespace test
{

enum class TraceLevel : std::uint8_t
{
    NONE = 0,
    ASSET_ONLY,
    ALL
};

// TODO Move to router private space and expose only dataList
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

    void addTrace(const std::string& asset, const std::string& traceContent, bool result)
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
    std::vector<std::string> m_assets;
    std::string m_environmetName;

    // Missing namespace and asset list
public:
    Opt(OutputFn callback, TraceLevel traceLevel, const decltype(m_assets)& assets, const std::string& envName)
        : m_callback {callback}
        , m_traceLevel {traceLevel}
        , m_assets {assets}
        , m_environmetName {envName}
    {
        // validate();
    }

    const std::string& environmentName() const { return m_environmetName; }
    auto assets() const -> const decltype(m_assets)& { return m_assets; }
};

} // namespace test

} // namespace router

#endif // _ROUTER2_TYPES_HPP
