#ifndef _ROUTER_TYPES_HPP
#define _ROUTER_TYPES_HPP

#include <functional>
#include <list>
#include <optional>
#include <string>
#include <tuple>
#include <unordered_set>

#include <base/logging.hpp>

#include <base/baseTypes.hpp>
#include <base/error.hpp>
#include <base/name.hpp>
#include <cmstore/types.hpp>

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
    UPDATED,  ///< Namespace is updated
    OUTDATED, ///< Namespace is outdated respect to the store
    ERROR     ///< Error, can't get the namespace status
};
} // namespace env

/**************************************************************************
 *                      Production types (router)                         *
 *************************************************************************/
namespace prod
{
/**
 * @brief Request for adding a new entry in production
 */
class EntryPost
{
private:
    std::string m_name;                       ///< Name of the environment
    cm::store::NamespaceId m_namespace;          ///< Namespace of the environment
    base::Name m_filter;                      ///< Filter of the environment
    std::size_t m_priority;                   ///< Priority of the environment
    std::optional<std::string> m_description; ///< Description of the environment

    static constexpr std::size_t MAX_PRIORITY = 1000; ///< Max priority of the environment

public:
    EntryPost() = delete;

    /**
     * @brief New entry in production
     *
     * @param name Name of environment
     * @param namespace Namespace of the environment
     * @param filter Filter of the environment
     * @param priority Priority of the environment
     */
    EntryPost(std::string name, cm::store::NamespaceId namespaceId, base::Name filter, std::size_t priority)
        : m_name {std::move(name)}
        , m_namespace {std::move(namespaceId)}
        , m_description {}
        , m_filter {std::move(filter)}
        , m_priority {priority}
    {
    }

    /**
     * @brief Validate the entry
     *
     * @return base::OptError Error if the entry is not valid
     */
    base::OptError validate() const
    {
        if (m_name.empty())
        {
            return base::Error {"Name cannot be empty"};
        }
        if (m_filter.parts().size() == 0)
        {
            return base::Error {"Filter name is empty"};
        }
        if (m_priority == 0)
        {
            return base::Error {"Priority cannot be 0"};
        }
        if (m_priority > MAX_PRIORITY)
        {
            return base::Error {"Priority cannot be greater than 1000"};
        }
        return base::OptError {};
    }

    // Setters and getters
    const std::string& name() const { return m_name; }
    const cm::store::NamespaceId& namespaceId() const { return m_namespace; }
    void namespaceId(cm::store::NamespaceId namespaceId) { m_namespace = std::move(namespaceId); }

    const std::optional<std::string>& description() const { return m_description; }
    void description(std::string_view description) { m_description = description; }

    const base::Name& filter() const { return m_filter; }
    void filter(base::Name filter) { m_filter = filter; }

    std::size_t priority() const { return m_priority; }
    void priority(std::size_t priority) { m_priority = priority; }

    static std::size_t maxPriority() { return MAX_PRIORITY; }
};

/**
 * @brief Response for get an entry in production
 */
class Entry : public EntryPost
{
private:
    env::Sync m_namespaceSync;     ///< Namespace sync status
    env::State m_status;        ///< Status of the environment
    std::uint64_t m_lastUpdate; /// Last update of the environment [TODO: Review this metadata]
    std::string m_hash;         /// Hash of the namespace

public:
    Entry(const EntryPost& entryPost)
        : EntryPost {entryPost}
        , m_lastUpdate {0}
        , m_namespaceSync {env::Sync::UNKNOWN}
        , m_status {env::State::UNKNOWN} {};

    // Setters and getters
    std::uint64_t lastUpdate() const { return m_lastUpdate; }
    void lastUpdate(std::uint64_t lastUpdate) { m_lastUpdate = lastUpdate; }

    env::Sync namespaceSync() const { return m_namespaceSync; }
    void namespaceSync(env::Sync namespaceSync) { m_namespaceSync = namespaceSync; }

    env::State status() const { return m_status; }
    void status(env::State status) { m_status = status; }

    const std::string& hash() const { return m_hash; }
    void hash(const std::string& hash) { m_hash = hash; }
};

} // namespace prod

/**************************************************************************
 *                      Testing types (tester)                            *
 *************************************************************************/
namespace test
{

/**
 * @brief Request for adding a new entry in production
 */
class EntryPost
{
private:
    std::string m_name;                       ///< Name of the environment
    cm::store::NamespaceId m_namespace;     ///< Namespace of the environment
    std::optional<std::string> m_description; ///< Description of the environment
    std::size_t m_lifetime;                   ///< Lifetime of the environment

public:
    EntryPost() = delete;

    /**
     * @brief New entry in production
     *
     * @param name Name of environment
     * @param namespace Namespace of the environment
     * @param lifetime Lifetime of the testing environment
     */
    EntryPost(std::string name, cm::store::NamespaceId namespaceId, std::size_t lifetime)
        : m_name {std::move(name)}
        , m_namespace {std::move(namespaceId)}
        , m_description {}
        , m_lifetime {lifetime}
    {
    }

    /**
     * @brief Validate the entry
     *
     * @return base::OptError Error if the entry is not valid
     */
    base::OptError validate() const
    {
        if (m_name.empty())
        {
            return base::Error {"Name cannot be empty"};
        }
        return base::OptError {};
    }

    // Setters and getters
    const std::string& name() const { return m_name; }
    void name(std::string name) { m_name = std::move(name); }
    const cm::store::NamespaceId& namespaceId() const { return m_namespace; }

    const std::optional<std::string>& description() const { return m_description; }
    void description(std::string_view description) { m_description = description; }

    std::size_t lifetime() const { return m_lifetime; }
    void lifetime(std::size_t lifetime) { m_lifetime = lifetime; }
};

/**
 * @brief Response for get an entry in production
 */
class Entry : public EntryPost
{
private:
    env::Sync m_namespaceSync;  ///< Namespace sync status
    env::State m_status;     ///< Status of the environment
    std::uint64_t m_lastUse; /// Last use of the entry.
    std::string m_hash;      /// Hash of the namespace

public:
    Entry(const EntryPost& entryPost)
        : EntryPost {entryPost}
        , m_lastUse {0}
        , m_namespaceSync {env::Sync::UNKNOWN}
        , m_status {env::State::UNKNOWN} {};

    // Setters and getters
    std::uint64_t lastUse() const { return m_lastUse; }
    void lastUse(std::uint64_t lastUse) { m_lastUse = lastUse; }

    env::Sync namespaceSync() const { return m_namespaceSync; }
    void namespaceSync(env::Sync namespaceSync) { m_namespaceSync = namespaceSync; }

    env::State status() const { return m_status; }
    void status(env::State status) { m_status = status; }

    const std::string& hash() const { return m_hash; }
    void hash(const std::string& hash) { m_hash = hash; }
};

/**
 * @brief Options for request a testing event
 */
class Options
{
public:
    /**
     * @brief Tracin level for testing
     */
    enum class TraceLevel : std::uint8_t
    {
        NONE = 0,
        ASSET_ONLY,
        ALL,
        UNKNOWN
    };

    static std::string_view traceLevelToString(TraceLevel tl) noexcept
    {
        switch (tl)
        {
            case TraceLevel::NONE:       return "NONE";
            case TraceLevel::ASSET_ONLY: return "ASSET_ONLY";
            case TraceLevel::ALL:        return "ALL";
            default:                     return "UNKNOWN";
        }
    }

    static TraceLevel stringToTraceLevel(const std::string& str) noexcept
    {
        std::string normalized;
        normalized.reserve(str.size());

        std::transform(
            str.begin(), str.end(),
            std::back_inserter(normalized),
            [](unsigned char c) { return std::toupper(c); }
        );

        if (normalized == traceLevelToString(TraceLevel::NONE))       return TraceLevel::NONE;
        if (normalized == traceLevelToString(TraceLevel::ASSET_ONLY)) return TraceLevel::ASSET_ONLY;
        if (normalized == traceLevelToString(TraceLevel::ALL))        return TraceLevel::ALL;

        return TraceLevel::UNKNOWN;
    }

private:
    TraceLevel m_traceLevel;                  ///< Tracing level for testing
    std::unordered_set<std::string> m_assets; ///< List of assets to trace (if any)
    std::string m_environmetName;             ///< Name of the environment to test

public:
    /**
     * @brief Create a new options for testing
     *
     * @param traceLevel Tracing level for testing
     * @param assets List of assets to trace (if any)
     * @param envName  Name of the environment to test
     */
    Options(TraceLevel traceLevel, const decltype(m_assets)& assets, const std::string& envName)
        : m_traceLevel {traceLevel}
        , m_assets {assets}
        , m_environmetName {envName}
    {
    }

    /**
     * @brief Validate the options
     *
     * @return base::OptError Error if the options are not valid
     */
    base::OptError validate() const
    {
        if (m_environmetName.empty())
        {
            return base::Error {"Environment name cannot be empty"};
        }

        if (traceLevel() == TraceLevel::NONE && assets().size() > 0)
        {
            return base::Error {"Assets cannot be set if trace level is NONE"};
        }
        return base::OptError {};
    }

    // Setters and getters
    const std::string& environmentName() const { return m_environmetName; }
    auto assets() const -> const decltype(m_assets)& { return m_assets; }
    TraceLevel traceLevel() const { return m_traceLevel; }
};

/**
 * @brief Represent a output of a testing event
 */
class Output
{
public:
    struct AssetTrace ///< Represent a trace of an asset
    {
        bool success = false;            ///< True if the asset has success
        std::vector<std::string> traces; ///< List of traces of the asset (if any)
    };
    using DataPair = std::pair<std::string, AssetTrace>; ///< Pair of asset name and tracing data

protected:
    base::Event m_event;          ///< Result event of the testing
    std::list<DataPair> m_traces; ///< List of traces of the testing

public:
    /**
     * @brief Create empty output
     */
    Output()
        : m_event {}
        , m_traces {}
    {
    }

    // Setters and getters
    base::Event& event() { return m_event; }
    const base::Event& event() const { return m_event; }

    std::list<DataPair>& traceList() { return m_traces; }
    const std::list<DataPair>& traceList() const { return m_traces; }

    bool isValid() const
    {
        if (m_event == nullptr)
        {
            return false;
        }
        return true;
    }
};

// Specialization of the external Queue for testing
using TestingTuple = std::tuple<base::Event, Options, std::function<void(base::RespOrError<Output>&&)>>;
using QueueType = std::shared_ptr<TestingTuple>;

} // namespace test

} // namespace router

#endif // _ROUTER_TYPES_HPP
