#include <algorithm>
#include <ctime>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <fmt/format.h>

#include <base/error.hpp>
#include <base/json.hpp>
#include <base/logging.hpp>
#include <base/utils/metaHelpers.hpp>
#include <base/utils/vectorHelpers.hpp>
#include <cmcontent/contentTopic.hpp>
#include <contentOnDemand.hpp>

#include <cmsync/cmsync.hpp>

namespace
{

const base::Name STORE_NAME_CMSYNC {"cmsync/status/0"};          ///< Name of the internal store document
const cm::store::NamespaceId DUMMY_NAMESPACE_ID {"dummy_ns_id"}; ///< Dummy namespace ID
constexpr std::string_view STANDARD_SPACE_NAME = "standard";     ///< Standard space name
constexpr std::string_view CUSTOM_SPACE_NAME = "custom";         ///< Custom space name
const std::string COMPONENT_NAME = "CMSync";                     ///< Component name for logging

constexpr std::string_view LOG_MODULE_NAME = "CM::Sync"; ///< Log module name for CMSync

} // namespace

namespace cm::sync
{

/**
 * @brief Represents a namespace being synchronized from the indexer
 */
class SyncedNamespace
{
private:
    std::string m_originSpace;                               ///< Origin space in the indexer
    std::string m_routeName;                                 ///< Route name in the router
    cm::store::NamespaceId m_nsId;                           ///< Destination namespace ID in the local store
    std::optional<std::string> m_consumerId;                 ///< Optional CTI consumer doc ID to validate during sync
    uint32_t m_lastSuccessfulUpdate {0};                     ///< Unix timestamp of last successful sync
    base::SyncStatus m_syncStatus {base::SyncStatus::READY}; ///< Per-space sync status

    // Cached router-derived state for status reporting. Updated during synchronize() so the status
    // snapshot can be built WITHOUT touching the router. Transient (not persisted): after restart
    // these stay default until the next sync.
    bool m_available {false}; ///< Whether a route currently exists for this space
    bool m_enabled {false};   ///< Whether the space is enabled in the remote policy
    std::string m_hash;       ///< Hash of the deployed route/policy

    static constexpr std::string_view JPATH_ORIGIN = "/origin_space";       ///< JSON path for origin space
    static constexpr std::string_view JPATH_NAMESPACE_ID = "/namespace_id"; ///< JSON path for namespace ID
    static constexpr std::string_view JPATH_CONSUMER_ID = "/consumer_id";   ///< JSON path for consumer ID
    static constexpr std::string_view JPATH_LAST_SUCCESSFUL_UPDATE =
        "/last_successful_update";                                ///< JSON path for last successful update
    static constexpr std::string_view JPATH_ENABLED = "/enabled"; ///< JSON path for the remote-policy enabled flag

    /**
     * @brief Generate a route name for the given origin space
     *
     * @param originSpace Origin space name
     * @return std::string Generated route name
     */
    static std::string generateRouteName(std::string_view originSpace) { return fmt::format("cmsync_{}", originSpace); }

public:
    SyncedNamespace() = delete;

    /**
     * @brief Construct a new dummy SyncedNamespace
     *
     * Used when adding a new space to sync before the first synchronization.
     *
     * @param originSpace Origin space name
     * @param consumerId Optional consumer document ID for CTI validation
     */
    explicit SyncedNamespace(std::string_view originSpace, std::optional<std::string> consumerId = std::nullopt)
        : m_originSpace(originSpace)
        , m_routeName(generateRouteName(originSpace))
        , m_nsId(DUMMY_NAMESPACE_ID)
        , m_consumerId(std::move(consumerId))
    {
    }

    /**
     * @brief Construct a new SyncedNamespace with all fields
     *
     * @param originSpace Origin space name
     * @param nsId Destination namespace ID in the local store
     * @param consumerId Optional consumer document ID for CTI validation
     */
    SyncedNamespace(std::string_view originSpace,
                    cm::store::NamespaceId nsId,
                    std::optional<std::string> consumerId = std::nullopt)
        : m_originSpace(originSpace)
        , m_routeName(generateRouteName(originSpace))
        , m_nsId(std::move(nsId))
        , m_consumerId(std::move(consumerId))
    {
    }

    /* Getters and Setters */
    const std::string& getOriginSpace() const { return m_originSpace; }
    const cm::store::NamespaceId& getNamespaceId() const { return m_nsId; }
    const std::string& getRouteName() const { return m_routeName; }
    const std::optional<std::string>& getConsumerId() const { return m_consumerId; }
    void setNamespaceId(const cm::store::NamespaceId& nsId) { m_nsId = nsId; }
    void setConsumerId(const std::optional<std::string>& consumerId) { m_consumerId = consumerId; }
    uint32_t getLastSuccessfulUpdate() const { return m_lastSuccessfulUpdate; }
    void setLastSuccessfulUpdate(uint32_t ts) { m_lastSuccessfulUpdate = ts; }
    base::SyncStatus getSyncStatus() const { return m_syncStatus; }
    void setSyncStatus(base::SyncStatus s) { m_syncStatus = s; }

    bool getAvailable() const { return m_available; }
    bool getEnabled() const { return m_enabled; }
    const std::string& getHash() const { return m_hash; }
    /// Cache the router-derived state reported by the status endpoint.
    void setRouteState(bool available, bool enabled, std::string hash)
    {
        m_available = available;
        m_enabled = enabled;
        m_hash = std::move(hash);
    }

    /// @return Whether this space has ever produced a namespace.
    bool hasNamespace() const { return m_nsId != DUMMY_NAMESPACE_ID; }

    /**
     * @brief Serialize the SyncedNamespace to a JSON object
     *
     * @return json::Json JSON representation of the SyncedNamespace
     */
    json::Json toJson() const
    {
        json::Json j {};
        j.setString(m_originSpace, JPATH_ORIGIN);
        j.setString(m_nsId.toStr(), JPATH_NAMESPACE_ID);
        if (m_consumerId.has_value())
        {
            j.setString(*m_consumerId, JPATH_CONSUMER_ID);
        }
        j.setInt64(static_cast<int64_t>(m_lastSuccessfulUpdate), JPATH_LAST_SUCCESSFUL_UPDATE);
        // Persist only the remote-policy enabled flag. 'available'/'hash' are live state re-derived
        // from the router on the next sync, so they are intentionally NOT persisted.
        j.setBool(m_enabled, JPATH_ENABLED);
        return j;
    }

    /**
     * @brief Deserialize a SyncedNamespace from a JSON object
     *
     * @param j JSON object to deserialize
     * @return SyncedNamespace Deserialized SyncedNamespace
     * @throw std::runtime_error if required fields are missing or invalid
     */
    static SyncedNamespace fromJson(const json::Json& j)
    {
        std::string origin;
        if (j.getString(origin, JPATH_ORIGIN) != json::RetGet::Success || origin.empty())
        {
            throw std::runtime_error("NsSyncState::fromJson: Missing/empty origin_space field");
        }

        std::string nsId;
        if (j.getString(nsId, JPATH_NAMESPACE_ID) != json::RetGet::Success)
        {
            throw std::runtime_error("NsSyncState::fromJson: Missing namespace_id field");
        }

        std::optional<std::string> consumerId = std::nullopt;
        std::string consumerIdStr;
        if (j.getString(consumerIdStr, JPATH_CONSUMER_ID) == json::RetGet::Success && !consumerIdStr.empty())
        {
            consumerId = std::move(consumerIdStr);
        }

        SyncedNamespace ns {origin, cm::store::NamespaceId(nsId), std::move(consumerId)};
        // Restore the last successful update timestamp if present (absent in older state documents).
        if (const auto ts = j.getInt64(JPATH_LAST_SUCCESSFUL_UPDATE); ts.has_value())
        {
            ns.setLastSuccessfulUpdate(static_cast<uint32_t>(*ts));
        }
        // Restore the last known enabled flag (available/hash stay default; re-derived on next sync).
        if (const auto enabled = j.getBool(JPATH_ENABLED); enabled.has_value())
        {
            ns.setRouteState(false, *enabled, "");
        }
        return ns;
    }
};

CMSync::CMSync(const std::shared_ptr<wiconnector::IWIndexerConnector>& indexerPtr,
               const std::shared_ptr<cm::crud::ICrudService>& cmcrudPt,
               const std::shared_ptr<::store::IStore>& storePtr,
               const std::shared_ptr<router::IRouterAPI>& routerPtr,
               nlohmann::json indexerConnection,
               const size_t attempts,
               const size_t waitSeconds,
               cmcontent::Options contentOptions,
               cmcontent::TopicFactory topicFactory)
    : m_indexerPtr(indexerPtr)
    , m_cmcrudPtr(cmcrudPt)
    , m_store(storePtr)
    , m_router(routerPtr)
    , m_attempts(attempts)
    , m_waitSeconds(waitSeconds)
    , m_indexerConnection(std::move(indexerConnection))
    , m_contentOptions(std::move(contentOptions))
    , m_topicFactory(topicFactory ? std::move(topicFactory) : cmcontent::defaultTopicFactory())
    , m_mutex()
{
    // Check if is the first setup
    if (storePtr->existsDoc(STORE_NAME_CMSYNC))
    {
        loadStateFromStore();

        {
            std::unique_lock lock(m_mutex);
            auto routerApi = base::utils::lockWeakPtr(m_router, "RouterAPI");

            collectOrphanNamespaces();

            for (auto& nsState : m_namespacesState)
            {
                registerTopic(nsState);

                if (!routerApi->existsEntry(nsState.getRouteName()))
                {
                    nsState.setRouteState(false, nsState.getEnabled(), "");
                    continue;
                }

                const auto resp = routerApi->getEntry(nsState.getRouteName());
                if (base::isError(resp))
                {
                    LOG_WARNING("[{}] Failed to read route '{}' while reconciling status on startup: {}",
                                LOG_MODULE_NAME,
                                nsState.getRouteName(),
                                base::getError(resp).message);
                    nsState.setRouteState(false, nsState.getEnabled(), "");
                    continue;
                }

                nsState.setRouteState(true, nsState.getEnabled(), base::getResponse(resp).hash());
            }
        }

        updateSpacesStatusSnapshot(); // Publish initial status
        return;
    }

    LOG_DEBUG("[{}] First setup detected, initializing default sync spaces", LOG_MODULE_NAME);

    // Populate directly and dump once to avoid multiple unnecessary store writes
    {
        std::unique_lock lock(m_mutex);
        m_namespacesState.emplace_back(STANDARD_SPACE_NAME,
                                       std::optional<std::string>(std::string(cmcontent::RULESET_CONSUMER_ID)));
        m_namespacesState.emplace_back(CUSTOM_SPACE_NAME);

        // No state document means nothing is legitimately deployed, so any namespace of ours still
        // in the store is left over from a previous install or an interrupted first sync.
        collectOrphanNamespaces();

        for (const auto& nsState : m_namespacesState)
        {
            registerTopic(nsState);
        }
        dumpStateToStore();
    }
    updateSpacesStatusSnapshot(); // Publish initial status
}

CMSync::~CMSync() = default;

void CMSync::registerTopic(const SyncedNamespace& nsState)
{
    const auto topicName = cmcontent::rulesetTopic(nsState.getOriginSpace());

    {
        std::lock_guard<std::mutex> containerLock(m_registrationsMutex);
        if (m_registrations.find(topicName) != m_registrations.end())
        {
            return;
        }
    }

    Registration registration;
    registration.sink = std::make_shared<cmcontent::RulesetSpaceSink>(
        m_cmcrudPtr, m_router, nsState.getOriginSpace(), nsState.getRouteName());

    // The router holds the deployed hash, so "storing" the token is what the hot-swap already did.
    // Saying so explicitly beats inventing a parallel field that could disagree with the router.
    //
    // The route name is bound in here rather than looked up per call: the loader runs on the content
    // cycle's thread, which for an on-demand update is a lane worker holding none of this object's
    // locks, so it must not read m_namespacesState.
    const auto routeName = nsState.getRouteName();
    auto tokenStore =
        cmcontent::derivedTokenStore([this, routeName]() { return loadTokenForRoute(routeName); });

    registration.topic =
        m_topicFactory(topicName,
                       cmcontent::rulesetParameters(m_indexerConnection, nsState.getOriginSpace(), m_contentOptions),
                       registration.sink,
                       std::move(tokenStore));

    std::lock_guard<std::mutex> containerLock(m_registrationsMutex);
    m_registrations.emplace(topicName, std::move(registration));
}

std::string CMSync::loadTokenForRoute(const std::string& routeName) const
{
    auto routerApi = m_router.lock();
    if (!routerApi)
    {
        return {};
    }

    if (!routerApi->existsEntry(routeName))
    {
        return {};
    }

    const auto resp = routerApi->getEntry(routeName);
    if (base::isError(resp))
    {
        return {};
    }

    const auto& entry = base::getResponse(resp);
    // A disabled route is not serving the content it was built from, so it must not count as
    // "already at this hash".
    if (entry.status() != ::router::env::State::ENABLED)
    {
        return {};
    }

    return entry.hash();
}

void CMSync::collectOrphanNamespaces()
{
    auto crud = m_cmcrudPtr.lock();
    auto routerApi = m_router.lock();
    if (!crud || !routerApi)
    {
        // Without the router there is no way to tell a dead namespace from a deployed one, and
        // guessing in that direction deletes a live ruleset. Reclaiming disk is never worth that.
        return;
    }

    try
    {
        // Everything this class ever creates is named cmsync_<space>_<suffix>, and for each tracked
        // space at most one of those is live. Anything else with that prefix is the residue of a
        // cycle that died between importing a namespace and routing it.
        //
        // "Live" comes from BOTH the persisted state and the router, and the second source is not
        // redundant: on a first setup the state says nothing is deployed, so trusting it alone would
        // delete the namespace a still-running route points at if the state document were ever lost.
        // The router knows what is actually being served.
        std::vector<std::string> live;
        std::vector<std::string> prefixes;
        live.reserve(m_namespacesState.size() * 2);
        prefixes.reserve(m_namespacesState.size());

        for (const auto& nsState : m_namespacesState)
        {
            if (nsState.hasNamespace())
            {
                live.push_back(nsState.getNamespaceId().toStr());
            }

            if (!routerApi->existsEntry(nsState.getRouteName()))
            {
                // Nothing is serving this space, so nothing of its is live.
                prefixes.push_back(fmt::format("cmsync_{}_", nsState.getOriginSpace()));
                continue;
            }

            const auto resp = routerApi->getEntry(nsState.getRouteName());
            if (base::isError(resp))
            {
                // A route exists but cannot be read: leave this space's namespaces entirely alone
                // rather than risk deleting the one it is serving.
                LOG_WARNING("[{}] Skipping orphan collection for space '{}': its route could not be read",
                            LOG_MODULE_NAME,
                            nsState.getOriginSpace());
                continue;
            }

            live.push_back(base::getResponse(resp).namespaceId().toStr());
            prefixes.push_back(fmt::format("cmsync_{}_", nsState.getOriginSpace()));
        }

        for (const auto& candidate : crud->listNamespaces())
        {
            const auto name = candidate.toStr();

            const bool ours = std::any_of(prefixes.begin(),
                                          prefixes.end(),
                                          [&name](const std::string& prefix)
                                          { return name.rfind(prefix, 0) == 0; });
            if (!ours)
            {
                continue;
            }

            if (std::find(live.begin(), live.end(), name) != live.end())
            {
                continue;
            }

            LOG_INFO("[{}] Removing the orphaned staging namespace '{}' left by an interrupted sync",
                     LOG_MODULE_NAME,
                     name);
            crud->deleteNamespace(candidate);
        }
    }
    catch (const std::exception& e)
    {
        // Reclaiming disk is not worth failing startup over; the next attempt will try again.
        LOG_WARNING("[{}] Could not collect orphaned staging namespaces: {}", LOG_MODULE_NAME, e.what());
    }
}

bool CMSync::existSpaceInRemote(std::string_view space)
{
    auto indexerPtr = base::utils::lockWeakPtr(m_indexerPtr, "IndexerConnector");

    return base::utils::executeWithRetry([&indexerPtr, space]() { return indexerPtr->existsPolicy(space); },
                                         COMPONENT_NAME,
                                         fmt::format("Check '{}' space in wazuh-indexer", space),
                                         m_attempts,
                                         m_waitSeconds,
                                         m_shutdownRequested);
}

void CMSync::addSpaceToSync(std::string_view space)
{
    std::unique_lock lock(m_mutex);

    // Check if the space is already in the sync list
    for (const auto& syncedNs : m_namespacesState)
    {
        if (syncedNs.getOriginSpace() == space)
        {
            throw std::runtime_error(fmt::format("Space '{}' is already in the sync list", space));
        }
    }

    // Add the new space to the sync list (constructor already sets DUMMY_NAMESPACE_ID)
    m_namespacesState.emplace_back(space);
    registerTopic(m_namespacesState.back());

    LOG_DEBUG("[{}] Added space '{}' to the sync list", LOG_MODULE_NAME, space);

    dumpStateToStore();
}

void CMSync::removeSpaceFromSync(std::string_view space)
{
    // Moved out under the lock and destroyed after it is released. ~ContentRegister blocks until any
    // in-flight cycle for that topic has drained, and that cycle's sink reaches back into the router
    // and the namespace store; destroying it while holding m_mutex would deadlock against itself.
    Registration doomed;

    {
        std::unique_lock lock(m_mutex);

        // addSpaceToSync() rejects duplicates, so at most one element can match here. Element order in
        // m_namespacesState is not semantically observed, so this is removed in O(1) via swap-with-back.
        const auto erased = base::utils::eraseFirstBySwap(
            m_namespacesState, [space](const SyncedNamespace& syncedNs) { return syncedNs.getOriginSpace() == space; });
        if (!erased)
        {
            throw std::runtime_error(fmt::format("Space '{}' is not in the sync list", space));
        }

        {
            std::lock_guard<std::mutex> containerLock(m_registrationsMutex);
            if (const auto it = m_registrations.find(cmcontent::rulesetTopic(space)); it != m_registrations.end())
            {
                doomed = std::move(it->second);
                m_registrations.erase(it);
            }
        }

        LOG_INFO("[{}] Removed space '{}' from the sync list", LOG_MODULE_NAME, space);

        dumpStateToStore();
    }
}

void CMSync::loadStateFromStore()
{
    auto storePtr = base::utils::lockWeakPtr(m_store, "Store");

    auto optDoc = storePtr->readDoc(STORE_NAME_CMSYNC);
    if (base::isError(optDoc))
    {
        throw std::runtime_error(
            fmt::format("Failed to load cmsync state from store: {}", base::getError(optDoc).message));
    }

    const auto& j = base::getResponse(optDoc);

    auto optArrayConf = j.getArray();
    if (!optArrayConf.has_value())
    {
        throw std::runtime_error("CMSync::loadStateFromStore: Invalid cmsync state document: missing array config");
    }

    m_namespacesState.clear();
    for (const auto& jSyncedNs : *optArrayConf)
    {
        m_namespacesState.emplace_back(SyncedNamespace::fromJson(jSyncedNs));
    }
}

void CMSync::dumpStateToStore()
{
    auto storePtr = base::utils::lockWeakPtr(m_store, "StoreInternal");

    json::Json j {};
    j.setArray();
    for (const auto& syncedNs : m_namespacesState)
    {
        j.appendJson(syncedNs.toJson());
    }

    if (auto optErr = storePtr->upsertDoc(STORE_NAME_CMSYNC, j); base::isError(optErr))
    {
        throw std::runtime_error(
            fmt::format("Failed to dump cmsync state to store: {}", base::getError(optErr).message));
    }
}

bool CMSync::syncSpace(SyncedNamespace& nsState)
{
    const auto topicName = cmcontent::rulesetTopic(nsState.getOriginSpace());

    Registration* registration = nullptr;
    {
        std::lock_guard<std::mutex> containerLock(m_registrationsMutex);
        const auto it = m_registrations.find(topicName);
        if (it == m_registrations.end())
        {
            LOG_WARNING("[{}] No content registration for space '{}'", LOG_MODULE_NAME, nsState.getOriginSpace());
            return false;
        }
        registration = &it->second;
    }

    registration->sink->prepare(
        nsState.hasNamespace() ? std::optional<cm::store::NamespaceId> {nsState.getNamespaceId()} : std::nullopt);

    content_manager::CycleOutcome outcome;
    try
    {
        // executeWithRetry retries on a thrown exception, but runOnce is noexcept and reports by
        // status, so a retryable outcome is rethrown here to drive it. The existing
        // analysisd.cmsync_indexer_connector_{max_retries,retry_interval} keys keep their meaning
        // and now guard the whole cycle instead of a single query.
        outcome = base::utils::executeWithRetry(
            [registration]()
            {
                auto result = registration->topic->runOnce();
                if (result.retryAfter.count() > 0)
                {
                    throw std::runtime_error(result.detail);
                }
                return result;
            },
            COMPONENT_NAME,
            fmt::format("Synchronize space '{}'", nsState.getOriginSpace()),
            m_attempts,
            m_waitSeconds,
            m_shutdownRequested);
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("[{}] Failed to synchronize namespace for space '{}': {}",
                    LOG_MODULE_NAME,
                    nsState.getOriginSpace(),
                    e.what());
        nsState.setSyncStatus(base::SyncStatus::FAILED);
        return false;
    }

    if (outcome.status == content_manager::CycleStatus::SkippedAlreadyRunning)
    {
        // An on-demand update for this space is in flight and will report its own result. Nothing
        // was observed here, so nothing is concluded here: leaving the status alone is the point —
        // marking the space FAILED because the API had just been used would be a lie, and reading
        // the sink's outcome would read the *other* cycle's.
        LOG_DEBUG("[{}] An update for space '{}' was already running; leaving its state untouched",
                  LOG_MODULE_NAME,
                  nsState.getOriginSpace());
        return false;
    }

    // Taken, not borrowed: this empties the sink's slot, so a later cycle cannot find this
    // outcome still sitting there and a caller cannot read one it did not produce.
    const auto sinkOutcome = registration->sink->takeOutcome();

    if (sinkOutcome.disabled)
    {
        // Route and namespace were torn down; the space keeps its entry so it can come back without
        // an operator re-adding it.
        nsState.setNamespaceId(DUMMY_NAMESPACE_ID);
        nsState.setRouteState(false, false, "");
        nsState.setSyncStatus(base::SyncStatus::READY);
        return true;
    }

    if (sinkOutcome.applied && sinkOutcome.newNamespaceId.has_value())
    {
        nsState.setNamespaceId(*sinkOutcome.newNamespaceId);
        nsState.setLastSuccessfulUpdate(static_cast<uint32_t>(std::time(nullptr)));
        nsState.setRouteState(true, true, sinkOutcome.hash);
        nsState.setSyncStatus(base::SyncStatus::READY);
        return true;
    }

    if (outcome.status == content_manager::CycleStatus::Unchanged)
    {
        LOG_DEBUG("[{}] No changes detected for space '{}'", LOG_MODULE_NAME, nsState.getOriginSpace());
        nsState.setRouteState(sinkOutcome.routeAvailable, true, sinkOutcome.hash);
        nsState.setSyncStatus(base::SyncStatus::READY);
        return false;
    }

    nsState.setSyncStatus(base::SyncStatus::FAILED);
    return false;
}

void CMSync::synchronize()
{
    LOG_DEBUG("[{}] Checking for namespace updates to synchronize", LOG_MODULE_NAME);

    std::unique_lock lock(m_mutex); // Lock the sync process, only 1 at a time

    bool stateChanged = false;

    for (auto& nsState : m_namespacesState)
    {
        // Check abort at the start of each namespace iteration
        if (m_shutdownRequested.load(std::memory_order_relaxed))
        {
            LOG_INFO("[{}] Synchronization aborted during namespace iteration", LOG_MODULE_NAME);
            break;
        }

        try
        {
            LOG_DEBUG("[{}] Synchronizing namespace for space '{}'", LOG_MODULE_NAME, nsState.getOriginSpace());

            if (!existSpaceInRemote(nsState.getOriginSpace()))
            {
                LOG_WARNING("[{}] Space '{}' does not exist in wazuh-indexer, skipping synchronization",
                            LOG_MODULE_NAME,
                            nsState.getOriginSpace());
                continue;
            }

            // Pre-flight check: verify the consumer is ready AND has data (local_offset != 0). The
            // content cycle validates readiness again inside its own snapshot — that is the
            // correctness gate — but this one is cheap, covers local_offset, and avoids paying for
            // a PIT when the indexer is visibly mid-update.
            if (nsState.getConsumerId().has_value())
            {
                auto indexerPtr = base::utils::lockWeakPtr(m_indexerPtr, "IndexerConnector");
                const bool ready = base::utils::executeWithRetry(
                    [&indexerPtr, &consumerId = nsState.getConsumerId().value()]()
                    { return indexerPtr->isConsumerReadyForSync(consumerId); },
                    COMPONENT_NAME,
                    fmt::format("Check consumer readiness for space '{}'", nsState.getOriginSpace()),
                    m_attempts,
                    m_waitSeconds,
                    m_shutdownRequested);

                if (!ready)
                {
                    LOG_INFO("[{}] Synchronization skipped for space '{}' because wazuh-indexer consumer '{}' is "
                             "not ready for sync (might be updating or no data)",
                             LOG_MODULE_NAME,
                             nsState.getOriginSpace(),
                             nsState.getConsumerId().value());
                    continue;
                }
            }

            nsState.setSyncStatus(base::SyncStatus::UPDATING);
            updateSpacesStatusSnapshot();

            if (syncSpace(nsState))
            {
                stateChanged = true;
            }

            updateSpacesStatusSnapshot();
        }
        catch (const std::exception& e)
        {
            nsState.setSyncStatus(base::SyncStatus::FAILED);
            updateSpacesStatusSnapshot();
            LOG_WARNING("[{}] Failed to synchronize namespace for space '{}': {}",
                        LOG_MODULE_NAME,
                        nsState.getOriginSpace(),
                        e.what());
        }
    }

    if (stateChanged)
    {
        try
        {
            dumpStateToStore();
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("[{}] Failed to dump sync state to store: {}", LOG_MODULE_NAME, e.what());
        }
    }

    LOG_DEBUG("[{}] Finished synchronization of spaces", LOG_MODULE_NAME);

    updateSpacesStatusSnapshot();
}

void CMSync::requestShutdown()
{
    m_shutdownRequested.store(true, std::memory_order_relaxed);

    // Wind down anything mid-cycle. Only the container is locked here — m_mutex is held by the very
    // cycle this is trying to interrupt.
    std::lock_guard<std::mutex> containerLock(m_registrationsMutex);
    for (auto& [_, registration] : m_registrations)
    {
        if (registration.topic)
        {
            registration.topic->requestStop();
        }
    }

    LOG_INFO("[{}] Shutdown requested", LOG_MODULE_NAME);
}

void CMSync::updateSpacesStatusSnapshot()
{
    // Full rebuild from the cached per-namespace state, then publish atomically. Does NOT query the
    // router: available/enabled/hash were cached during synchronize() (setRouteState), so building
    // the status never contends with event processing nor duplicates router calls.
    std::vector<SpaceStatus> result;
    result.reserve(m_namespacesState.size());

    for (const auto& nsState : m_namespacesState)
    {
        SpaceStatus entry;
        entry.name = nsState.getOriginSpace();
        entry.status = nsState.getSyncStatus();
        entry.available = nsState.getAvailable();
        entry.enabled = nsState.getEnabled();
        entry.hash = nsState.getHash();
        entry.lastSuccessfulUpdate = nsState.getLastSuccessfulUpdate();
        result.push_back(std::move(entry));
    }

    m_spacesStatus.store(std::move(result));
}

std::vector<SpaceStatus> CMSync::getSpacesStatus() const
{
    return *m_spacesStatus.load();
}

void CMSync::requestOnDemandUpdate(std::string_view space)
{
    const auto wanted = space.empty() ? std::string {} : cmcontent::rulesetTopic(space);

    std::lock_guard<std::mutex> containerLock(m_registrationsMutex);
    for (const auto& [topicName, registration] : m_registrations)
    {
        if (!wanted.empty() && topicName != wanted)
        {
            continue;
        }

        content_manager::requestOnDemand(topicName,
                                         content_manager::RunRequest {false, true},
                                         [topicName](content_manager::OnDemandResult result)
                                         {
                                             if (result.code == content_manager::OnDemandCode::Completed)
                                             {
                                                 LOG_DEBUG("[{}] On-demand update of '{}' finished",
                                                           LOG_MODULE_NAME,
                                                           topicName);
                                                 return;
                                             }
                                             LOG_WARNING("[{}] On-demand update of '{}' was not run: {}",
                                                         LOG_MODULE_NAME,
                                                         topicName,
                                                         result.detail);
                                         });
    }
}

} // namespace cm::sync
