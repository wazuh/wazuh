#include <algorithm>
#include <chrono>
#include <ctime>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <utility>

#include <base/logging.hpp>
#include <base/utils/generator.hpp>
#include <base/utils/metaHelpers.hpp>

#include <cmsync/cmsync.hpp>

namespace
{

const base::Name STORE_NAME_CMSYNC {"cmsync/status/0"};          ///< Name of the internal store document
const cm::store::NamespaceId DUMMY_NAMESPACE_ID {"dummy_ns_id"}; ///< Dummy namespace ID
constexpr std::string_view STANDARD_SPACE_NAME = "standard";     ///< Standard space name
constexpr std::string_view CUSTOM_SPACE_NAME = "custom";         ///< Custom space name
const std::string COMPONENT_NAME = "CMSync";                     ///< Component name for logging

constexpr std::string_view LOG_MODULE_NAME = "CM::Sync"; ///< Log module name for CMSync

/**
 * @brief Generate a random namespace ID for the given origin space
 *
 * @param originSpace Origin space name
 * @return cm::store::NamespaceId Generated namespace ID
 */
cm::store::NamespaceId generateNamespaceId(std::string_view originSpace)
{
    return {fmt::format("cmsync_{}_{}", originSpace, base::utils::generators::randomHexString(4))};
}

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

    // Cached router-derived state for status reporting. Updated during synchronize() (which already
    // queries the router for its own logic) so the status snapshot can be built WITHOUT touching the
    // router. Transient (not persisted): after restart these stay default until the next sync.
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
     * This constructor is used to create a dummy SyncedNamespace with only the origin space, used when adding a new
     * space to sync before the first synchronization.
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
               const size_t attempts,
               const size_t waitSeconds)
    : m_indexerPtr(indexerPtr)
    , m_cmcrudPtr(cmcrudPt)
    , m_store(storePtr)
    , m_router(routerPtr)
    , m_mutex()
    , m_attempts(attempts)
    , m_waitSeconds(waitSeconds)
{
    // Check if is the first setup
    if (storePtr->existsDoc(STORE_NAME_CMSYNC))
    {
        loadStateFromStore();
        const auto reconcileRouteState = [this]()
        {
            auto routerPtr = base::utils::lockWeakPtr(m_router, "RouterAPI");

            for (auto& nsState : m_namespacesState)
            {
                if (!routerPtr->existsEntry(nsState.getRouteName()))
                {
                    nsState.setRouteState(false, nsState.getEnabled(), "");
                    continue;
                }

                const auto resp = routerPtr->getEntry(nsState.getRouteName());
                if (base::isError(resp))
                {
                    LOG_WARNING("[CMSync] Failed to read route '{}' while reconciling status on startup: {}",
                                nsState.getRouteName(),
                                base::getError(resp).message);
                    nsState.setRouteState(false, nsState.getEnabled(), "");
                    continue;
                }

                nsState.setRouteState(true, nsState.getEnabled(), base::getResponse(resp).hash());
            }
        };
        reconcileRouteState();
        updateSpacesStatusSnapshot(); // Publish initial status
        return;
    }

    LOG_DEBUG("[{}] First setup detected, initializing default sync spaces", LOG_MODULE_NAME);

    // Populate directly and dump once to avoid multiple unnecessary store writes
    m_namespacesState.emplace_back(STANDARD_SPACE_NAME,
                                   std::optional<std::string>(std::string(wiconnector::STANDARD_RULESET_CONSUMER_ID)));
    m_namespacesState.emplace_back(CUSTOM_SPACE_NAME);
    dumpStateToStore();
    updateSpacesStatusSnapshot(); // Publish initial status
}

CMSync::~CMSync() = default;

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

bool CMSync::downloadNamespace(std::string_view originSpace,
                               const cm::store::NamespaceId& dstNamespace,
                               const std::optional<std::string_view>& consumerId)
{
    auto indexerPtr = base::utils::lockWeakPtr(m_indexerPtr, "IndexerConnector");
    auto cmcrudPtr = base::utils::lockWeakPtr(m_cmcrudPtr, "CMCrudService");

    // Download policy from wazuh-indexer (with optional consumer validation in PIT)
    auto policyResource = base::utils::executeWithRetry(
        [&indexerPtr, originSpace, &consumerId]() { return indexerPtr->getPolicy(originSpace, consumerId); },
        COMPONENT_NAME,
        fmt::format("Download '{}' space from wazuh-indexer", originSpace),
        m_attempts,
        m_waitSeconds,
        m_shutdownRequested);

    // If consumer is not idle, getPolicy returns nullopt
    if (!policyResource.has_value())
    {
        return false;
    }

    // Create destNamespace
    try
    {
        cmcrudPtr->importNamespace(dstNamespace,
                                   policyResource->kvdbs,
                                   policyResource->decoders,
                                   policyResource->filters,
                                   policyResource->integration,
                                   policyResource->policy,
                                   /*softValidation=*/true);
    }
    catch (const std::exception& e)
    {
        try
        {
            cmcrudPtr->deleteNamespace(dstNamespace);
        }
        catch (const std::exception& ex)
        {
            LOG_WARNING("[{}] Failed to rollback namespace '{}' after import failure: {}",
                        LOG_MODULE_NAME,
                        dstNamespace.toStr(),
                        ex.what());
        }
        throw std::runtime_error(
            fmt::format("Failed to store resources in namespace '{}': {}", dstNamespace.toStr(), e.what()));
    }

    return true;
}

std::optional<std::pair<std::string, bool>>
CMSync::getPolicyHashAndEnabledFromRemote(std::string_view space, const std::optional<std::string_view>& consumerId)
{
    auto indexerPtr = base::utils::lockWeakPtr(m_indexerPtr, "Indexer Connector");

    return base::utils::executeWithRetry(
        [&indexerPtr, space, &consumerId]() { return indexerPtr->getPolicyHashAndEnabled(space, consumerId); },
        COMPONENT_NAME,
        fmt::format("Get policy hash and enabled status for '{}' space from wazuh-indexer", space),
        m_attempts,
        m_waitSeconds,
        m_shutdownRequested);
}

std::optional<cm::store::NamespaceId>
CMSync::downloadAndEnrichNamespace(std::string_view originSpace, const std::optional<std::string_view>& consumerId)
{

    auto cmcrudPtr = base::utils::lockWeakPtr(m_cmcrudPtr, "CMCrud Service");

    // Generate a unique namespace ID
    const auto newNs = [&]() -> cm::store::NamespaceId
    {
        auto tempNsId = generateNamespaceId(originSpace);
        while (cmcrudPtr->existsNamespace(tempNsId))
        {
            tempNsId = generateNamespaceId(originSpace);
        }
        return tempNsId;
    }();

    if (!downloadNamespace(originSpace, newNs, consumerId))
    {
        return std::nullopt; // Consumer not idle
    }

    // Enrich the namespace with local-only assets
    /*
    try
    {
        // [KVDB/DECODER/INTEGRATIONS]: Add here any extra assets to the temporary namespace

        // [OUTPUTS]: Add local outputs for the current namespace

        // [FILTERS]: Add default filter for the current namespace

    }
    catch (const std::exception& e)
    {
        // Rollback temporary namespace
        try
        {
            cmcrudPtr->deleteNamespace(newNs);
        }
        catch (const std::exception& ex)
        {
            LOG_WARNING("[{}] Failed to rollback temporary namespace '{}' after asset "
                        "addition failure: {}",
                        LOG_MODULE_NAME,
                        newNs.toStr(),
                        ex.what());
        }
        throw std::runtime_error(
            fmt::format("Failed to add extra assets to namespace '{}': {}", newNs.toStr(), e.what()));
    }
    */

    return newNs;
}

void CMSync::syncNamespaceInRoute(const SyncedNamespace& nsState, const cm::store::NamespaceId& newNamespaceId)
{
    auto routerPtr = base::utils::lockWeakPtr(m_router, "RouterAPI");

    // If the route exists, hot-swap the namespace
    if (routerPtr->existsEntry(nsState.getRouteName()))
    {
        if (auto err = routerPtr->hotSwapNamespace(nsState.getRouteName(), newNamespaceId); base::isError(err))
        {
            throw std::runtime_error(
                fmt::format("Failed to hot-swap namespace in route '{}': {}", nsState.getRouteName(), err->message));
        }
        return;
    }

    // TODO: Remove router priority and evaluate route lexicographical order after
    // Helper: Get a aviable priority for the new route
    auto getAvailablePriority = [&routerPtr]() -> std::size_t
    {
        std::set<std::size_t> usedPriorities;
        for (const auto& entry : routerPtr->getEntries())
        {
            usedPriorities.insert(entry.priority());
        }
        for (std::size_t priority = 1; priority <= router::prod::EntryPost::maxPriority(); ++priority)
        {
            if (usedPriorities.find(priority) == usedPriorities.end())
            {
                return priority;
            }
        }
        throw std::runtime_error("No available priority for new route");
    };

    // Create a new route for the namespace
    router::prod::EntryPost newEntry {nsState.getRouteName(), newNamespaceId, getAvailablePriority()};

    if (auto err = routerPtr->postEntry(newEntry); base::isError(err))
    {
        throw std::runtime_error(
            fmt::format("Failed to create new route '{}': {}", nsState.getRouteName(), err->message));
    }
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

    LOG_DEBUG("[{}] Added space '{}' to the sync list", LOG_MODULE_NAME, space);

    dumpStateToStore();
}

void CMSync::removeSpaceFromSync(std::string_view space)
{
    std::unique_lock lock(m_mutex);

    auto it = std::remove_if(m_namespacesState.begin(),
                             m_namespacesState.end(),
                             [space](const SyncedNamespace& syncedNs) { return syncedNs.getOriginSpace() == space; });
    if (it == m_namespacesState.end())
    {
        throw std::runtime_error(fmt::format("Space '{}' is not in the sync list", space));
    }

    m_namespacesState.erase(it, m_namespacesState.end());

    LOG_INFO("[{}] Removed space '{}' from the sync list", LOG_MODULE_NAME, space);

    dumpStateToStore();
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

void CMSync::synchronize()
{

    LOG_DEBUG("[{}] Checking for namespace updates to synchronize", LOG_MODULE_NAME);

    const auto cmcrudPtr = base::utils::lockWeakPtr(m_cmcrudPtr, "CMCrud Service");
    const auto routerPtr = base::utils::lockWeakPtr(m_router, "RouterAPI");
    std::unique_lock lock(m_mutex); // Lock the sync process, only 1 at a time

    const auto dumpAndLogFn = [&]()
    {
        try
        {
            dumpStateToStore();
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("[{}] Failed to dump sync state to store: {}", LOG_MODULE_NAME, e.what());
        }
    };

    for (auto& nsState : m_namespacesState)
    {
        // Check abort at the start of each namespace iteration
        if (m_shutdownRequested.load(std::memory_order_relaxed))
        {
            LOG_INFO("[{}] Synchronization aborted during namespace iteration", LOG_MODULE_NAME);
            updateSpacesStatusSnapshot();
            return;
        }

        try
        {
            LOG_DEBUG("[{}] Synchronizing namespace for space '{}'", LOG_MODULE_NAME, nsState.getOriginSpace());

            // Check the route in the router FIRST (router is local, works even if the indexer is down).
            // This refreshes availability up front, so a route removed out-of-band is reflected even if
            // the indexer-dependent steps below abort. The result is reused by routeConfig (no re-query).
            const bool routeExists = routerPtr->existsEntry(nsState.getRouteName());
            if (!routeExists && nsState.getAvailable())
            {
                // Route gone out-of-band → no usable instance (keep enabled = last known policy).
                nsState.setRouteState(false, nsState.getEnabled(), "");
                updateSpacesStatusSnapshot();
            }

            if (!existSpaceInRemote(nsState.getOriginSpace()))
            {
                LOG_WARNING("[{}] Space '{}' does not exist in wazuh-indexer, skipping synchronization",
                            LOG_MODULE_NAME,
                            nsState.getOriginSpace());
                continue;
            }

            // Get remote policy hash and enabled status (with consumer validation in PIT if configured)
            if (m_shutdownRequested.load(std::memory_order_relaxed))
            {
                LOG_INFO("[{}] Synchronization aborted before getting policy info for space '{}'",
                         LOG_MODULE_NAME,
                         nsState.getOriginSpace());
                updateSpacesStatusSnapshot();
                return;
            }

            // Pre-flight check: verify consumer is idle and has data (local_offset != 0)
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

            const auto hashResult =
                getPolicyHashAndEnabledFromRemote(nsState.getOriginSpace(), nsState.getConsumerId());
            if (!hashResult.has_value())
            {
                LOG_INFO("[{}] Synchronization skipped for space '{}' because wazuh-indexer is updating the policy "
                         "or consumer is not idle (consumer ID: '{}')",
                         LOG_MODULE_NAME,
                         nsState.getOriginSpace(),
                         nsState.getConsumerId().value_or("unknown"));
                continue;
            }
            const auto& [remoteHash, remoteEnabled] = *hashResult;

            // Check the current route/ns configuration to avoid unnecessary synchronization.
            // Reuses routeExists from the up-front check above (no second existsEntry call).
            const auto routeConfig = [&]() -> std::optional<std::tuple<bool, cm::store::NamespaceId, std::string>>
            {
                if (routeExists)
                {
                    const auto resp = routerPtr->getEntry(nsState.getRouteName());
                    if (base::isError(resp))
                    {
                        throw std::runtime_error(fmt::format("Failed to get route entry for '{}': {}",
                                                             nsState.getRouteName(),
                                                             base::getError(resp).message));
                    }
                    const auto& entry = base::getResponse(resp);

                    const auto enabledRoute = entry.status() == ::router::env::State::ENABLED;
                    return std::make_tuple(enabledRoute, entry.namespaceId(), entry.hash());
                }
                return std::nullopt;
            }();

            // Cache the current state for status reporting (avoids extra router calls in the status
            // build). 'enabled' reflects the remote policy (remoteEnabled), not the router route state;
            // 'available'/'hash' come from the current route. Overridden below on disable/success.
            if (routeConfig.has_value())
            {
                const auto& [_enabledRoute, _routeNsId, routeHash] = *routeConfig;
                nsState.setRouteState(true, remoteEnabled, routeHash);
            }
            else
            {
                nsState.setRouteState(false, remoteEnabled, "");
            }

            // Cases:
            // 1. If the policy is disabled in the indexer, we should remove route and namespace if they exist, and skip
            // synchronization until it's enabled again.
            // 2. If the policy is enabled and the route/namespace exist, and the hash is the same, we should skip
            // synchronization.
            // 3. If the policy is enabled and the route/namespace do not exist, we should synchronize.
            // 4. If the policy is enabled and the route/namespace exist, but the hash is different, we should
            // synchronize.

            // Case 1: Policy disabled in indexer
            if (!remoteEnabled)
            {
                if (routeConfig.has_value())
                {
                    const auto& [_ignore, nsId, routeHash] = *routeConfig;
                    LOG_INFO("[{}] Policy for space '{}' is disabled in indexer, removing route and namespace",
                             LOG_MODULE_NAME,
                             nsState.getOriginSpace());

                    if (auto err = routerPtr->deleteEntry(nsState.getRouteName()); base::isError(err))
                    {
                        LOG_WARNING("[{}] Failed to delete route '{}' for space '{}': {}",
                                    LOG_MODULE_NAME,
                                    nsState.getRouteName(),
                                    nsState.getOriginSpace(),
                                    err->message);
                    }
                    try
                    {
                        cmcrudPtr->deleteNamespace(nsId);
                        nsState.setNamespaceId(DUMMY_NAMESPACE_ID); // Set dummy namespace id until next synchronization
                        dumpAndLogFn();
                    }
                    catch (const std::exception& e)
                    {
                        LOG_WARNING("[{}] Failed to delete namespace '{}' for space '{}': {}",
                                    LOG_MODULE_NAME,
                                    nsId.toStr(),
                                    nsState.getOriginSpace(),
                                    e.what());
                    }
                }
                else
                {
                    LOG_DEBUG("[{}] Policy for space '{}' is disabled in indexer and no route exists, skipping",
                              LOG_MODULE_NAME,
                              nsState.getOriginSpace());
                }
                nsState.setRouteState(false, false, ""); // route removed / absent → not available
                continue;
            }

            // Cases 2: No changes, skip synchronization
            if (routeConfig.has_value())
            {
                const auto& [enabledRoute, nsId, routeHash] = *routeConfig;
                if (enabledRoute && routeHash == remoteHash)
                {
                    LOG_DEBUG("[{}] No changes detected for space '{}', skipping synchronization",
                              LOG_MODULE_NAME,
                              nsState.getOriginSpace());
                    continue; // Case 4: No changes, skip synchronization
                }
            }

            // Cases 3 and 4: Changes detected, perform synchronization
            LOG_INFO("[{}] Changes detected for space '{}', updating...", LOG_MODULE_NAME, nsState.getOriginSpace());

            // Mark this space as running
            nsState.setSyncStatus(base::SyncStatus::UPDATING);
            updateSpacesStatusSnapshot();

            // Check abort before download (most expensive operation)
            if (m_shutdownRequested.load(std::memory_order_relaxed))
            {
                LOG_INFO("[{}] Synchronization aborted before downloading namespace for space '{}'",
                         LOG_MODULE_NAME,
                         nsState.getOriginSpace());
                nsState.setSyncStatus(base::SyncStatus::READY);
                updateSpacesStatusSnapshot();
                return;
            }

            // Download and enrich the namespace (consumer validated again within PIT)
            const auto newNsIdOpt = downloadAndEnrichNamespace(nsState.getOriginSpace(), nsState.getConsumerId());
            if (!newNsIdOpt.has_value())
            {
                LOG_INFO("[{}] Download skipped for space '{}' because consumer is not idle",
                         LOG_MODULE_NAME,
                         nsState.getOriginSpace());
                nsState.setSyncStatus(base::SyncStatus::READY);
                updateSpacesStatusSnapshot();
                continue;
            }
            const auto& newNsId = *newNsIdOpt;

            // Sync the namespace in the router
            try
            {
                syncNamespaceInRoute(nsState, newNsId);
            }
            catch (const std::exception& e)
            {
                // Rollback temporary namespace
                try
                {
                    cmcrudPtr->deleteNamespace(newNsId);
                }
                catch (const std::exception& ex)
                {
                    LOG_WARNING("[{}::synchronize] Failed to rollback temporary namespace '{}' after route sync "
                                "failure: {}",
                                LOG_MODULE_NAME,
                                newNsId.toStr(),
                                ex.what());
                }
                LOG_ERROR("[{}] Failed to sync namespace in route for space '{}': {}",
                          LOG_MODULE_NAME,
                          nsState.getOriginSpace(),
                          e.what());
                nsState.setSyncStatus(base::SyncStatus::FAILED);
                updateSpacesStatusSnapshot();
                continue;
            }

            // Update and dump the sync state. Set the timestamp BEFORE dumping so it is persisted.
            auto oldNsId = nsState.getNamespaceId();
            nsState.setNamespaceId(newNsId);
            nsState.setLastSuccessfulUpdate(static_cast<uint32_t>(std::time(nullptr)));
            dumpAndLogFn();

            // Delete old namespace if it exists and is different from the new one
            if (oldNsId != DUMMY_NAMESPACE_ID && oldNsId != newNsId)
            {
                try
                {
                    cmcrudPtr->deleteNamespace(oldNsId);
                }
                catch (const std::exception& e)
                {
                    LOG_WARNING("[{}] Failed to delete old namespace '{}' for space '{}': {}",
                                LOG_MODULE_NAME,
                                oldNsId.toStr(),
                                nsState.getOriginSpace(),
                                e.what());
                }
            }

            LOG_INFO("[{}] Successfully synchronized space '{}'", LOG_MODULE_NAME, nsState.getOriginSpace());
            // Route now deployed for an enabled policy at the remote hash.
            nsState.setRouteState(true, remoteEnabled, remoteHash);
            nsState.setSyncStatus(base::SyncStatus::READY);
            updateSpacesStatusSnapshot();
        }
        catch (const std::exception& e)
        {
            nsState.setSyncStatus(base::SyncStatus::FAILED);
            updateSpacesStatusSnapshot();
            LOG_WARNING(
                "[{}] Failed to synchronize namespace for space '{}': {}", LOG_MODULE_NAME, nsState.getOriginSpace(), e.what());
        }
    }

    LOG_DEBUG("[{}] Finished synchronization of spaces", LOG_MODULE_NAME);

    updateSpacesStatusSnapshot();
}

void CMSync::requestShutdown()
{
    m_shutdownRequested.store(true, std::memory_order_relaxed);
    LOG_INFO("[{}] Shutdown requested", LOG_MODULE_NAME);
}

void CMSync::updateSpacesStatusSnapshot()
{
    // Full rebuild from the cached per-namespace state, then publish atomically. Does NOT query the
    // router: available/enabled/hash were cached during synchronize() (setRouteState), so building the
    // status never contends with event processing nor duplicates router calls.
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

} // namespace cm::sync
