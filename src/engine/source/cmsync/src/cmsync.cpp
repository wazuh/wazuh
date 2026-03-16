#include <algorithm>
#include <chrono>
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
constexpr std::string_view COMPONENT_NAME = "CMSync";            ///< Component name for logging

/**
 * @brief Generate a route name for the given origin space
 *
 * @param originSpace Origin space name
 * @return std::string Generated route name
 */
std::string generateRouteName(std::string_view originSpace)
{
    return fmt::format("cmsync_{}", originSpace);
}

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
    std::string m_originSpace;     ///< Origin space in the indexer
    std::string m_routeName;       ///< Route name in the router
    cm::store::NamespaceId m_nsId; ///< Destination namespace ID in the local store

    static constexpr std::string_view JPATH_ORIGIN = "/origin_space";       ///< JSON path for origin space
    static constexpr std::string_view JPATH_NAMESPACE_ID = "/namespace_id"; ///< JSON path for namespace ID

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
     */
    explicit SyncedNamespace(std::string_view originSpace)
        : m_originSpace(originSpace)
        , m_routeName(generateRouteName(originSpace))
        , m_nsId(DUMMY_NAMESPACE_ID)
    {
    }

    /**
     * @brief Construct a new SyncedNamespace with all fields
     *
     * @param originSpace Origin space name
     * @param nsId Destination namespace ID in the local store
     */
    SyncedNamespace(std::string_view originSpace, cm::store::NamespaceId nsId)
        : m_originSpace(originSpace)
        , m_routeName(generateRouteName(originSpace))
        , m_nsId(std::move(nsId))
    {
    }

    /* Getters and Setters */
    const std::string& getOriginSpace() const { return m_originSpace; }
    const cm::store::NamespaceId& getNamespaceId() const { return m_nsId; }
    const std::string& getRouteName() const { return m_routeName; }
    void setNamespaceId(const cm::store::NamespaceId& nsId) { m_nsId = nsId; }

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
        auto optOrigin = j.getString(JPATH_ORIGIN);
        if (!optOrigin.has_value() || optOrigin->empty())
        {
            throw std::runtime_error("NsSyncState::fromJson: Missin/empty origin_space field");
        }

        auto optNsId = j.getString(JPATH_NAMESPACE_ID);
        if (!optNsId.has_value())
        {
            throw std::runtime_error("NsSyncState::fromJson: Missing namespace_id field");
        }

        return {*optOrigin, cm::store::NamespaceId(*optNsId)};
    }
};

CMSync::CMSync(const std::shared_ptr<wiconnector::IWIndexerConnector>& indexerPtr,
               const std::shared_ptr<cm::crud::ICrudService>& cmcrudPt,
               const std::shared_ptr<::store::IStore>& storePtr,
               const std::shared_ptr<router::IRouterAPI>& routerPtr,
               const size_t attemps,
               const size_t waitSeconds)
    : m_indexerPtr(indexerPtr)
    , m_cmcrudPtr(cmcrudPt)
    , m_store(storePtr)
    , m_router(routerPtr)
    , m_mutex()
    , m_attemps(attemps)
    , m_waitSeconds(waitSeconds)
{
    // Check if is the first setup
    if (storePtr->existsDoc(STORE_NAME_CMSYNC))
    {
        loadStateFromStore();
        return;
    }

    LOG_INFO("[CMSync] First setup detected, initializing default sync spaces");

    addSpaceToSync("standard");
    addSpaceToSync("custom");
    dumpStateToStore();
}

CMSync::~CMSync() = default;

bool CMSync::existSpaceInRemote(std::string_view space)
{
    auto indexerPtr = base::utils::lockWeakPtr(m_indexerPtr, "IndexerConnector");

    return base::utils::executeWithRetry([&indexerPtr, space]() { return indexerPtr->existsPolicy(space); },
                                         fmt::format("{}::exist()", COMPONENT_NAME),
                                         fmt::format("Check '{}' space in wazuh-indexer", space),
                                         m_attemps,
                                         m_waitSeconds);
}

void CMSync::downloadNamespace(std::string_view originSpace, const cm::store::NamespaceId& dstNamespace)
{
    auto indexerPtr = base::utils::lockWeakPtr(m_indexerPtr, "IndexerConnector");
    auto cmcrudPtr = base::utils::lockWeakPtr(m_cmcrudPtr, "CMCrudService");

    // Download policy from wazuh-indexer
    auto policyResource =
        base::utils::executeWithRetry([&indexerPtr, originSpace]() { return indexerPtr->getPolicy(originSpace); },
                                      fmt::format("{}::downloadNamespace()", COMPONENT_NAME),
                                      fmt::format("Download '{}' space from wazuh-indexer", originSpace),
                                      m_attemps,
                                      m_waitSeconds);

    // Create destNamespace
    try
    {
        cmcrudPtr->importNamespace(dstNamespace,
                                   policyResource.kvdbs,
                                   policyResource.decoders,
                                   policyResource.integration,
                                   policyResource.policy,
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
            LOG_WARNING("[CMSync::downloadNamespace] Failed to rollback namespace '{}' after import failure: {}",
                        dstNamespace.toStr(),
                        ex.what());
        }
        throw std::runtime_error(
            fmt::format("Failed to store resources in namespace '{}': {}", dstNamespace.toStr(), e.what()));
    }
}

std::pair<std::string, bool> CMSync::getPolicyHashAndEnabledFromRemote(std::string_view space)
{
    auto indexerPtr = base::utils::lockWeakPtr(m_indexerPtr, "Indexer Connector");

    return base::utils::executeWithRetry(
        [&indexerPtr, space]() { return indexerPtr->getPolicyHashAndEnabled(space); },
        fmt::format("{}::getInfoFromRemote()", COMPONENT_NAME),
        fmt::format("Get policy hash and enabled status for '{}' space from wazuh-indexer", space),
        m_attemps,
        m_waitSeconds);
}

cm::store::NamespaceId CMSync::downloadAndEnrichNamespace(std::string_view originSpace)
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

    downloadNamespace(originSpace, newNs);

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
            LOG_WARNING("[CMSync::downloadAndEnrichNamespace] Failed to rollback temporary namespace '{}' after asset "
                        "addition failure: {}",
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
                ;
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

    // Add the new space to the sync list
    m_namespacesState.emplace_back(space);
    // SET Dummy namespace id
    m_namespacesState.back().setNamespaceId(DUMMY_NAMESPACE_ID);

    LOG_INFO("[CMSync] Added space '{}' to the sync list", space);

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

    LOG_INFO("[CMSync] Removed space '{}' from the sync list", space);

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

    LOG_DEBUG("[CMSync] Checking for namespace updates to synchronize");

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
            LOG_WARNING("[CMSync] Failed to dump sync state to store: {}", e.what());
        }
    };

    for (auto& nsState : m_namespacesState)
    {
        try
        {
            LOG_DEBUG("[CMSync] Synchronizing namespace for space '{}'", nsState.getOriginSpace());

            if (!existSpaceInRemote(nsState.getOriginSpace()))
            {
                LOG_WARNING("[CMSync] Space '{}' does not exist in remote indexer, skipping synchronization",
                            nsState.getOriginSpace());
                continue;
            }

            // Get remote policy hash and enabled status
            const auto [remoteHash, remoteEnabled] = getPolicyHashAndEnabledFromRemote(nsState.getOriginSpace());

            // Check the current route/ns configuration to avoid unnecessary synchronization.
            const auto routeConfig = [&]() -> std::optional<std::tuple<bool, cm::store::NamespaceId, std::string>>
            {
                if (routerPtr->existsEntry(nsState.getRouteName()))
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
                    LOG_INFO("[CMSync] Policy for space '{}' is disabled in indexer, removing route and namespace",
                             nsState.getOriginSpace());

                    if (auto err = routerPtr->deleteEntry(nsState.getRouteName()); base::isError(err))
                    {
                        LOG_WARNING("[CMSync] Failed to delete route '{}' for space '{}': {}",
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
                        LOG_WARNING("[CMSync] Failed to delete namespace '{}' for space '{}': {}",
                                    nsId.toStr(),
                                    nsState.getOriginSpace(),
                                    e.what());
                    }
                }
                else
                {
                    LOG_DEBUG("[CMSync] Policy for space '{}' is disabled in indexer and no route exists, skipping",
                              nsState.getOriginSpace());
                }
                continue;
            }

            // Cases 2: No changes, skip synchronization
            if (routeConfig.has_value())
            {
                const auto& [enabledRoute, nsId, routeHash] = *routeConfig;
                if (enabledRoute && routeHash == remoteHash)
                {
                    LOG_DEBUG("[CMSync] No changes detected for space '{}', skipping synchronization",
                              nsState.getOriginSpace());
                    continue; // Case 4: No changes, skip synchronization
                }
            }

            // Cases 3 and 4: Changes detected, perform synchronization
            LOG_INFO("[CMSync] Changes detected for space '{}', updating...", nsState.getOriginSpace());

            // Download and enrich the namespace
            const auto newNsId = downloadAndEnrichNamespace(nsState.getOriginSpace());

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
                    LOG_WARNING("[CMSync::synchronize] Failed to rollback temporary namespace '{}' after route sync "
                                "failure: {}",
                                newNsId.toStr(),
                                ex.what());
                }
                LOG_ERROR("[CMSync] Failed to sync namespace in route for space '{}': {}",
                          nsState.getOriginSpace(),
                          e.what());
                continue;
            }

            // Update and dump the sync state
            auto oldNsId = nsState.getNamespaceId();
            nsState.setNamespaceId(newNsId);
            dumpAndLogFn();

            // Delete old namespace if it exists and is different from the new one
            if (oldNsId != DUMMY_NAMESPACE_ID && oldNsId != newNsId)
            {
                auto cmcrudPtr = base::utils::lockWeakPtr(m_cmcrudPtr, "CMCrud Service");
                try
                {
                    cmcrudPtr->deleteNamespace(oldNsId);
                }
                catch (const std::exception& e)
                {
                    LOG_WARNING("[CMSync] Failed to delete old namespace '{}' for space '{}': {}",
                                oldNsId.toStr(),
                                nsState.getOriginSpace(),
                                e.what());
                }
            }

            LOG_INFO("[CMSync] Successfully synchronized space '{}'", nsState.getOriginSpace());
        }
        catch (const std::exception& e)
        {
            LOG_WARNING(
                "[CMSync] Failed to synchronize namespace for space '{}': {}", nsState.getOriginSpace(), e.what());
        }
    }

    LOG_DEBUG("[CMSync] Finished synchronization of spaces");
}

} // namespace cm::sync
