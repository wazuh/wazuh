#include <chrono>
#include <set>
#include <stdexcept>
#include <thread>
#include <utility>

#include <base/logging.hpp>
#include <base/utils/generator.hpp>

#include <cmsync/cmsync.hpp>

namespace
{

const base::Name STORE_NAME_CMSYNC {"cmsync/status/0"};          ///< Name of the internal store document
const base::Name ALLOW_ALL_FILTER_NAME {"filter/allow-all/0"};   ///< Name of the Allow All Filter
const cm::store::NamespaceId DUMMY_NAMESPACE_ID {"dummy_ns_id"}; ///< Dummy namespace ID

/**
 * @brief Locks a weak pointer and returns a shared pointer.
 *
 * @tparam T Type of the resource
 * @param weakPtr Weak pointer to lock
 * @param resourceName Name of the resource for error messages
 * @return std::shared_ptr<T> Shared pointer to the resource
 * @throw std::runtime_error if the resource is not available
 */
template<typename T>
std::shared_ptr<T> lockWeakPtr(const std::weak_ptr<T>& weakPtr, const std::string& resourceName)
{
    auto sharedPtr = weakPtr.lock();
    if (!sharedPtr)
    {
        throw std::runtime_error(resourceName + " resource is not available");
    }
    return sharedPtr;
}

/**
 * @brief Create a Allow All Filter
 *
 * @return json::Json Filter definition
 */
json::Json createAllowAllFilter()
{
    json::Json filter {};
    filter.setString(ALLOW_ALL_FILTER_NAME.toStr(), "/name");
    filter.setString(base::utils::generators::generateUUIDv4(), "/id");
    return filter;
}

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
 * @brief State of a namespace being synchronized
 */
class NsSyncState
{
private:
    std::string m_originSpace;     ///< Origin space in the indexer
    std::string m_lastPolicyHash;  ///< Last known policy hash
    std::string m_routeName;       ///< Route name in the router
    cm::store::NamespaceId m_nsId; ///< Destination namespace ID in the local store

    static constexpr std::string_view JPATH_ORIGIN = "/origin_space";               ///< JSON path for origin space
    static constexpr std::string_view JPATH_LAST_POLICY_HASH = "/last_policy_hash"; ///< JSON path for last policy hash
    static constexpr std::string_view JPATH_NAMESPACE_ID = "/namespace_id";         ///< JSON path for namespace ID

public:
    NsSyncState() = delete;
    explicit NsSyncState(std::string_view originSpace)
        : m_originSpace(originSpace)
        , m_lastPolicyHash()
        , m_routeName(generateRouteName(originSpace))
        , m_nsId(generateNamespaceId(originSpace))
    {
    }

    NsSyncState(std::string_view originSpace, std::string_view lastPolicyHash, cm::store::NamespaceId nsId)
        : m_originSpace(originSpace)
        , m_lastPolicyHash(lastPolicyHash)
        , m_nsId(std::move(nsId))
    {
    }

    /* Getters and Setters */
    const std::string& getOriginSpace() const { return m_originSpace; }
    const std::string& getLastPolicyHash() const { return m_lastPolicyHash; }
    const cm::store::NamespaceId& getNamespaceId() const { return m_nsId; }
    const std::string& getRouteName() const { return m_routeName; }
    void setLastPolicyHash(std::string_view hash) { m_lastPolicyHash = hash; }
    void setRouteName(std::string_view routeName) { m_routeName = routeName; }
    void setOriginSpace(std::string_view originSpace) { m_originSpace = originSpace; }
    void setNamespaceId(const cm::store::NamespaceId& nsId) { m_nsId = nsId; }

    /**
     * @brief Serialize the NsSyncState to a JSON object
     *
     * @return json::Json JSON representation of the NsSyncState
     */
    json::Json toJson() const
    {
        json::Json j {};
        j.setString(m_originSpace, JPATH_ORIGIN);
        j.setString(m_lastPolicyHash, JPATH_LAST_POLICY_HASH);
        j.setString(m_nsId.toStr(), JPATH_NAMESPACE_ID);
        return j;
    }

    /**
     * @brief Deserialize a NsSyncState from a JSON object
     *
     * @param j JSON object to deserialize
     * @return NsSyncState Deserialized NsSyncState
     * @throw std::runtime_error if required fields are missing or invalid
     */
    static NsSyncState fromJson(const json::Json& j)
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

        auto optLastHash = j.getString(JPATH_LAST_POLICY_HASH);
        if (!optLastHash.has_value())
        {
            throw std::runtime_error("NsSyncState::fromJson: Missing last_policy_hash field");
        }

        return {*optOrigin, *optLastHash, cm::store::NamespaceId(*optNsId)};
    }
};

CMSync::CMSync(const std::shared_ptr<wiconnector::IWIndexerConnector>& indexerPtr,
               const std::shared_ptr<cm::crud::ICrudService>& cmcrudPt,
               const std::shared_ptr<::store::IStoreInternal>& storePtr,
               const std::shared_ptr<router::IRouterAPI>& routerPtr)
    : m_indexerPtr(indexerPtr)
    , m_cmcrudPtr(cmcrudPt)
    , m_store(storePtr)
    , m_router(routerPtr)
    , m_mutex()
    , m_attemps(3)
    , m_waitSeconds(5)
// , m_namespacesState()

{
    // Check if is the first setup
    if (storePtr->existsInternalDoc(STORE_NAME_CMSYNC))
    {
        loadStateFromStore();
        return;
    }

    LOG_INFO("[CM::Sync] First setup detected, initializing default sync spaces");

    addSpaceToSync("wazuh");
    addSpaceToSync("custom");
    addSpaceToSync("free");
    dumpStateToStore();
}

CMSync::~CMSync() = default;

bool CMSync::existSpaceInRemote(std::string_view space)
{
    auto indexerPtr = lockWeakPtr(m_indexerPtr, "IndexerConnector");

    for (std::size_t attempt = 1; attempt <= m_attemps; ++attempt)
    {
        try
        {
            return indexerPtr->existsPolicy(space);
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("[CMSync::existSpaceInRemote] Attempt {}/{}: Failed to check existence of space '{}': {}",
                        attempt,
                        m_attemps,
                        space,
                        e.what());
            if (attempt < m_attemps)
                std::this_thread::sleep_for(std::chrono::seconds(m_waitSeconds));
            else
                throw;
        }
    }
    throw std::runtime_error("Unreachable code in CMSync::existSpaceInRemote");
}

void CMSync::downloadNamespace(std::string_view originSpace, const cm::store::NamespaceId& dstNamespace)
{

    auto indexerPtr = lockWeakPtr(m_indexerPtr, "IndexerConnector");
    auto cmcrudPtr = lockWeakPtr(m_cmcrudPtr, "CMCrudService");

    // Download de policy from wazuh-indexer
    auto policyResource = [this, &indexerPtr, &originSpace]()
    {
        for (std::size_t attempt = 1; attempt <= m_attemps; ++attempt)
        {
            try
            {
                return indexerPtr->getPolicy(originSpace);
            }
            catch (const std::exception& e)
            {
                LOG_WARNING("[CMSync::downloadNamespace] Attempt {}/{}: Failed to get policy for space '{}': {}",
                            attempt,
                            m_attemps,
                            originSpace,
                            e.what());
                if (attempt < m_attemps)
                    std::this_thread::sleep_for(std::chrono::seconds(m_waitSeconds));
                else
                    throw;
            }
        }
        throw std::runtime_error("Unreachable code in CMSync::downloadNamespace");
    }();

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
            cmcrudPtr->deleteNamespace(dstNamespace.toStr());
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

std::string CMSync::getPolicyHashFromRemote(std::string_view space)
{
    auto indexerPtr = lockWeakPtr(m_indexerPtr, "Indexer Connector");

    for (std::size_t attempt = 1; attempt <= m_attemps; ++attempt)
    {
        try
        {
            return indexerPtr->getPolicyHash(space);
        }
        catch (const std::exception& e)
        {
            LOG_WARNING_L("CMSync::getPolicyHashFromRemote",
                          "Attempt {}/{}: Failed to get policy hash for space '{}': {}",
                          attempt,
                          m_attemps,
                          space,
                          e.what());
            if (attempt < m_attemps)
                std::this_thread::sleep_for(std::chrono::seconds(m_waitSeconds));
            else
                throw;
        }
    }
    throw std::runtime_error("Unreachable code in CMSync::getPolicyHashFromRemote");
}

cm::store::NamespaceId CMSync::downloadAndEnrichNamespace(std::string_view originSpace)
{

    auto cmcrudPtr = lockWeakPtr(m_cmcrudPtr, "CMCrud Service");

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
    try
    {
        // [KVDB/DECODER/INTEGRATIONS]: Add here any extra assets to the temporary namespace

        // [OUTPUTS]: Add local outputs for the current namespace
        // TODO

        // [FILTERS]: Necesary filter for the route to work
        cmcrudPtr->upsertResource(
            createAllowAllFilter().str(), cm::store::ResourceType::FILTER, ALLOW_ALL_FILTER_NAME.fullName());
    }
    catch (const std::exception& e)
    {
        // Rollback temporary namespace
        try
        {
            cmcrudPtr->deleteNamespace(newNs.toStr());
        }
        catch (const std::exception& ex)
        {
            LOG_WARNING(
                "[CMSync::buildNamespace] Failed to rollback temporary namespace '{}' after asset addition failure: {}",
                newNs.toStr(),
                ex.what());
        }
        throw std::runtime_error(
            fmt::format("Failed to add extra assets to namespace '{}': {}", newNs.toStr(), e.what()));
    }

    return newNs;
}

void CMSync::syncNamespaceInRoute(const NsSyncState& nsState, const cm::store::NamespaceId& newNamespaceId)
{
    auto routerPtr = lockWeakPtr(m_router, "RouterAPI");

    // If the route exists, hot-swap the namespace
    if (routerPtr->existsEntry(nsState.getRouteName()))
    {
        if (auto err = routerPtr->hotSwapNamespace(nsState.getRouteName(), newNamespaceId); base::isError(err))
        {
            throw std::runtime_error(
                fmt::format("[CMSync::syncNamespaceInRoute] Failed to hot-swap namespace in route '{}': {}",
                            nsState.getRouteName(),
                            err->message));
        }
        return;
    }

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
    router::prod::EntryPost newEntry {
        nsState.getRouteName(), newNamespaceId, ALLOW_ALL_FILTER_NAME, getAvailablePriority()};

    if (auto err = routerPtr->postEntry(newEntry); base::isError(err))
    {
        throw std::runtime_error(fmt::format("[CMSync::syncNamespaceInRoute] Failed to create new route '{}': {}",
                                             nsState.getRouteName(),
                                             err->message));
    }
}

void CMSync::addSpaceToSync(std::string_view space)
{
    std::unique_lock lock(m_mutex);

    // Check if the space is already in the sync list
    for (const auto& nsState : m_namespacesState)
    {
        if (nsState.getOriginSpace() == space)
        {
            throw std::runtime_error(fmt::format("Space '{}' is already in the sync list", space));
        }
    }

    // Add the new space to the sync list
    m_namespacesState.emplace_back(space);
    // SET Dummy namespace id
    m_namespacesState.back().setNamespaceId(DUMMY_NAMESPACE_ID);

    LOG_INFO("[CM::Sync] Added space '{}' to the sync list", space);

    dumpStateToStore();
}

void CMSync::removeSpaceFromSync(std::string_view space)
{
    std::unique_lock lock(m_mutex);

    auto it = std::remove_if(m_namespacesState.begin(),
                             m_namespacesState.end(),
                             [space](const NsSyncState& nsState) { return nsState.getOriginSpace() == space; });
    if (it == m_namespacesState.end())
    {
        throw std::runtime_error(fmt::format("Space '{}' is not in the sync list", space));
    }

    m_namespacesState.erase(it, m_namespacesState.end());

    LOG_INFO("[CM::Sync] Removed space '{}' from the sync list", space);

    dumpStateToStore();
}

void CMSync::loadStateFromStore()
{

    auto storePtr = lockWeakPtr(m_store, "StoreInternal");

    auto optDoc = storePtr->readInternalDoc(STORE_NAME_CMSYNC);
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
    for (const auto& jNsState : *optArrayConf)
    {
        m_namespacesState.push_back(NsSyncState::fromJson(jNsState));
    }
}

void CMSync::dumpStateToStore()
{

    auto storePtr = lockWeakPtr(m_store, "StoreInternal");

    json::Json j {};
    j.setArray();
    for (const auto& nsState : m_namespacesState)
    {
        j.appendJson(nsState.toJson());
    }

    if (auto optErr = storePtr->upsertInternalDoc(STORE_NAME_CMSYNC, j); base::isError(optErr))
    {
        throw std::runtime_error(
            fmt::format("Failed to dump cmsync state to store: {}", base::getError(optErr).message));
    }
}

void CMSync::synchronize()
{

    LOG_INFO("[CM::Sync] Checking for namespace updates to synchronize");

    std::unique_lock lock(m_mutex); // Lock the sync process, only 1 at a time

    for (auto& nsState : m_namespacesState)
    {
        try
        {
            LOG_DEBUG("[CM::Sync] Synchronizing namespace for space '{}'", nsState.getOriginSpace());

            if (!existSpaceInRemote(nsState.getOriginSpace()))
            {
                LOG_DEBUG("[CM::Sync] Space '{}' does not exist in remote indexer, skipping synchronization",
                          nsState.getOriginSpace());
                continue;
            }

            // Get remote policy hash
            const auto remoteHash = getPolicyHashFromRemote(nsState.getOriginSpace());

            // Check if the policy has changed
            if (remoteHash == nsState.getLastPolicyHash())
            {
                LOG_DEBUG("[CM::Sync] No changes detected for space '{}'", nsState.getOriginSpace());
                continue;
            }

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
                auto cmcrudPtr = lockWeakPtr(m_cmcrudPtr, "CMCrud Service");
                try
                {
                    cmcrudPtr->deleteNamespace(newNsId.toStr());
                }
                catch (const std::exception& ex)
                {
                    LOG_WARNING("[CMSync::synchronize] Failed to rollback temporary namespace '{}' after route sync "
                                "failure: {}",
                                newNsId.toStr(),
                                ex.what());
                }
                throw; // Re-throw the original exception
            }

            // Update the sync state
            auto oldNsId = nsState.getNamespaceId();
            nsState.setLastPolicyHash(remoteHash);
            nsState.setNamespaceId(newNsId);

            // Delete old namespace if it exists and is different from the new one
            if (oldNsId != DUMMY_NAMESPACE_ID && oldNsId != newNsId)
            {
                auto cmcrudPtr = lockWeakPtr(m_cmcrudPtr, "CMCrud Service");
                try
                {
                    cmcrudPtr->deleteNamespace(oldNsId.toStr());
                }
                catch (const std::exception& e)
                {
                    LOG_WARNING("[CM::Sync] Failed to delete old namespace '{}' for space '{}': {}",
                                oldNsId.toStr(),
                                nsState.getOriginSpace(),
                                e.what());
                }
            }

            LOG_INFO("[CM::Sync] Successfully synchronized space '{}'", nsState.getOriginSpace());
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("[CM::Sync] Failed to synchronize namespace for space '{}': {}", nsState.getOriginSpace(), e.what());
        }
    }

    // Dump the updated state to the store
    dumpStateToStore();

    LOG_INFO("[CM::Sync] Finished synchronization of spaces");
}

} // namespace cm::sync
