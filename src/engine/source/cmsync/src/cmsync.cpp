#include <base/logging.hpp>

#include <cmsync/cmsync.hpp>

namespace
{

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

} // namespace

namespace cm::sync
{

/**
 * @brief State of a namespace being synchronized
 */
class NsSyncState
{

public:
    NsSyncState(const cm::store::NamespaceId& nsId, std::string_view originSpace)
        : m_nsId(nsId)
        , m_originSpace(originSpace)
        , m_lastPolicyHash()
    {
    }

    const cm::store::NamespaceId& getNamespaceId() const { return m_nsId; }
    const std::string& getOriginSpace() const { return m_originSpace; }
    const std::string& getLastPolicyHash() const { return m_lastPolicyHash; }
    void setLastPolicyHash(std::string_view hash) { m_lastPolicyHash = hash; }

private:
    cm::store::NamespaceId m_nsId; ///< Namespace identifier
    std::string m_originSpace;     ///< Origin space in the indexer
    std::string m_lastPolicyHash;  ///< Last known policy hash
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
}

CMSync::~CMSync() = default;

void CMSync::downloadNamespace(std::string_view originSpace, std::string_view destNamespace)
{

    auto indexerPtr = lockWeakPtr(m_indexerPtr, "IndexerConnector");
    auto cmcrudPtr = lockWeakPtr(m_cmcrudPtr, "CMCrudService");

    // Create destination Namespace
    auto destNSId = cm::store::NamespaceId(destNamespace);

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
                LOG_WARNING_L("CMSync::downloadNamespace",
                              "Attempt {}/{}: Failed to get policy for space '{}': {}",
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
        cmcrudPtr->importNamespace(destNSId,
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
            cmcrudPtr->deleteNamespace(destNamespace);
        }
        catch (const std::exception& ex)
        {
            LOG_WARNING_L("CMSync::downloadNamespace",
                          "Failed to rollback namespace '{}' after import failure: {}",
                          destNSId.toStr(),
                          ex.what());
        }
        throw std::runtime_error(fmt::format(
            "[CMSync::downloadNamespace] Failed to store resources in namespace '{}': {}", destNSId.toStr(), e.what()));
    }
}

void CMSync::loadStateFromStore()
{
}

void CMSync::dumpStateToStore()
{
}

void CMSync::syncNamespace(NsSyncState& nsState)
{

    auto indexerPtr = lockWeakPtr(m_indexerPtr, "Indexer Connector");
    auto routerPtr = lockWeakPtr(m_router, "Orchestrator");

    // Get remote policy hash (We suppose the space exists)
    std::string remotePolicyHash = [&]()
    {
        for (std::size_t attempt = 1; attempt <= m_attemps; ++attempt)
        {
            try
            {
                return indexerPtr->getPolicyHash(nsState.getOriginSpace());
            }
            catch (const std::exception& e)
            {
                LOG_WARNING_L("CMSync::syncNamespace",
                              "Attempt {}/{}: Failed to get policy hash for space '{}': {}",
                              attempt,
                              m_attemps,
                              nsState.getOriginSpace(),
                              e.what());
                if (attempt < m_attemps)
                    std::this_thread::sleep_for(std::chrono::seconds(m_waitSeconds));
                else
                    throw;
            }
        }
        throw std::runtime_error("Unreachable code in CMSync::syncNamespace");
    }();

    bool needSync = (remotePolicyHash != nsState.getLastPolicyHash());
    if (!needSync)
    {
        LOG_DEBUG_L("CMSync::syncNamespace",
                      "Namespace '{}' is up to date, no synchronization needed.",
                      nsState.getNamespaceId().toStr());
        return;
    }

    LOG_INFO_L("CMSync::syncNamespace",
               "Synchronizing space '{}' into namespace '{}'.",
               nsState.getOriginSpace(),
               nsState.getNamespaceId().toStr());

    // Create a temporary namespace
    std::string tempNamespace = nsState.getNamespaceId().toStr() + "_cmsync_tmp";
    downloadNamespace(nsState.getOriginSpace(), tempNamespace);

    // [OUTPUTS]: Add extra assets to the temporary namespace
    // TODO

    // [FILTERS]: Add extra assets to the temporary namespace
    // TODO

    // [INTEGRATIONS]: Add extra assets to the temporary namespace
    // TODO

    // Try create to create a temporary disable entry in router
    // TODO

    // Swap routes to the temporary namespace
    // TODO

    // Update last policy hash
    // TODO

    // Dump state to store
    // TODO

    // Cleanup old routes and temporary namespace
    // TODO

}

} // namespace cm::sync
