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
 * @return std::pair<base::Name, json::Json> The filter name and json with the filter definition
 */
std::pair<base::Name, json::Json> createAllowAllFilter()
{
    return {base::Name {"filter/allow-all/0"},
            []()
            {
                json::Json filter {};
                filter.setString("filter/allow-all/0", "name");
                filter.setString(base::utils::generators::generateUUIDv4(), "id");
                return filter;
            }()};
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

public:
    NsSyncState() = delete;
    explicit NsSyncState(std::string_view originSpace)
        : m_originSpace(originSpace)
        , m_lastPolicyHash()
        , m_routeName(generateRouteName(originSpace))
        , m_nsId(generateNamespaceId(originSpace))
    {
    }

    const std::string& getOriginSpace() const { return m_originSpace; }
    const std::string& getLastPolicyHash() const { return m_lastPolicyHash; }
    const cm::store::NamespaceId& getNamespaceId() const { return m_nsId; }
    const std::string& getRouteName() const { return m_routeName; }
    void setLastPolicyHash(std::string_view hash) { m_lastPolicyHash = hash; }
    void setRouteName(std::string_view routeName) { m_routeName = routeName; }
    void setOriginSpace(std::string_view originSpace) { m_originSpace = originSpace; }
    void setNamespaceId(const cm::store::NamespaceId& nsId) { m_nsId = nsId; }
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
            LOG_WARNING_L("CMSync::downloadNamespace",
                          "Failed to rollback namespace '{}' after import failure: {}",
                          dstNamespace.toStr(),
                          ex.what());
        }
        throw std::runtime_error(
            fmt::format("[CMSync::downloadNamespace] Failed to store resources in namespace '{}': {}",
                        dstNamespace.toStr(),
                        e.what()));
    }
}

void CMSync::loadStateFromStore() {}

void CMSync::dumpStateToStore() {}

std::string CMSync::remoteHash(std::string_view space)
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
            LOG_WARNING_L("CMSync::remoteHash",
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
    throw std::runtime_error("Unreachable code in CMSync::remoteHash");
}

cm::store::NamespaceId CMSync::downloadAndEnrichNamespace(std::string_view originSpace)
{

    auto cmcrudPtr = lockWeakPtr(m_cmcrudPtr, "CMCrud Service");

    // Create a temporary namespace
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

    try
    {
        // [KVDB/DECODER/INTEGRATIONS]: Add here any extra assets to the temporary namespace

        // [OUTPUTS]: Add local outputs for the current namespace
        // TODO

        // [FILTERS]: Necesary filter for the route to work
        const auto [allowAllFilterName, allowAllFilter] = createAllowAllFilter();
        cmcrudPtr->upsertResource(newNs.toStr(), cm::store::ResourceType::FILTER, allowAllFilter.str());
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
            LOG_WARNING_L("CMSync::buildNamespace",
                          "Failed to rollback temporary namespace '{}' after asset addition failure: {}",
                          newNs.toStr(),
                          ex.what());
        }
        throw std::runtime_error(fmt::format(
            "[CMSync::buildNamespace] Failed to add extra assets to namespace '{}': {}", newNs.toStr(), e.what()));
    }

    return newNs;
}

} // namespace cm::sync
