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

} // namespace cm::sync
