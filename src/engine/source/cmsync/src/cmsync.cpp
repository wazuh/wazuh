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
    auto cmstorePtr = lockWeakPtr(m_cmstorePtr, "CMStore");

    // Helpers
    // Parse JSON resource and throw detailed error on failure
    auto parseJsonResource = [](const std::string& resourceStr, const std::string& resourceType) -> json::Json
    {
        try
        {
            return json::Json(resourceStr.c_str());
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(
                fmt::format("Failed to parse {} JSON: '{}'. Original error: {}", resourceType, resourceStr, e.what()));
        }
    };

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
        throw std::runtime_error("Unreachable code reached in downloadNamespace");
    }();

    // Create destNamespace
    auto nsHandler = cmstorePtr->createNamespace(destNSId);
    auto cleanupDestNS = [&cmstorePtr, &nsHandler, &destNSId]()
    {
        try
        {
            nsHandler.reset();
            cmstorePtr->deleteNamespace(destNSId);
        }
        catch (const std::exception& e)
        {
            LOG_WARNING_L(
                "CMSync::downloadNamespace", "Failed to cleanup namespace '{}': {}", destNSId.toStr(), e.what());
        }
    };

    try
    {
        // Upload resources to destNamespace
        for (const auto& kvdb : policyResource.kvdbs)
        {
            const auto jKVdb = parseJsonResource(kvdb, "KVDB");
            const auto sKVDB = store::dataType::KVDB::fromJson(jKVdb);

            nsHandler->createResource(sKVDB.getName(), cm::store::ResourceType::KVDB, sKVDB.toJson().str());
        }
        for (const auto& decoder : policyResource.decoders)
        {
            const auto jDecoder = parseJsonResource(decoder, "Decoder");
            // Adapt decoder
            // Pass the json.str() directly to createResource
            nsHandler->createResource("", cm::store::ResourceType::DECODER, decoder);
        }
        for (const auto& integration : policyResource.integration)
        {
            const auto jIntegration = parseJsonResource(integration, "Integration");
            const auto sIntegration = store::dataType::Integration::fromJson(jIntegration);
            nsHandler->createResource(
                sIntegration.getName(), cm::store::ResourceType::INTEGRATION, sIntegration.toJson().str());
        }
        // Upload policy
        auto p = store::dataType::Policy::fromJson(parseJsonResource(policyResource.policy, "Policy"));
        nsHandler->upsertPolicy(p);
    }
    catch (const std::exception& e)
    {
        cleanupDestNS();
        throw std::runtime_error(fmt::format(
            "[CMSync::downloadNamespace] Failed to store resources in namespace '{}': {}", destNSId.toStr(), e.what()));
    }
}

} // namespace cm::sync
