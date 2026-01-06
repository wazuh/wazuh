#ifndef _CMSYNC_CMSYNC
#define _CMSYNC_CMSYNC

#include <string>

#include <cmcrud/icmcrudservice.hpp>
#include <router/iapi.hpp>
#include <store/istore.hpp>
#include <wiconnector/iwindexerconnector.hpp>

#include <cmsync/icmsync.hpp>

namespace cm::sync
{

// Forward declarations for config sync
class NsSyncState;

class CMSync : public ICMSync
{

private:
    std::weak_ptr<wiconnector::IWIndexerConnector> m_indexerPtr; ///< Indexer connector resource
    std::weak_ptr<cm::crud::ICrudService> m_cmcrudPtr;           ///< Resource namespace handler
    std::weak_ptr<::store::IStoreInternal> m_store;              ///< Internal config store
    std::weak_ptr<router::IRouterAPI> m_router;                  ///< Router API for event injection

    std::mutex m_mutex;        ///< Only one sync at a time
    std::size_t m_attemps;     ///< Number of attempts to connect or retry operations before failing
    std::size_t m_waitSeconds; ///< Seconds to wait between attempts

    // std::vector<NsSyncState> m_namespacesState; ///< State of the namespaces being synchronized

    /**
     * @brief Download a full namespace from the indexer to the local cmcrud store
     *
     * @param originSpace Define the source space in the indexer
     * @param dstNamespace Define the destination namespace in the local store (Must not exist)
     * @throws std::runtime_error on errors.
     */
    void downloadNamespace(std::string_view originSpace, const cm::store::NamespaceId& dstNamespace);

    /**
     * @brief Get remote policy hash for a space
     *
     * @param space Space name in the indexer
     * @return std::string SHA-256 hash of the policy
     * @throws std::runtime_error on errors.
     */
    std::string remoteHash(std::string_view space);

    /**
     * @brief Downloads a namespace from the indexer and enriches it with local assets
     *
     * This method performs a two-phase operation to prepare a complete namespace:
     * 1. Downloads the policy and resources from the remote indexer (KVDB, decoders, integrations, policy)
     * 2. Enriches the namespace with local-only assets (outputs, filters, etc.)
     *
     * The method generates a unique temporary namespace ID to avoid conflicts and performs
     * automatic rollback on failure, ensuring the local store remains consistent.
     *
     * @param originSpace The source space name in the wazuh-indexer to download from
     * @return cm::store::NamespaceId The newly created namespace ID in the local store,
     * @throws std::runtime_error if any step of the process fails
     * @warning There is no ganrantee that the returned namespace is valid, should be verified by the router.
     * @note If the operation fails at any point, the temporary namespace is automatically deleted
     *       to maintain store consistency
     */
    cm::store::NamespaceId downloadAndEnrichNamespace(std::string_view originSpace);

    void loadStateFromStore(); ///< Load sync state from the internal store
    void dumpStateToStore();   ///< Dump sync state to the internal store

public:
    CMSync() = delete;
    CMSync(const std::shared_ptr<wiconnector::IWIndexerConnector>& indexerPtr,
           const std::shared_ptr<cm::crud::ICrudService>& cmcrudPtr,
           const std::shared_ptr<::store::IStoreInternal>& storePtr,
           const std::shared_ptr<router::IRouterAPI>& routerPtr);
    ~CMSync() override;
};

} // namespace cm::sync

#endif // _CMSYNC_CMSYNC
