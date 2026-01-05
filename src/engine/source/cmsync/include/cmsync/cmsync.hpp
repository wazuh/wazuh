#ifndef _CMSYNC_CMSYNC
#define _CMSYNC_CMSYNC

#include <string>

#include <wiconnector/iwindexerconnector.hpp>
#include <cmcrud/icmcrudservice.hpp>
#include <store/istore.hpp>
#include <router/iapi.hpp>

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
     * @param destNamespace Define the destination namespace in the local store (Must not exist)
     * @throws std::runtime_error on errors.
     */
    void downloadNamespace(std::string_view originSpace, std::string_view destNamespace);

    void loadStateFromStore(); ///< Load sync state from the internal store
    void dumpStateToStore();   ///< Dump sync state to the internal store

    void syncNamespace(NsSyncState& nsState); ///< Sync a single namespace based on its state

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
