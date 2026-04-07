#ifndef IOCSYNC_IOCSYNC_HPP
#define IOCSYNC_IOCSYNC_HPP

#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <iockvdb/iManager.hpp>
#include <store/istore.hpp>
#include <wiconnector/iwindexerconnector.hpp>

#include <iocsync/iiocsync.hpp>

namespace ioc::sync
{

// Forward declarations, state of synchronized IOC database
class SyncedIOCDatabase;

class IocSync : public IIocSync
{

private:
    std::weak_ptr<wiconnector::IWIndexerConnector> m_indexerPtr; ///< Indexer connector resource
    std::weak_ptr<ioc::kvdb::IKVDBManager> m_kvdbiocManagerPtr;  ///< KVDB IOC manager
    std::weak_ptr<::store::IStore> m_store;                      ///< Internal config store

    std::size_t m_attempts;         ///< Number of attempts to connect or retry operations before failing
    std::size_t m_waitSeconds;      ///< Seconds to wait between attempts
    std::size_t m_iocSyncBatchSize; ///< Number of documents to retrieve per batch from indexer during sync

    mutable std::shared_mutex m_mutex; ///< Mutex to protect access to m_databasesState and sync operations
    std::vector<SyncedIOCDatabase> m_databasesState; ///< State of the IOC databases being synchronized

    /**
     * @brief Check if IOC data index exists in wazuh-indexer
     *
     * @return true if the IOC index exists, false otherwise
     * @throws std::runtime_error on errors.
     */
    bool existIocDataInRemote();

    /**
     * @brief Get remote per-type hashes from special IOC hashes document.
     *
     * @return Map(type -> hash)
     * @throws std::runtime_error on errors.
     */
    std::unordered_map<std::string, std::string> getRemoteHashesFromRemote();

    /**
     * @brief Download IOCs from indexer and populate a KVDB database
     *
     * This method delegates IOC retrieval to the indexer connector for the
     * requested type and stores each key/value IOC entry in KVDB.
     *
     * @param iocType IOC type to filter (e.g., connection, url_domain, url_full, hash_md5, hash_sha1, hash_sha256)
     * @param dbName Database name in kvdbioc to populate
     * @throws std::runtime_error on errors.
     */
    void downloadAndPopulateDB(std::string_view iocType, const std::string& dbName);

    /**
     * @brief Synchronize a single IOC type
     *
     * @param dbState State of the IOC database to synchronize
     * @param remoteTypeHashes Map of remote type hashes
     * @param kvdbiocPtr KVDB IOC manager shared pointer
     * @return true if state was changed (sync was successful), false otherwise
     */
    bool syncIOCType(SyncedIOCDatabase& dbState,
                     const std::unordered_map<std::string, std::string>& remoteTypeHashes,
                     const std::shared_ptr<ioc::kvdb::IKVDBManager>& kvdbiocPtr);

    void addIOCTypeToSync(std::string_view iocType);      ///< Add an IOC type to the sync list
    void removeIOCTypeFromSync(std::string_view iocType); ///< Remove an IOC type from the sync list

    void loadStateFromStore(); ///< Load sync state from the internal store
    void saveStateToStore();   ///< Save sync state to the internal store

public:
    IocSync() = delete;

    /**
     * @brief Construct a new Ioc Sync object
     *
     * @param indexerPtr Pointer to the indexer connector resource, used to retrieve IOC data and hashes from the remote
     * indexer
     * @param kvdbiocManagerPtr Pointer to the KVDB IOC manager, used to create and manage IOC databases
     * @param storePtr Pointer to the internal config store
     * @param maxRetries Maximum number of attempts to connect or retry operations before failing
     * @param retryIntervalSeconds Seconds to wait between attempts
     * @param iocSyncBatchSize Number of documents to retrieve per batch from indexer during sync
     */
    IocSync(const std::shared_ptr<wiconnector::IWIndexerConnector>& indexerPtr,
            const std::shared_ptr<ioc::kvdb::IKVDBManager>& kvdbiocManagerPtr,
            const std::shared_ptr<::store::IStore>& storePtr,
            const size_t maxRetries,
            const size_t retryIntervalSeconds,
            const size_t iocSyncBatchSize);
    ~IocSync() override;

    /**
     * @copydoc IIocSync::synchronize
     */
    void synchronize() override;
};

} // namespace ioc::sync

#endif // IOCSYNC_IOCSYNC_HPP
