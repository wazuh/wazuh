#ifndef _IOCSYNC_IOCSYNC_HPP
#define _IOCSYNC_IOCSYNC_HPP

#include <mutex>
#include <shared_mutex>
#include <string>
#include <vector>

#include <kvdbioc/iManager.hpp>
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
    std::weak_ptr<kvdbioc::IKVDBManager> m_kvdbiocManagerPtr;    ///< KVDB IOC manager
    std::weak_ptr<::store::IStore> m_store;                      ///< Internal config store

    std::size_t m_attemps;     ///< Number of attempts to connect or retry operations before failing
    std::size_t m_waitSeconds; ///< Seconds to wait between attempts

    mutable std::shared_mutex m_mutex; ///< Mutex to protect access to m_databasesState and sync operations
    std::vector<SyncedIOCDatabase> m_databasesState; ///< State of the IOC databases being synchronized

    /**
     * @brief Check if an index exists in the wazuh-indexer
     *
     * @param indexName Index name to check
     * @return true if the index exists, false otherwise
     * @throws std::runtime_error on errors.
     */
    bool existIndexInRemote(std::string_view indexName);

    /**
     * @brief Get remote data hash for an IOC type
     *
     * @param iocType IOC type (e.g., ipv4-addr, domain-name, url, file)
     * @return std::string Hash of the data
     * @throws std::runtime_error on errors.
     */
    std::string getDataHashFromRemote(std::string_view iocType);

    /**
     * @brief Download IOCs from indexer and populate a KVDB database
     *
     * This method queries the .cti-iocs index, iterates over the enrichments array
     * in each document, filters by the specified IOC type, extracts enrichments.indicator.name 
     * as the key, and stores each enrichment object as the value.
     *
     * @param iocType IOC type to filter (e.g., ipv4-addr, domain-name, url, file)
     * @param dbName Database name in kvdbioc to populate
     * @throws std::runtime_error on errors.
     */
    void downloadAndPopulateDB(std::string_view iocType, const std::string& dbName);

    void addIOCTypeToSync(std::string_view iocType);      ///< Add an IOC type to the sync list
    void removeIOCTypeFromSync(std::string_view iocType); ///< Remove an IOC type from the sync list

    void loadStateFromStore(); ///< Load sync state from the internal store
    void saveStateToStore();   ///< Save sync state to the internal store

public:
    IocSync() = delete;
    IocSync(const std::shared_ptr<wiconnector::IWIndexerConnector>& indexerPtr,
           const std::shared_ptr<kvdbioc::IKVDBManager>& kvdbiocManagerPtr,
           const std::shared_ptr<::store::IStore>& storePtr);
    ~IocSync() override;

    /**
     * @brief Perform synchronization of all configured IOC databases
     *
     * This method iterates through all IOC types configured for synchronization,
     * checking for updates in the remote indexer. If changes are detected, it
     * downloads the updated IOCs, creates a new database, and performs an atomic
     * hot-swap to ensure readers transparently switch to the new data.
     *
     * Key operations:
     * - Compare local hash vs remote hash for each IOC type
     * - Download full database only if hash has changed
     * - Atomic hot-swap of the active database
     * - Safe cleanup of old database versions
     *
     * @throws std::runtime_error if any step of the synchronization process fails
     */
    void synchronize();
};

} // namespace ioc::sync

#endif // _IOCSYNC_IOCSYNC_HPP