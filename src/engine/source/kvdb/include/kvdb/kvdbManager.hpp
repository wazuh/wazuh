#ifndef _KVDB_MANAGER_H
#define _KVDB_MANAGER_H

#include <atomic>
#include <filesystem>
#include <map>
#include <mutex>

#include <kvdb/iKVDBHandlerManager.hpp>
#include <kvdb/iKVDBManager.hpp>
#include <kvdb/kvdbHandlerCollection.hpp>
#include <kvdb/kvdbScope.hpp>
#include <kvdb/kvdbSpace.hpp>

#include <utils/baseMacros.hpp>

#include <rocksdb/db.h>
#include <rocksdb/options.h>

namespace metricsManager
{
class IMetricsManager;
class IMetricsScope;
} // namespace metricsManager

namespace kvdbManager
{

constexpr static const char* DEFAULT_CF_NAME {"default"};

/**
 * @brief Options for the KVDBManager.
 *
 */
struct KVDBManagerOptions
{
    std::filesystem::path dbStoragePath;
    std::string dbName;
};

/**
 * @brief KVDBManager Entry Point class.
 *
 */
class KVDBManager final
    : public IKVDBManager
    , public IKVDBHandlerManager
{
    WAZUH_DISABLE_COPY_ASSIGN(KVDBManager);

public:
    /**
     * @brief Construct a new KVDBManager object
     *
     * @param options Options for the KVDBManager.
     * @param metricsManager Pointer to the Metrics Manager.
     */
    KVDBManager(const KVDBManagerOptions& options,
                const std::shared_ptr<metricsManager::IMetricsManager>& metricsManager);

    /**
     * @brief Initialize the KVDBManager.
     * Setup options, filesystem, RocksDB internals, etc.
     *
     */
    void initialize();

    /**
     * @brief Finalize the KVDBManager.
     *
     */
    void finalize();

    /**
     * @copydoc IKVDBManager::getKVDBScope
     *
     */
    std::shared_ptr<IKVDBScope> getKVDBScope(const std::string& scopeName) override;

    /**
     * @copydoc IKVDBManager::getKVDBScopesInfo
     *
     */
    std::map<std::string, RefInfo> getKVDBScopesInfo() override;

    /**
     * @copydoc IKVDBManager::getKVDBHandlersInfo
     *
     */
    std::map<std::string, RefInfo> getKVDBHandlersInfo() override;

    /**
     * @copydoc IKVDBHandlerManager::getKVDBHandler
     *
     */
    std::variant<std::shared_ptr<IKVDBHandler>, base::Error> getKVDBHandler(const std::string& dbName, const std::string& scopeName) override;

    /**
     * @copydoc IKVDBHandlerManager::removeKVDBHandler
     *
     */
    void removeKVDBHandler(const std::string& dbName, const std::string& scopeName) override;

    /**
     * @copydoc IKVDBHandlerManager::skipAutoRemoveEnabled
     *
     */
    bool skipAutoRemoveEnabled() override;

    /**
     * @copydoc IKVDBManager::listDBs
     *
     */
    std::vector<std::string> listDBs(const bool loaded) override;

    /**
     * @copydoc IKVDBManager::deleteDB
     *
     */
    std::variant<bool, base::Error> deleteDB(const std::string& name) override;

    /**
     * @copydoc IKVDBManager::createDB
     *
     */
    std::variant<bool, base::Error> createDB(const std::string& name) override;

    /**
     * @copydoc IKVDBManager::existsDB
     *
     */
    bool existsDB(const std::string& name) override;

private:
    /**
     * @brief Setup RocksDB Options. Populate m_rocksDBOptions with the default values.
     *
     */
    void initializeOptions();

    /**
     * @brief Initialize the Main DB. Setup Filesystem, open RocksDB, create initial maps.
     *
     */
    void initializeMainDB();

    /**
     * @brief Finalize the Main DB. Close RocksDB, destroy maps.
     *
     */
    void finalizeMainDB();

    /**
     * @brief Custom Collection Object to wrap maps, searchs, references, related to handlers and scopes.
     *
     */
    std::unique_ptr<KVDBHandlerCollection> m_kvdbHandlerCollection;

    // TODO: Check if this is needed and possibly hide the handlers methods with another interface.
    friend class kvdbManager::KVDBScope;

    /**
     * @brief Pointer to the Metrics Manager through MetricsScope.
     *
     */
    std::shared_ptr<metricsManager::IMetricsScope> m_spMetricsScope;

    /**
     * @brief Collection of DB Scopes. Scopes are identifiers for users of db.
     *
     */
    std::map<std::string, std::shared_ptr<KVDBScope>> m_mapScopes;

    /**
     * @brief Create a Column Family object and store in map.
     *
     * @param name Name of the DB -> mapped to Column Family.
     * @return std::variant<rocksdb::ColumnFamilyHandle*, base::Error> Column Family Handle or specific error.
     */
    std::variant<rocksdb::ColumnFamilyHandle*, base::Error> createColumnFamily(const std::string& name);

    /**
     * @brief Options the Manager was built with.
     *
     */
    KVDBManagerOptions m_ManagerOptions;

    /**
     * @brief Internal representation of RocksDB Options.
     *
     */
    rocksdb::Options m_rocksDBOptions;

    /**
     * @brief Internal rocksdb::DB object. This is the main object through which all operations are done.
     *
     */
    rocksdb::DB* m_pRocksDB;

    /**
     * @brief Internal map of Column Family Handles.
     * This is the loaded CFs or KVDBs.
     *
     */
    std::map<std::string, rocksdb::ColumnFamilyHandle*> m_mapCFHandles;

    /**
     * @brief Syncronization object for Scopes Collection (m_mapScopes).
     *
     */
    std::mutex m_mutexScopes;

    // TODO: Check lock of functions where these states are changed/checked. Maybe use mutex to increase guard scope.
    /**
     * @brief Flag bool variable to indicate if the Manager is initialized.
     *
     */

    std::atomic<bool> m_isInitialized {false};

    // TODO: Check lock of functions where these states are changed/checked. Maybe use mutex to increase guard scope.
    /**
     * @brief Flag bool variable to indicate if the Manager is shutting down.
     *
     */
    std::atomic<bool> m_isShuttingDown {false};
};

} // namespace kvdbManager

#endif // _KVDB_MANAGER_H
