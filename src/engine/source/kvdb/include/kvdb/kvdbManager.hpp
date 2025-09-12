#ifndef _KVDB_MANAGER_H
#define _KVDB_MANAGER_H

#include <atomic>
#include <filesystem>
#include <map>
#include <mutex>

#include <rocksdb/db.h>
#include <rocksdb/options.h>

#include <base/error.hpp>

#include <kvdb/ikvdbmanager.hpp>
#include <kvdb/kvdbHandler.hpp>
#include <kvdb/kvdbHandlerCollection.hpp>

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
class KVDBManager final : public IKVDBManager
{
public:
    KVDBManager(const KVDBManager&) = delete;
    KVDBManager(KVDBManager&&) = delete;
    const KVDBManager& operator=(const KVDBManager&) = delete;
    void operator=(KVDBManager&&) = delete;

    /**
     * @brief Construct a new KVDBManager object
     *
     * @param options Options for the KVDBManager.
     */
    KVDBManager(const KVDBManagerOptions& options);

    /**
     * @copydoc IKVDBManager::initialize
     *
     */
    void initialize() override;

    /**
     * @copydoc IKVDBManager::finalize
     *
     */
    void finalize() override;

    /**
     * @copydoc IKVDBManager::getKVDBScopesInfo
     *
     */
    std::map<std::string, RefInfo> getKVDBScopesInfo() override;

    /**
     * @copydoc IKVDBManager::getKVDBHandlersInfo
     *
     */
    std::map<std::string, RefInfo> getKVDBHandlersInfo() const override;

    /**
     * @copydoc IKVDBManager::getKVDBHandlersCount
     *
     */
    uint32_t getKVDBHandlersCount(const std::string& dbName) const override;

    /**
     * @copydoc IKVDBManager::getKVDBHandler
     *
     */
    base::RespOrError<std::shared_ptr<IKVDBHandler>> getKVDBHandler(const std::string& dbName,
                                                                    const std::string& scopeName) override;

    /**
     * @copydoc IKVDBManager::listDBs
     *
     */
    std::vector<std::string> listDBs(const bool loaded) override;

    /**
     * @copydoc IKVDBManager::deleteDB
     *
     */
    base::OptError deleteDB(const std::string& name) override;

    /**
     * @copydoc IKVDBManager::createDB
     *
     */
    base::OptError createDB(const std::string& name) override;

    /**
     * @copydoc IKVDBManager::createDB
     *
     */
    base::OptError createDB(const std::string& name, const std::string& path) override;

    /**
     * @copydoc IKVDBManager::loadDBFromJson
     *
     */
    base::OptError loadDBFromJson(const std::string& name, const json::Json& content) override;

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
     * @brief Get the content of a json file
     *
     * @param path Path of the json file.
     * @return base::RespOrError<json::Json> A json document or specific error.
     */
    base::RespOrError<json::Json> getContentFromJsonFile(const std::string& path);

    /**
     * @brief Create a Shared Column Family Shared Pointer with custom delete function.
     *
     * @param cfRawPtr Raw pointer to the Column Family Handle.
     * @return std::shared_ptr<rocksdb::ColumnFamilyHandle> Shared Pointer to the Column Family Handle.
     */
    std::shared_ptr<rocksdb::ColumnFamilyHandle> createSharedCFHandle(rocksdb::ColumnFamilyHandle* cfRawPtr);

    /**
     * @brief Custom Collection Object to wrap maps, searchs, references, related to handlers and scopes.
     *
     */
    std::shared_ptr<KVDBHandlerCollection> m_kvdbHandlerCollection;

    /**
     * @brief Create a Column Family object and store in map.
     *
     * @param name Name of the DB -> mapped to Column Family.
     * @return base::OptError Specific error.
     */
    base::OptError createColumnFamily(const std::string& name);

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
    std::shared_ptr<rocksdb::DB> m_pRocksDB;
    /**
     * @brief Internal map of Column Family Handles.
     * This is the loaded CFs or KVDBs.
     *
     */
    std::map<std::string, std::shared_ptr<rocksdb::ColumnFamilyHandle>> m_mapCFHandles;

    /**
     * @brief Default Column Family Handle
     *
     */
    std::shared_ptr<rocksdb::ColumnFamilyHandle> m_pDefaultCFHandle;

    /**
     * @brief Syncronization object for Scopes Collection (m_mapScopes).
     *
     */
    std::mutex m_mutexScopes;

    // TODO: Check lock of functions where these states are changed/checked.
    /**
     * @brief Flag bool variable to indicate if the Manager is initialized.
     *
     */
    std::atomic<bool> m_isInitialized {false};
};

} // namespace kvdbManager

#endif // _KVDB_MANAGER_H
