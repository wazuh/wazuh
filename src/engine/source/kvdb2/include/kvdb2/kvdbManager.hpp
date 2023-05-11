#ifndef _KVDBMANAGER_H
#define _KVDBMANAGER_H

#include <filesystem>
#include <map>
#include <mutex>

#include <kvdb2/iKVDBManager.hpp>
#include <kvdb2/iKVDBHandlerManager.hpp>
#include <kvdb2/kvdbScope.hpp>
#include <kvdb2/kvdbSpace.hpp>
#include <kvdb2/kvdbHandlerCollection.hpp>

#include <utils/baseMacros.hpp>

#include <rocksdb/db.h>
#include <rocksdb/options.h>

namespace metricsManager
{
    class IMetricsManager;
    class IMetricsScope;
}

namespace kvdbManager
{

struct KVDBManagerOptions
{
    std::filesystem::path dbStoragePath;
    std::string dbName;
};

/**
 * @brief KVDBManager Entry Point class.
 *
 */
class KVDBManager final : public IKVDBManager, public IKVDBHandlerManager
{
    WAZUH_DISABLE_COPY_ASSIGN(KVDBManager);

public:
    KVDBManager(const KVDBManagerOptions& options, const std::shared_ptr<metricsManager::IMetricsManager>& metricsManager);
    ~KVDBManager() = default;

    void initialize();
    void finalize();

    std::shared_ptr<IKVDBScope> getKVDBScope(const std::string& scopeName) override;
    std::shared_ptr<IKVDBHandler> getKVDBHandler(const std::string& dbName, const std::string& scopeName) override;
    void removeKVDBHandler(const std::string& dbName, const std::string& scopeName) override;

private:
    /**
     * @brief Setup RocksDB Options. Populate m_rocksDBOptions with the default values.
     *
     */
    void initializeOptions();
    void initializeMainDB();
    void finalizeMainDB();

    std::unique_ptr<KVDBHandlerCollection> m_kvdbHandlerCollection;

    friend class kvdbManager::KVDBScope;

    std::shared_ptr<metricsManager::IMetricsScope> m_spMetricsScope;

    std::map<std::string, std::shared_ptr<KVDBScope>> m_mapScopes;


    KVDBManagerOptions m_ManagerOptions;

    rocksdb::Options m_rocksDBOptions;
    rocksdb::DB* m_pRocksDB;

    std::map<std::string, rocksdb::ColumnFamilyHandle*> m_mapCFHandles;

    std::mutex m_mutexScopes;

    bool m_isInitialized { false };
    bool m_isDBLoaded { false };
};

} // namespace kvdbManager


#endif // _KVDBMANAGER_H
