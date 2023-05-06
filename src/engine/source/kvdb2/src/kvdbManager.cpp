#include <kvdb2/kvdbManager.hpp>

#include <logging/logging.hpp>
#include <metrics/metricsManager.hpp>

#include "rocksdb/db.h"
#include "rocksdb/options.h"

namespace kvdbManager
{

KVDBManager::KVDBManager(const KVDBManagerOptions& options, const std::shared_ptr<metricsManager::IMetricsManager>& metricsManager)
{
    m_ManagerOptions = options;
    m_spMetricsScope = metricsManager->getMetricsScope("KVDB");
    m_kvdbHandlerCollection = std::make_unique<KVDBHandlerCollection>(this);
}

bool KVDBManager::initialize()
{
    setupRocksDBOptions();
    return createMainDB();
}

std::shared_ptr<IKVDBScope> KVDBManager::getKVDBScope(const std::string& scopeName)
{
    const std::lock_guard<std::mutex> lock(m_mutexScopes);

    auto it = m_mapScopes.find(scopeName);
    if (m_mapScopes.end() != it)
    {
        return it->second;
    }
    else
    {
        LOG_INFO("KVDB Manager: Created new KVDB Scope : ({})", scopeName);

        m_mapScopes.insert(
            std::make_pair<std::string, std::shared_ptr<KVDBScope>>(
                std::string(scopeName),
                std::make_shared<KVDBScope>(this, scopeName)));

        auto& retScope = m_mapScopes[scopeName];

        retScope->initialize();

        return retScope;
    }

    return nullptr;
}

void KVDBManager::setupRocksDBOptions()
{
    m_rocksDBOptions = rocksdb::Options();
    m_rocksDBOptions.IncreaseParallelism();
    m_rocksDBOptions.OptimizeLevelStyleCompaction();
    m_rocksDBOptions.create_if_missing = true;
}

bool KVDBManager::createMainDB()
{
    rocksdb::Status s = rocksdb::DB::Open(m_rocksDBOptions, m_ManagerOptions.dbStoragePath, &m_pRocksDB);
    assert(s.ok());
    return true;
}

std::shared_ptr<IKVDBHandler> KVDBManager::getKVDBHandler(const std::string& dbName, const std::string& scopeName)
{
    return m_kvdbHandlerCollection->getKVDBHandler(dbName, scopeName);
}

void KVDBManager::removeKVDBHandler(const std::string& dbName, const std::string& scopeName)
{
    m_kvdbHandlerCollection->removeKVDBHandler(dbName, scopeName);
}
} // namespace kvdbManager
