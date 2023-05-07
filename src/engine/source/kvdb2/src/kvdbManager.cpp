#include <kvdb2/kvdbManager.hpp>
#include <kvdb2/kvdbExcept.hpp>
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

void KVDBManager::initialize()
{
    initializeOptions();
    initializeMainDB();
    m_isInitialized = true;
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

void KVDBManager::initializeOptions()
{
    m_rocksDBOptions = rocksdb::Options();
    m_rocksDBOptions.IncreaseParallelism();
    m_rocksDBOptions.OptimizeLevelStyleCompaction();
    m_rocksDBOptions.create_if_missing = true;
}

void KVDBManager::initializeMainDB()
{
    rocksdb::Status s = rocksdb::DB::Open(m_rocksDBOptions, m_ManagerOptions.dbName, &m_pRocksDB);
    assert(s.ok());
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
