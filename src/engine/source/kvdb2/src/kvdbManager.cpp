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

void KVDBManager::finalize()
{
    finalizeMainDB();
    m_isInitialized = false;
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
    std::vector<std::string> columnNames;

    auto dbPath = fmt::format("{}{}", m_ManagerOptions.dbStoragePath.string(), m_ManagerOptions.dbName);

    auto listStatus = rocksdb::DB::ListColumnFamilies(rocksdb::DBOptions(), dbPath, &columnNames);

    if (listStatus.ok())
    {
        for (auto cfName : columnNames)
        {
            auto newDescriptor = rocksdb::ColumnFamilyDescriptor(cfName, rocksdb::ColumnFamilyOptions());
            m_cfDescriptors.push_back(newDescriptor);
        }
    }

    auto openStatus = rocksdb::DB::Open(m_rocksDBOptions, dbPath, m_cfDescriptors, &m_cfHandles, &m_pRocksDB);

    for (int k=0; k<columnNames.size(); k++)
    {
        m_mapCFHandles.insert(std::make_pair(columnNames[k], m_cfHandles[k]));
    }

    assert(openStatus.ok());
}

void KVDBManager::finalizeMainDB()
{
    rocksdb::Status s;

    for (auto handle : this->m_cfHandles)
    {
        s = this->m_pRocksDB->DestroyColumnFamilyHandle(handle);
        assert(s.ok());
    }

    s = m_pRocksDB->Close();
    assert(s.ok());
    delete m_pRocksDB;
}

std::shared_ptr<IKVDBHandler> KVDBManager::getKVDBHandler(const std::string& dbName, const std::string& scopeName)
{
    rocksdb::ColumnFamilyHandle* cfHandle = nullptr;
    std::shared_ptr<IKVDBHandler> result = nullptr;

    if (m_mapCFHandles.count(dbName))
    {
        cfHandle = m_mapCFHandles[dbName];
    }
    else
    {
        rocksdb::Status s = this->m_pRocksDB->CreateColumnFamily(rocksdb::ColumnFamilyOptions(), dbName, &cfHandle);
        assert(s.ok());

        auto newDescriptor = rocksdb::ColumnFamilyDescriptor(dbName, rocksdb::ColumnFamilyOptions());
        m_cfDescriptors.push_back(newDescriptor);

        this->m_cfHandles.push_back(cfHandle);
        m_mapCFHandles.insert(std::make_pair(dbName, cfHandle));
    }

    result = m_kvdbHandlerCollection->getKVDBHandler(cfHandle, dbName, scopeName);

    return result;
}

void KVDBManager::removeKVDBHandler(const std::string& dbName, const std::string& scopeName)
{
    //TODO: check cfhandler is use for other scope
    this->m_cfHandles.erase(std::remove_if(this->m_cfHandles.begin(),
                                           this->m_cfHandles.end(),
                                           [&](auto const& cf)
                                           { return cf->GetName() == dbName; }));

    m_kvdbHandlerCollection->removeKVDBHandler(dbName, scopeName);
}
} // namespace kvdbManager
