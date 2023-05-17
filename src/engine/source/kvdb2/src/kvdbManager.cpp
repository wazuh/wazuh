#include <kvdb2/kvdbManager.hpp>
#include <kvdb2/kvdbExcept.hpp>
#include <logging/logging.hpp>
#include <metrics/metricsManager.hpp>

#include "rocksdb/db.h"
#include "rocksdb/options.h"

#include <fmt/format.h>
#include <optional>

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
    m_isShuttingDown = false;
    m_isInitialized = true;
}

void KVDBManager::finalize()
{
    m_isShuttingDown = true;
    finalizeMainDB();
    m_isInitialized = false;
}

bool KVDBManager::skipAutoRemoveEnabled()
{
    return m_isShuttingDown;
}

rocksdb::ColumnFamilyHandle* KVDBManager::createColumnFamily(const std::string& name)
{
    rocksdb::ColumnFamilyHandle* cfHandle;
    rocksdb::Status s = m_pRocksDB->CreateColumnFamily(rocksdb::ColumnFamilyOptions(), name, &cfHandle);

    if (s.ok())
    {
        m_mapCFHandles.insert(std::make_pair(name, cfHandle));
        return cfHandle;
    }
    else
    {
        return nullptr;
    }
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
    auto dbStoragePath = m_ManagerOptions.dbStoragePath.string();

    std::filesystem::create_directories(dbStoragePath);

    auto dbNameFullPath = fmt::format("{}{}", dbStoragePath, m_ManagerOptions.dbName);

    std::vector<std::string> columnNames;
    auto listStatus = rocksdb::DB::ListColumnFamilies(rocksdb::DBOptions(), dbNameFullPath, &columnNames);

    std::vector<rocksdb::ColumnFamilyDescriptor> cfDescriptors;
    std::vector<rocksdb::ColumnFamilyHandle*> cfHandles;

    if (listStatus.ok())
    {
        for (auto cfName : columnNames)
        {
            auto newDescriptor = rocksdb::ColumnFamilyDescriptor(cfName, rocksdb::ColumnFamilyOptions());
            cfDescriptors.push_back(newDescriptor);
        }
    }
    else
    {
        auto newDescriptor = rocksdb::ColumnFamilyDescriptor(rocksdb::kDefaultColumnFamilyName, rocksdb::ColumnFamilyOptions());
        cfDescriptors.push_back(newDescriptor);
    }

    auto openStatus = rocksdb::DB::Open(m_rocksDBOptions, dbNameFullPath, cfDescriptors, &cfHandles, &m_pRocksDB);

    for (int k = 0; k<cfDescriptors.size(); k++)
    {
        m_mapCFHandles.insert(std::make_pair(cfDescriptors[k].name, cfHandles[k]));
    }

    assert(openStatus.ok());
    assert(m_pRocksDB);
}

void KVDBManager::finalizeMainDB()
{
    rocksdb::Status opStatus;

    for (auto entry : m_mapCFHandles)
    {
        auto cfHandle = entry.second;
        opStatus = m_pRocksDB->DestroyColumnFamilyHandle(cfHandle);
        assert(opStatus.ok());
    }

    m_mapCFHandles.clear();

    opStatus = m_pRocksDB->Close();
    assert(opStatus.ok());

    delete m_pRocksDB;
}

KVDBHandler KVDBManager::getKVDBHandler(const std::string& dbName, const std::string& scopeName)
{
    rocksdb::ColumnFamilyHandle* cfHandle;

    if (m_mapCFHandles.count(dbName))
    {
        cfHandle = m_mapCFHandles[dbName];
    }
    else
    {
        cfHandle = createColumnFamily(dbName);
        assert(cfHandle);
    }

    auto retHandler = m_kvdbHandlerCollection->getKVDBHandler(m_pRocksDB, cfHandle, dbName, scopeName);
    assert(retHandler);

    return retHandler;
}

void KVDBManager::removeKVDBHandler(const std::string& dbName, const std::string& scopeName)
{
    bool isRemoved = false;
    m_kvdbHandlerCollection->removeKVDBHandler(dbName, scopeName, isRemoved);
    if (isRemoved && m_mapCFHandles.size())
    {
        auto cfHandle = m_mapCFHandles[dbName];
        assert(cfHandle);
        rocksdb::Status s = m_pRocksDB->DestroyColumnFamilyHandle(cfHandle);
        assert(s.ok());
        m_mapCFHandles.erase(dbName);
    }
}

std::vector<std::string> KVDBManager::listDBs(const bool loaded)
{
    // TODO: return handles loaded -> m_kvdbHandlerCollection
    std::vector<std::string> spaces;

    for(auto cf : m_mapCFHandles)
    {
        spaces.push_back(cf.first);
    }

    return spaces;
}

std::optional<base::Error> KVDBManager::deleteDB(const std::string& name)
{
    return base::Error { fmt::format("Not yet implemented.") };
}

std::optional<base::Error> KVDBManager::createDB(const std::string& name)
{
    auto cfHandle = createColumnFamily(name);

    if (cfHandle != nullptr)
    {
        return std::nullopt;
    }
    else
    {
        return base::Error { fmt::format("Could not create DB.") };
    }
}

std::optional<base::Error> KVDBManager::existsDB(const std::string& name)
{
    if (m_mapCFHandles.count(name))
    {
        return std::nullopt;
    }
    else
    {
        return base::Error { fmt::format("The DB not exists.") };
    }
}

std::map<std::string, kvdbManager::RefInfo> KVDBManager::getKVDBScopesInfo()
{
    // List reverse lookup of getKVDBHandlersInfo. List of scopes and DBs that are using them.
    std::map<std::string, kvdbManager::RefInfo> retValue;
    std::map<std::string, kvdbManager::RefInfo> handlersInfo = getKVDBHandlersInfo();
    std::map<std::string, kvdbManager::RefCounter> refCounterMap;

    for (auto &entry : handlersInfo)
    {
        auto dbName = entry.first;
        auto refInfo = entry.second;

        for (auto &scopeEntry : refInfo )
        {
            std::string scopeName = scopeEntry.first;
            int scopeRefCounter = scopeEntry.second;
            auto counterMap = refCounterMap[scopeName];

            for (int k=0; k<scopeRefCounter; k++)
            {
                counterMap.addRef(dbName);
            }

            refCounterMap[scopeName] = counterMap;
        }
    }

    for (auto &entry : refCounterMap)
    {
        auto scopeName = entry.first;
        auto refCounter = entry.second;
        auto refInfo = refCounter.getRefMap();
        retValue.insert(std::make_pair(scopeName, refInfo));
    }

    return retValue;
}

std::map<std::string, kvdbManager::RefInfo> KVDBManager::getKVDBHandlersInfo()
{
    // List of DBs and the scopes referencing them.
    std::map<std::string, kvdbManager::RefInfo> retValue;
    auto dbNames = m_kvdbHandlerCollection->getDBNames();
    for (auto dbName : dbNames)
    {
        auto refInfo = m_kvdbHandlerCollection->getRefMap(dbName);
        retValue.insert(std::make_pair(dbName, refInfo));
    }
    return retValue;
}

} // namespace kvdbManager
