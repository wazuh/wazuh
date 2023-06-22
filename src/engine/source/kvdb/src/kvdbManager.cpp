#include <kvdb/kvdbManager.hpp>
#include <logging/logging.hpp>
#include <metrics/metricsManager.hpp>

#include "rocksdb/db.h"
#include "rocksdb/options.h"

#include <filesystem>
#include <fmt/format.h>
#include <fstream>
#include <optional>

namespace kvdbManager
{

KVDBManager::KVDBManager(const KVDBManagerOptions& options,
                         const std::shared_ptr<metricsManager::IMetricsManager>& metricsManager)
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

bool KVDBManager::managerShuttingDown()
{
    return m_isShuttingDown;
}

std::variant<rocksdb::ColumnFamilyHandle*, base::Error> KVDBManager::createColumnFamily(const std::string& name)
{
    rocksdb::ColumnFamilyHandle* cfHandle {nullptr};
    rocksdb::Status s {m_pRocksDB->CreateColumnFamily(rocksdb::ColumnFamilyOptions(), name, &cfHandle)};

    if (s.ok())
    {
        m_mapCFHandles.insert(std::make_pair(name, cfHandle));
        return cfHandle;
    }

    return base::Error {fmt::format("Could not create DB {}, RocksDB Status: {}", name, s.ToString())};
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

        m_mapScopes.insert(std::make_pair<std::string, std::shared_ptr<KVDBScope>>(
            std::string(scopeName),
            std::make_shared<KVDBScope>(this, scopeName)));

        auto& retScope = m_mapScopes[scopeName];
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

    const std::string dbNameFullPath {fmt::format("{}{}", dbStoragePath, m_ManagerOptions.dbName)};

    std::vector<std::string> columnNames;
    auto listStatus = rocksdb::DB::ListColumnFamilies(rocksdb::DBOptions(), dbNameFullPath, &columnNames);

    std::vector<rocksdb::ColumnFamilyDescriptor> cfDescriptors;
    std::vector<rocksdb::ColumnFamilyHandle*> cfHandles;

    rocksdb::Status openStatus;

    if (listStatus.ok())
    {
        for (auto cfName : columnNames)
        {
            auto newDescriptor = rocksdb::ColumnFamilyDescriptor(cfName, rocksdb::ColumnFamilyOptions());
            cfDescriptors.push_back(newDescriptor);
        }

        openStatus = rocksdb::DB::Open(m_rocksDBOptions, dbNameFullPath, cfDescriptors, &cfHandles, &m_pRocksDB);
    }
    else
    {
        openStatus = rocksdb::DB::Open(m_rocksDBOptions, dbNameFullPath, &m_pRocksDB);
    }

    // rocksdb::DB::Open returns two vectors.
    // One with the descriptors containing the names of the DBs. (cfDescriptors)
    // Plus one with the internal handles to the DB. (cfHandles)
    // In this procedure we join these vectors into a map.
    for (int cfDescriptorIndex = 0; cfDescriptorIndex < cfDescriptors.size(); cfDescriptorIndex++)
    {
        m_mapCFHandles.insert(std::make_pair(cfDescriptors[cfDescriptorIndex].name, cfHandles[cfDescriptorIndex]));
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

std::variant<std::shared_ptr<IKVDBHandler>, base::Error> KVDBManager::getKVDBHandler(const std::string& dbName,
                                                                                     const std::string& scopeName)
{
    rocksdb::ColumnFamilyHandle* cfHandle;

    if (m_mapCFHandles.count(dbName))
    {
        cfHandle = m_mapCFHandles[dbName];
    }
    else
    {
        return base::Error {fmt::format("The DB {} not exists.", dbName)};
    }

    auto retHandler = m_kvdbHandlerCollection->getKVDBHandler(m_pRocksDB, cfHandle, dbName, scopeName);
    assert(retHandler);

    return retHandler;
}

void KVDBManager::removeKVDBHandler(const std::string& dbName, const std::string& scopeName)
{
    m_kvdbHandlerCollection->removeKVDBHandler(dbName, scopeName);
}

std::vector<std::string> KVDBManager::listDBs(const bool loaded)
{
    std::vector<std::string> spaces;

    for (auto cf : m_mapCFHandles)
    {
        spaces.push_back(cf.first);
    }

    return spaces;
}

std::optional<base::Error> KVDBManager::deleteDB(const std::string& name)
{
    auto handlersInfo = getKVDBHandlersInfo();

    auto refCount = handlersInfo.count(name);
    if (refCount)
    {
        return base::Error {fmt::format("Could not remove the DB {}. Usage Reference Count: {}.", name, refCount)};
    }

    auto it = m_mapCFHandles.find(name);
    if (it != m_mapCFHandles.end())
    {
        auto cfHandle = it->second;
        auto opStatus = m_pRocksDB->DropColumnFamily(cfHandle);
        if (opStatus.ok())
        {
            m_mapCFHandles.erase(it);
        }
        else
        {
            return base::Error {
                fmt::format("Could not remove the DB {}. RocksDB Status: {}", name, opStatus.ToString())};
        }
    }
    else
    {
        return base::Error {fmt::format("The DB not exists.")};
    }

    return std::nullopt;
}

std::optional<base::Error> KVDBManager::createDB(const std::string& name, const std::string& path)
{
    if (existsDB(name))
    {
        return std::nullopt;
    }

    std::vector<std::tuple<std::string, json::Json>> entries {};

    // Open file and read content
    if (!path.empty())
    {
        // Open file and read content
        std::string contents;
        // TODO: No check the size, the location, the type of file, the permissions it's a
        // security issue. The API should be changed to receive a stream instead of a path
        std::ifstream in(path, std::ios::in | std::ios::binary);
        if (in)
        {
            in.seekg(0, std::ios::end);
            contents.resize(in.tellg());
            in.seekg(0, std::ios::beg);
            in.read(&contents[0], contents.size());
            in.close();
        }
        else
        {
            return base::Error {fmt::format("An error occurred while opening the file '{}'", path.c_str())};
        }

        json::Json jKv;
        try
        {
            jKv = json::Json {contents.c_str()};
        }
        catch (const std::exception& e)
        {
            return base::Error {fmt::format("An error occurred while parsing the JSON file '{}'", path.c_str())};
        }

        if (!jKv.isObject())
        {
            return base::Error {
                fmt::format("An error occurred while parsing the JSON file '{}': JSON is not an object", path.c_str())};
        }

        entries = jKv.getObject().value();
    }

    auto createResult = createColumnFamily(name);

    if (std::holds_alternative<base::Error>(createResult))
    {
        return std::get<base::Error>(createResult);
    }
    auto cfHandle = std::get<rocksdb::ColumnFamilyHandle*>(createResult);

    for (const auto& [key, value] : entries)
    {
        auto status = m_pRocksDB->Put(rocksdb::WriteOptions(), cfHandle, key, value.str());
        if (!status.ok())
        {
            // TODO check error
        }
    }

    return std::nullopt;
}

bool KVDBManager::existsDB(const std::string& name)
{
    return m_mapCFHandles.count(name) > 0;
}

std::map<std::string, kvdbManager::RefInfo> KVDBManager::getKVDBScopesInfo()
{
    // List reverse lookup of getKVDBHandlersInfo. List of scopes and DBs that are using them.
    std::map<std::string, kvdbManager::RefInfo> retValue;

    // Retrieve the list of DBs and scopes that are using them.
    std::map<std::string, kvdbManager::RefInfo> handlersInfo = getKVDBHandlersInfo();

    // Create a temporal map with the reverse lookup indexed by Scope instead of Database.
    std::map<std::string, kvdbManager::RefCounter> refCounterMap;

    // Iterate over the map of DBs and scopes that are using them.
    for (auto& dbEntry : handlersInfo)
    {
        auto dbName = dbEntry.first;
        auto scopesUsingDB = dbEntry.second;

        // Iterate over the scopes that are using thisDB.
        for (auto& scopeEntry : scopesUsingDB)
        {
            std::string scopeName {scopeEntry.first};
            // Get the current refCounter for this scope.
            auto counterMap = refCounterMap[scopeName];

            // Insert number of used DBs in current scope.
            int countDBsUsingScope {scopeEntry.second};
            counterMap.addRef(dbName, countDBsUsingScope);

            // Update the refCounter for this scope.
            refCounterMap[scopeName] = counterMap;
        }
    }

    for (auto& entry : refCounterMap)
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
