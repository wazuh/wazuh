#include <ctistore/ctistoragedb.hpp>

#include <filesystem>
#include <shared_mutex>
#include <stdexcept>
#include <unordered_map>

#include <rocksdb/db.h>
#include <rocksdb/write_batch.h>
#include <rocksdb/filter_policy.h>
#include <rocksdb/table.h>
#include <rocksDBSharedBuffers.hpp>
#include <rocksdb/slice_transform.h>
#include <base/logging.hpp>

namespace cti::store
{

// PIMPL implementation - contains all RocksDB-specific details
struct CTIStorageDB::Impl
{
    // Simple RAII wrapper for RocksDB ColumnFamilyHandle
    class CFHandle
    {
    public:
        CFHandle() = default;

        CFHandle(rocksdb::ColumnFamilyHandle* handle, rocksdb::DB* db)
            : m_handle(handle), m_db(db) {}

        ~CFHandle()
        {
            if (m_handle && m_db) {
                m_db->DestroyColumnFamilyHandle(m_handle);
            }
        }

        // Move only
        CFHandle(const CFHandle&) = delete;
        CFHandle& operator=(const CFHandle&) = delete;

        CFHandle(CFHandle&& other) noexcept
            : m_handle(other.m_handle), m_db(other.m_db)
        {
            other.m_handle = nullptr;
            other.m_db = nullptr;
        }

        CFHandle& operator=(CFHandle&& other) noexcept
        {
            if (this != &other) {
                if (m_handle && m_db) {
                    m_db->DestroyColumnFamilyHandle(m_handle);
                }
                m_handle = other.m_handle;
                m_db = other.m_db;
                other.m_handle = nullptr;
                other.m_db = nullptr;
            }
            return *this;
        }

        rocksdb::ColumnFamilyHandle* get() const { return m_handle; }

    private:
        rocksdb::ColumnFamilyHandle* m_handle = nullptr;
        rocksdb::DB* m_db = nullptr;
    };

    struct ColumnFamilyHandles
    {
        CFHandle metadata;
        CFHandle policy;
        CFHandle integration;
        CFHandle decoder;
        CFHandle kvdb;
    };

    std::unique_ptr<rocksdb::DB> m_db;                          ///< DB handle.
    ColumnFamilyHandles m_cfHandles;                            ///< Column family handles.
    std::shared_ptr<rocksdb::Cache> m_readCache;                ///< Optional shared block cache.
    std::shared_ptr<rocksdb::WriteBufferManager> m_writeManager;///< Optional shared write buffer manager.

    // Thread safety: single-writer, multiple-reader pattern
    mutable std::shared_mutex m_rwMutex;                        ///< Reader-writer mutex for thread safety.

    // Implementation methods
    void initializeColumnFamilies(const std::string& dbPath, bool useSharedBuffers);
    rocksdb::ColumnFamilyHandle* getColumnFamily(CTIStorageDB::ColumnFamily cf) const;

    std::string extractIdFromJson(const json::Json& doc) const;
    std::string extractTitleFromJson(const json::Json& doc) const;
    std::string extractIntegrationIdFromJson(const json::Json& doc) const;

    void storeWithIndex(const json::Json& doc,
                        CTIStorageDB::ColumnFamily cf,
                        const std::string& keyPrefix,
                        const std::string& namePrefix);

    json::Json getByIdOrName(const std::string& identifier,
                             CTIStorageDB::ColumnFamily cf,
                             const std::string& keyPrefix,
                             const std::string& namePrefix) const;

    bool existsByIdOrName(const std::string& identifier,
                          CTIStorageDB::ColumnFamily cf,
                          const std::string& keyPrefix,
                          const std::string& namePrefix) const;

    void updateRelationshipIndexes(const json::Json& integrationDoc);

    std::vector<std::string> getRelatedAssets(const std::string& integrationId,
                                              const std::string& relationshipKey) const;

    // Public API implementations
    void storePolicy(const json::Json& policyDoc);
    void storeIntegration(const json::Json& integrationDoc);
    void storeDecoder(const json::Json& decoderDoc);
    void storeKVDB(const json::Json& kvdbDoc);
    std::vector<base::Name> getAssetList(const std::string& assetType) const;
    json::Json getAsset(const base::Name& name, const std::string& assetType) const;
    bool assetExists(const base::Name& name, const std::string& assetType) const;
    std::vector<std::string> getKVDBList() const;
    std::vector<std::string> getKVDBList(const base::Name& integrationName) const;
    bool kvdbExists(const std::string& kvdbName) const;
    json::Json kvdbDump(const std::string& kvdbName) const;
    std::vector<base::Name> getPolicyIntegrationList() const;
    base::Name getPolicyDefaultParent() const;
    void clearAll();
    size_t getStorageStats(CTIStorageDB::ColumnFamily cf) const;
    bool validateDocument(const json::Json& doc, const std::string& expectedType) const;
};

const std::unordered_map<std::string, CTIStorageDB::ColumnFamily>& CTIStorageDB::getAssetTypeToColumnFamily()
{
    static const std::unordered_map<std::string, ColumnFamily> s_map = {
        {"integration", ColumnFamily::INTEGRATION},
        {"decoder", ColumnFamily::DECODER},
        {"policy", ColumnFamily::POLICY}
    };
    return s_map;
}

const std::unordered_map<std::string, std::string>& CTIStorageDB::getAssetTypeToKeyPrefix()
{
    static const std::unordered_map<std::string, std::string> s_map = {
        {"integration", "integration:"},
        {"decoder", "decoder:"},
        {"policy", "policy:"}
    };
    return s_map;
}

const std::unordered_map<std::string, std::string>& CTIStorageDB::getAssetTypeToNamePrefix()
{
    static const std::unordered_map<std::string, std::string> s_map = {
        {"integration", "name:integration:"},
        {"decoder", "name:decoder:"},
        {"policy", "name:policy:"}
    };
    return s_map;
}

CTIStorageDB::CTIStorageDB(const std::string& dbPath, bool useSharedBuffers)
    : m_pImpl(std::make_unique<Impl>())
{
    try
    {
        m_pImpl->initializeColumnFamilies(dbPath, useSharedBuffers);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error("Failed to initialize CTI Storage Database: " + std::string(e.what()));
    }
}

CTIStorageDB::~CTIStorageDB() = default;

bool CTIStorageDB::isOpen() const
{
    std::shared_lock<std::shared_mutex> lock(m_pImpl->m_rwMutex); // Shared read lock
    return m_pImpl->m_db != nullptr;
}

void CTIStorageDB::Impl::initializeColumnFamilies(const std::string& dbPath, bool useSharedBuffers)
{
    if (useSharedBuffers)
    {
        auto& sharedBuffers = RocksDBSharedBuffers::getInstance();
        m_writeManager = sharedBuffers.getWriteBufferManager();
        m_readCache = sharedBuffers.getReadCache();
    }
    else
    {
        m_readCache = rocksdb::NewLRUCache(32 * 1024 * 1024); // 32MB
        m_writeManager = std::make_shared<rocksdb::WriteBufferManager>(64 * 1024 * 1024, m_readCache);
    }

    rocksdb::BlockBasedTableOptions tableOptions;
    tableOptions.block_cache = m_readCache;
    tableOptions.filter_policy.reset(rocksdb::NewBloomFilterPolicy(10, false));

    rocksdb::Options options;
    options.table_factory.reset(rocksdb::NewBlockBasedTableFactory(tableOptions));
    options.create_if_missing = true;
    options.create_missing_column_families = true;
    options.info_log_level = rocksdb::InfoLogLevel::INFO_LEVEL;
    options.keep_log_file_num = 5;
    options.max_log_file_size = 5 * 1024 * 1024;
    options.recycle_log_file_num = 5;
    options.max_open_files = 32;
    options.write_buffer_manager = m_writeManager;
    options.num_levels = 4;
    options.write_buffer_size = 32 * 1024 * 1024;
    options.max_write_buffer_number = 3;
    options.max_background_jobs = 4;

    std::vector<rocksdb::ColumnFamilyDescriptor> columnFamilies = {
        rocksdb::ColumnFamilyDescriptor(rocksdb::kDefaultColumnFamilyName, options),
        rocksdb::ColumnFamilyDescriptor("metadata", options),
        rocksdb::ColumnFamilyDescriptor("policy", options),
        rocksdb::ColumnFamilyDescriptor("integration", options),
        rocksdb::ColumnFamilyDescriptor("decoder", options),
        rocksdb::ColumnFamilyDescriptor("kvdb", options)
    };

    std::filesystem::create_directories(std::filesystem::path(dbPath));

    rocksdb::DB* db;
    std::vector<rocksdb::ColumnFamilyHandle*> handles;

    auto status = rocksdb::DB::Open(options, dbPath, columnFamilies, &handles, &db);

    if (!status.ok())
    {
        if (status.IsCorruption() || status.IsIOError())
        {
            LOG_WARNING("Database corruption detected, attempting repair: {}", dbPath);
            rocksdb::Options repairOptions;
            auto repairStatus = rocksdb::RepairDB(dbPath, repairOptions);
            if (!repairStatus.ok())
            {
                throw std::runtime_error("Failed to repair corrupted database: " + repairStatus.ToString());
            }

            status = rocksdb::DB::Open(options, dbPath, columnFamilies, &handles, &db);
            if (!status.ok())
            {
                throw std::runtime_error("Failed to open database after repair: " + status.ToString());
            }
            LOG_INFO("Database repaired successfully: {}", dbPath);
        }
        else
        {
            throw std::runtime_error("Failed to open database: " + status.ToString());
        }
    }

    m_db.reset(db);

    if (handles.size() != 6)
    {
        for (auto* handle : handles) { if (handle) delete handle; }
        throw std::runtime_error("Unexpected number of column family handles");
    }

    m_cfHandles.metadata = CFHandle(handles[1], m_db.get());
    m_cfHandles.policy = CFHandle(handles[2], m_db.get());
    m_cfHandles.integration = CFHandle(handles[3], m_db.get());
    m_cfHandles.decoder = CFHandle(handles[4], m_db.get());
    m_cfHandles.kvdb = CFHandle(handles[5], m_db.get());
}

rocksdb::ColumnFamilyHandle* CTIStorageDB::Impl::getColumnFamily(CTIStorageDB::ColumnFamily cf) const
{
    switch (cf)
    {
        case ColumnFamily::METADATA: return m_cfHandles.metadata.get();
        case ColumnFamily::POLICY: return m_cfHandles.policy.get();
        case ColumnFamily::INTEGRATION: return m_cfHandles.integration.get();
        case ColumnFamily::DECODER: return m_cfHandles.decoder.get();
        case ColumnFamily::KVDB: return m_cfHandles.kvdb.get();
    }
    throw std::invalid_argument("Invalid column family");
}

std::string CTIStorageDB::Impl::extractIdFromJson(const json::Json& doc) const
{
    if (doc.exists("/name"))
    {
        return doc.getString("/name").value_or("");
    }
    return "";
}

std::string CTIStorageDB::Impl::extractTitleFromJson(const json::Json& doc) const
{
    if (doc.exists("/payload/title"))
    {
        return doc.getString("/payload/title").value_or("");
    }
    if (doc.exists("/payload/document/title"))
    {
        return doc.getString("/payload/document/title").value_or("");
    }
    return "";
}

std::string CTIStorageDB::Impl::extractIntegrationIdFromJson(const json::Json& doc) const
{
    if (doc.exists("/payload/integration_id"))
    {
        return doc.getString("/payload/integration_id").value_or("");
    }
    return "";
}

void CTIStorageDB::Impl::storeWithIndex(const json::Json& doc,
                                        CTIStorageDB::ColumnFamily cf,
                                        const std::string& keyPrefix,
                                        const std::string& namePrefix)
{
    std::string id = extractIdFromJson(doc);
    std::string title = extractTitleFromJson(doc);

    if (id.empty())
    {
        throw std::invalid_argument("Document missing required 'name' field");
    }

    rocksdb::WriteBatch batch;
    std::string docJson = doc.str();

    batch.Put(getColumnFamily(cf), keyPrefix + id, docJson);

    if (!title.empty())
    {
        batch.Put(getColumnFamily(ColumnFamily::METADATA), namePrefix + title, id);
    }

    auto status = m_db->Write(rocksdb::WriteOptions(), &batch);
    if (!status.ok())
    {
        throw std::runtime_error("Failed to store document: " + status.ToString());
    }
}

void CTIStorageDB::storePolicy(const json::Json& policyDoc)
{
    m_pImpl->storePolicy(policyDoc);
}

void CTIStorageDB::storeIntegration(const json::Json& integrationDoc)
{
    m_pImpl->storeIntegration(integrationDoc);
}

void CTIStorageDB::storeDecoder(const json::Json& decoderDoc)
{
    m_pImpl->storeDecoder(decoderDoc);
}

void CTIStorageDB::storeKVDB(const json::Json& kvdbDoc)
{
    m_pImpl->storeKVDB(kvdbDoc);
}

void CTIStorageDB::Impl::updateRelationshipIndexes(const json::Json& integrationDoc)
{
    std::string integrationId = extractIdFromJson(integrationDoc);
    if (integrationId.empty()) return;

    rocksdb::WriteBatch batch;

    if (integrationDoc.exists("/payload/document/decoders"))
    {
        auto decoders = integrationDoc.getArray("/payload/document/decoders");
        if (decoders)
        {
            json::Json decoderList;
            decoderList.setArray();
            for (const auto& decoder : *decoders)
            {
                if (auto decoderStr = decoder.getString())
                {
                    decoderList.appendString(*decoderStr);
                }
            }
            batch.Put(getColumnFamily(ColumnFamily::METADATA),
                     "idx:integration_decoders:" + integrationId,
                     decoderList.str());
        }
    }

    if (integrationDoc.exists("/payload/document/kvdbs"))
    {
        auto kvdbs = integrationDoc.getArray("/payload/document/kvdbs");
        if (kvdbs)
        {
            json::Json kvdbList;
            kvdbList.setArray();
            for (const auto& kvdb : *kvdbs)
            {
                if (auto kvdbStr = kvdb.getString())
                {
                    kvdbList.appendString(*kvdbStr);
                }
            }
            batch.Put(getColumnFamily(ColumnFamily::METADATA),
                     "idx:integration_kvdbs:" + integrationId,
                     kvdbList.str());
        }
    }

    auto status = m_db->Write(rocksdb::WriteOptions(), &batch);
    if (!status.ok())
    {
        LOG_WARNING("Failed to update relationship indexes for integration {}: {}", integrationId, status.ToString());
    }
}

json::Json CTIStorageDB::Impl::getByIdOrName(const std::string& identifier,
                                             CTIStorageDB::ColumnFamily cf,
                                             const std::string& keyPrefix,
                                             const std::string& namePrefix) const
{
    std::string value;

    auto status = m_db->Get(rocksdb::ReadOptions(), getColumnFamily(cf), keyPrefix + identifier, &value);

    if (!status.ok() && status.IsNotFound())
    {
        std::string actualId;
        status = m_db->Get(rocksdb::ReadOptions(), getColumnFamily(ColumnFamily::METADATA), namePrefix + identifier, &actualId);

        if (status.ok())
        {
            status = m_db->Get(rocksdb::ReadOptions(), getColumnFamily(cf), keyPrefix + actualId, &value);
        }
    }

    if (!status.ok())
    {
        if (status.IsNotFound())
        {
            throw std::runtime_error("Asset not found: " + identifier);
        }
        throw std::runtime_error("Failed to retrieve asset: " + status.ToString());
    }

    try
    {
        return json::Json(value.c_str());
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error("Failed to parse JSON document: " + std::string(e.what()));
    }
}

bool CTIStorageDB::Impl::existsByIdOrName(const std::string& identifier,
                                          CTIStorageDB::ColumnFamily cf,
                                          const std::string& keyPrefix,
                                          const std::string& namePrefix) const
{
    std::string value;

    auto status = m_db->Get(rocksdb::ReadOptions(), getColumnFamily(cf), keyPrefix + identifier, &value);

    if (status.IsNotFound())
    {
        std::string actualId;
        status = m_db->Get(rocksdb::ReadOptions(), getColumnFamily(ColumnFamily::METADATA), namePrefix + identifier, &actualId);

        if (status.ok())
        {
            status = m_db->Get(rocksdb::ReadOptions(), getColumnFamily(cf), keyPrefix + actualId, &value);
        }
    }

    return status.ok();
}

std::vector<base::Name> CTIStorageDB::getAssetList(const std::string& assetType) const
{
    return m_pImpl->getAssetList(assetType);
}

json::Json CTIStorageDB::getAsset(const base::Name& name, const std::string& assetType) const
{
    return m_pImpl->getAsset(name, assetType);
}

bool CTIStorageDB::assetExists(const base::Name& name, const std::string& assetType) const
{
    return m_pImpl->assetExists(name, assetType);
}

std::vector<std::string> CTIStorageDB::getKVDBList() const
{
    return m_pImpl->getKVDBList();
}

std::vector<std::string> CTIStorageDB::getKVDBList(const base::Name& integrationName) const
{
    return m_pImpl->getKVDBList(integrationName);
}

std::vector<std::string> CTIStorageDB::Impl::getRelatedAssets(const std::string& integrationId, const std::string& relationshipKey) const
{
    std::string value;
    auto status = m_db->Get(rocksdb::ReadOptions(), getColumnFamily(ColumnFamily::METADATA), relationshipKey + integrationId, &value);

    if (!status.ok())
    {
        return {};
    }

    try
    {
        json::Json assetList(value.c_str());
        std::vector<std::string> result;

        if (assetList.isArray())
        {
            auto array = assetList.getArray();
            if (array)
            {
                for (const auto& item : *array)
                {
                    if (auto itemStr = item.getString())
                    {
                        result.push_back(*itemStr);
                    }
                }
            }
        }

        return result;
    }
    catch (const std::exception&)
    {
        return {};
    }
}

bool CTIStorageDB::kvdbExists(const std::string& kvdbName) const
{
    return m_pImpl->kvdbExists(kvdbName);
}

json::Json CTIStorageDB::kvdbDump(const std::string& kvdbName) const
{
    return m_pImpl->kvdbDump(kvdbName);
}

std::vector<base::Name> CTIStorageDB::getPolicyIntegrationList() const
{
    return m_pImpl->getPolicyIntegrationList();
}

base::Name CTIStorageDB::getPolicyDefaultParent() const
{
    return m_pImpl->getPolicyDefaultParent();
}

void CTIStorageDB::clearAll()
{
    m_pImpl->clearAll();
}

size_t CTIStorageDB::getStorageStats(ColumnFamily cf) const
{
    return m_pImpl->getStorageStats(cf);
}

bool CTIStorageDB::validateDocument(const json::Json& doc, const std::string& expectedType) const
{
    return m_pImpl->validateDocument(doc, expectedType);
}

// Impl method implementations
void CTIStorageDB::Impl::storePolicy(const json::Json& policyDoc)
{
    std::unique_lock<std::shared_mutex> lock(m_rwMutex); // Exclusive write lock
    if (!validateDocument(policyDoc, "policy"))
    {
        throw std::invalid_argument("Invalid policy document format");
    }
    storeWithIndex(policyDoc, CTIStorageDB::ColumnFamily::POLICY, "policy:", "name:policy:");
}

void CTIStorageDB::Impl::storeIntegration(const json::Json& integrationDoc)
{
    std::unique_lock<std::shared_mutex> lock(m_rwMutex); // Exclusive write lock
    if (!validateDocument(integrationDoc, "integration"))
    {
        throw std::invalid_argument("Invalid integration document format");
    }
    storeWithIndex(integrationDoc, CTIStorageDB::ColumnFamily::INTEGRATION, "integration:", "name:integration:");
    updateRelationshipIndexes(integrationDoc);
}

void CTIStorageDB::Impl::storeDecoder(const json::Json& decoderDoc)
{
    std::unique_lock<std::shared_mutex> lock(m_rwMutex); // Exclusive write lock
    if (!validateDocument(decoderDoc, "decoder"))
    {
        throw std::invalid_argument("Invalid decoder document format");
    }
    storeWithIndex(decoderDoc, CTIStorageDB::ColumnFamily::DECODER, "decoder:", "name:decoder:");
}

void CTIStorageDB::Impl::storeKVDB(const json::Json& kvdbDoc)
{
    std::unique_lock<std::shared_mutex> lock(m_rwMutex); // Exclusive write lock
    if (!validateDocument(kvdbDoc, "kvdb"))
    {
        throw std::invalid_argument("Invalid KVDB document format");
    }
    storeWithIndex(kvdbDoc, CTIStorageDB::ColumnFamily::KVDB, "kvdb:", "name:kvdb:");
}

std::vector<base::Name> CTIStorageDB::Impl::getAssetList(const std::string& assetType) const
{
    std::shared_lock<std::shared_mutex> lock(m_rwMutex); // Shared read lock

    auto cfIt = CTIStorageDB::getAssetTypeToColumnFamily().find(assetType);
    if (cfIt == CTIStorageDB::getAssetTypeToColumnFamily().end())
    {
        throw std::invalid_argument("Invalid asset type: " + assetType);
    }

    auto keyPrefixIt = CTIStorageDB::getAssetTypeToKeyPrefix().find(assetType);
    if (keyPrefixIt == CTIStorageDB::getAssetTypeToKeyPrefix().end())
    {
        throw std::invalid_argument("No key prefix for asset type: " + assetType);
    }

    std::vector<base::Name> assets;
    const std::string& prefix = keyPrefixIt->second;
    rocksdb::ReadOptions ro;
    ro.total_order_seek = true;
    auto it = std::unique_ptr<rocksdb::Iterator>(m_db->NewIterator(ro, getColumnFamily(cfIt->second)));

    for (it->Seek(prefix); it->Valid() &&
         it->key().ToString().compare(0, prefix.size(), prefix) == 0; it->Next())
    {
        try
        {
            json::Json doc(it->value().ToString().c_str());
            std::string title = extractTitleFromJson(doc);
            if (!title.empty())
            {
                assets.emplace_back(title);
            }
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("Failed to parse document while listing assets: {}", e.what());
        }
    }

    return assets;
}

json::Json CTIStorageDB::Impl::getAsset(const base::Name& name, const std::string& assetType) const
{
    std::shared_lock<std::shared_mutex> lock(m_rwMutex); // Shared read lock

    auto cfIt = CTIStorageDB::getAssetTypeToColumnFamily().find(assetType);
    if (cfIt == CTIStorageDB::getAssetTypeToColumnFamily().end())
    {
        throw std::invalid_argument("Invalid asset type: " + assetType);
    }

    auto keyPrefixIt = CTIStorageDB::getAssetTypeToKeyPrefix().find(assetType);
    auto namePrefixIt = CTIStorageDB::getAssetTypeToNamePrefix().find(assetType);
    if (keyPrefixIt == CTIStorageDB::getAssetTypeToKeyPrefix().end() || namePrefixIt == CTIStorageDB::getAssetTypeToNamePrefix().end())
    {
        throw std::invalid_argument("No prefix configuration for asset type: " + assetType);
    }

    return getByIdOrName(name.fullName(), cfIt->second, keyPrefixIt->second, namePrefixIt->second);
}

bool CTIStorageDB::Impl::assetExists(const base::Name& name, const std::string& assetType) const
{
    std::shared_lock<std::shared_mutex> lock(m_rwMutex); // Shared read lock

    auto cfIt = CTIStorageDB::getAssetTypeToColumnFamily().find(assetType);
    if (cfIt == CTIStorageDB::getAssetTypeToColumnFamily().end())
    {
        return false;
    }

    auto keyPrefixIt = CTIStorageDB::getAssetTypeToKeyPrefix().find(assetType);
    auto namePrefixIt = CTIStorageDB::getAssetTypeToNamePrefix().find(assetType);
    if (keyPrefixIt == CTIStorageDB::getAssetTypeToKeyPrefix().end() || namePrefixIt == CTIStorageDB::getAssetTypeToNamePrefix().end())
    {
        return false;
    }

    return existsByIdOrName(name.fullName(), cfIt->second, keyPrefixIt->second, namePrefixIt->second);
}

std::vector<std::string> CTIStorageDB::Impl::getKVDBList() const
{
    std::shared_lock<std::shared_mutex> lock(m_rwMutex); // Shared read lock

    std::vector<std::string> kvdbs;
    rocksdb::ReadOptions ro;
    ro.total_order_seek = true;
    auto it = std::unique_ptr<rocksdb::Iterator>(m_db->NewIterator(ro, getColumnFamily(CTIStorageDB::ColumnFamily::KVDB)));
    const std::string prefix = "kvdb:";

    for (it->Seek(prefix); it->Valid() &&
         it->key().ToString().compare(0, prefix.size(), prefix) == 0; it->Next())
    {
        try
        {
            json::Json doc(it->value().ToString().c_str());
            std::string title = extractTitleFromJson(doc);
            if (!title.empty())
            {
                kvdbs.push_back(title);
            }
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("Failed to parse KVDB document: {}", e.what());
        }
    }

    return kvdbs;
}

std::vector<std::string> CTIStorageDB::Impl::getKVDBList(const base::Name& integrationName) const
{
    std::shared_lock<std::shared_mutex> lock(m_rwMutex); // Shared read lock

    try
    {
        json::Json integration = getByIdOrName(integrationName.fullName(), CTIStorageDB::ColumnFamily::INTEGRATION, "integration:", "name:integration:");
        std::string integrationId = extractIdFromJson(integration);

        if (integrationId.empty())
        {
            return {};
        }

        return getRelatedAssets(integrationId, "idx:integration_kvdbs:");
    }
    catch (const std::exception&)
    {
        return {};
    }
}

bool CTIStorageDB::Impl::kvdbExists(const std::string& kvdbName) const
{
    std::shared_lock<std::shared_mutex> lock(m_rwMutex); // Shared read lock
    return existsByIdOrName(kvdbName, CTIStorageDB::ColumnFamily::KVDB, "kvdb:", "name:kvdb:");
}

json::Json CTIStorageDB::Impl::kvdbDump(const std::string& kvdbName) const
{
    std::shared_lock<std::shared_mutex> lock(m_rwMutex); // Shared read lock

    json::Json kvdbDoc = getByIdOrName(kvdbName, CTIStorageDB::ColumnFamily::KVDB, "kvdb:", "name:kvdb:");

    if (kvdbDoc.exists("/payload/document/content"))
    {
        auto content = kvdbDoc.getJson("/payload/document/content");
        if (content)
        {
            return *content;
        }
    }

    json::Json empty;
    empty.setObject();
    return empty;
}

std::vector<base::Name> CTIStorageDB::Impl::getPolicyIntegrationList() const
{
    std::shared_lock<std::shared_mutex> lock(m_rwMutex); // Shared read lock

    std::vector<base::Name> integrations;
    rocksdb::ReadOptions ro;
    ro.total_order_seek = true;
    auto it = std::unique_ptr<rocksdb::Iterator>(m_db->NewIterator(ro, getColumnFamily(CTIStorageDB::ColumnFamily::POLICY)));
    const std::string prefix = "policy:";

    for (it->Seek(prefix); it->Valid() &&
         it->key().ToString().compare(0, prefix.size(), prefix) == 0; it->Next())
    {
        try
        {
            json::Json doc(it->value().ToString().c_str());
            if (doc.exists("/payload/integrations"))
            {
                auto integrationArray = doc.getArray("/payload/integrations");
                if (integrationArray)
                {
                    for (const auto& integration : *integrationArray)
                    {
                        if (auto integrationStr = integration.getString())
                        {
                            integrations.emplace_back(*integrationStr);
                        }
                    }
                }
            }
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("Failed to parse policy document: {}", e.what());
        }
    }

    return integrations;
}

base::Name CTIStorageDB::Impl::getPolicyDefaultParent() const
{
    // Note: This is a constant value, no lock needed but added for consistency
    std::shared_lock<std::shared_mutex> lock(m_rwMutex); // Shared read lock
    return base::Name("wazuh");
}

void CTIStorageDB::Impl::clearAll()
{
    std::unique_lock<std::shared_mutex> lock(m_rwMutex); // Exclusive write lock

    rocksdb::WriteBatch batch;

    auto clearColumnFamily = [&](rocksdb::ColumnFamilyHandle* cf) {
        auto it = std::unique_ptr<rocksdb::Iterator>(m_db->NewIterator(rocksdb::ReadOptions(), cf));
        for (it->SeekToFirst(); it->Valid(); it->Next())
        {
            batch.Delete(cf, it->key());
        }
    };

    clearColumnFamily(m_cfHandles.metadata.get());
    clearColumnFamily(m_cfHandles.policy.get());
    clearColumnFamily(m_cfHandles.integration.get());
    clearColumnFamily(m_cfHandles.decoder.get());
    clearColumnFamily(m_cfHandles.kvdb.get());

    auto status = m_db->Write(rocksdb::WriteOptions(), &batch);
    if (!status.ok())
    {
        throw std::runtime_error("Failed to clear database: " + status.ToString());
    }
}

size_t CTIStorageDB::Impl::getStorageStats(CTIStorageDB::ColumnFamily cf) const
{
    std::shared_lock<std::shared_mutex> lock(m_rwMutex); // Shared read lock

    size_t count = 0;
    auto it = std::unique_ptr<rocksdb::Iterator>(m_db->NewIterator(rocksdb::ReadOptions(), getColumnFamily(cf)));

    for (it->SeekToFirst(); it->Valid(); it->Next())
    {
        ++count;
    }

    return count;
}

bool CTIStorageDB::Impl::validateDocument(const json::Json& doc, const std::string& expectedType) const
{
    // Note: validateDocument is a pure function that doesn't access database state
    // No lock needed, but we could add shared lock for consistency if needed
    if (!doc.exists("/name") || extractIdFromJson(doc).empty())
    {
        return false;
    }

    if (!doc.exists("/payload"))
    {
        return false;
    }

    if (doc.exists("/payload/type"))
    {
        auto type = doc.getString("/payload/type");
        if (type && *type != expectedType)
        {
            return false;
        }
    }

    if (expectedType != "policy" && !doc.exists("/payload/document"))
    {
        return false;
    }

    return true;
}

} // namespace cti::store
