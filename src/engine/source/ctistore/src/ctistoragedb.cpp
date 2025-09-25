#include <ctistore/ctistoragedb.hpp>

#include <filesystem>
#include <stdexcept>

#include <rocksdb/filter_policy.h>
#include <rocksdb/table.h>
#include <rocksDBSharedBuffers.hpp>
#include <rocksdb/slice_transform.h>
#include <base/logging.hpp>

namespace cti::store
{

const std::unordered_map<std::string, CTIStorageDB::ColumnFamily> CTIStorageDB::s_assetTypeToColumnFamily = {
    {"integration", ColumnFamily::INTEGRATION},
    {"decoder", ColumnFamily::DECODER},
    {"policy", ColumnFamily::POLICY}
};

const std::unordered_map<std::string, std::string> CTIStorageDB::s_assetTypeToKeyPrefix = {
    {"integration", "integration:"},
    {"decoder", "decoder:"},
    {"policy", "policy:"}
};

const std::unordered_map<std::string, std::string> CTIStorageDB::s_assetTypeToNamePrefix = {
    {"integration", "name:integration:"},
    {"decoder", "name:decoder:"},
    {"policy", "name:policy:"}
};

CTIStorageDB::CTIStorageDB(const std::string& dbPath, bool useSharedBuffers)
    : m_db(nullptr), m_cfHandles{}
{
    try
    {
        initializeColumnFamilies(dbPath, useSharedBuffers);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error("Failed to initialize CTI Storage Database: " + std::string(e.what()));
    }
}

void CTIStorageDB::initializeColumnFamilies(const std::string& dbPath, bool useSharedBuffers)
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

    m_cfHandles.metadata = handles[1];
    m_cfHandles.policy = handles[2];
    m_cfHandles.integration = handles[3];
    m_cfHandles.decoder = handles[4];
    m_cfHandles.kvdb = handles[5];
}

rocksdb::ColumnFamilyHandle* CTIStorageDB::getColumnFamily(ColumnFamily cf) const
{
    switch (cf)
    {
        case ColumnFamily::METADATA: return m_cfHandles.metadata;
        case ColumnFamily::POLICY: return m_cfHandles.policy;
        case ColumnFamily::INTEGRATION: return m_cfHandles.integration;
        case ColumnFamily::DECODER: return m_cfHandles.decoder;
        case ColumnFamily::KVDB: return m_cfHandles.kvdb;
        default:
            throw std::invalid_argument("Invalid column family");
    }
}

std::string CTIStorageDB::extractIdFromJson(const json::Json& doc) const
{
    if (doc.exists("/name"))
    {
        return doc.getString("/name").value_or("");
    }
    return "";
}

std::string CTIStorageDB::extractTitleFromJson(const json::Json& doc) const
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

std::string CTIStorageDB::extractIntegrationIdFromJson(const json::Json& doc) const
{
    if (doc.exists("/payload/integration_id"))
    {
        return doc.getString("/payload/integration_id").value_or("");
    }
    return "";
}

void CTIStorageDB::storeWithIndex(const json::Json& doc,
                                 ColumnFamily cf,
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
    if (!validateDocument(policyDoc, "policy"))
    {
        throw std::invalid_argument("Invalid policy document format");
    }
    storeWithIndex(policyDoc, ColumnFamily::POLICY, "policy:", "name:policy:");
}

void CTIStorageDB::storeIntegration(const json::Json& integrationDoc)
{
    if (!validateDocument(integrationDoc, "integration"))
    {
        throw std::invalid_argument("Invalid integration document format");
    }
    storeWithIndex(integrationDoc, ColumnFamily::INTEGRATION, "integration:", "name:integration:");
    updateRelationshipIndexes(integrationDoc);
}

void CTIStorageDB::storeDecoder(const json::Json& decoderDoc)
{
    if (!validateDocument(decoderDoc, "decoder"))
    {
        throw std::invalid_argument("Invalid decoder document format");
    }
    storeWithIndex(decoderDoc, ColumnFamily::DECODER, "decoder:", "name:decoder:");
}

void CTIStorageDB::storeKVDB(const json::Json& kvdbDoc)
{
    if (!validateDocument(kvdbDoc, "kvdb"))
    {
        throw std::invalid_argument("Invalid KVDB document format");
    }
    storeWithIndex(kvdbDoc, ColumnFamily::KVDB, "kvdb:", "name:kvdb:");
}

void CTIStorageDB::updateRelationshipIndexes(const json::Json& integrationDoc)
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

json::Json CTIStorageDB::getByIdOrName(const std::string& identifier,
                                      ColumnFamily cf,
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

bool CTIStorageDB::existsByIdOrName(const std::string& identifier,
                                   ColumnFamily cf,
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
    auto cfIt = s_assetTypeToColumnFamily.find(assetType);
    if (cfIt == s_assetTypeToColumnFamily.end())
    {
        throw std::invalid_argument("Invalid asset type: " + assetType);
    }

    auto keyPrefixIt = s_assetTypeToKeyPrefix.find(assetType);
    if (keyPrefixIt == s_assetTypeToKeyPrefix.end())
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

json::Json CTIStorageDB::getAsset(const base::Name& name, const std::string& assetType) const
{
    auto cfIt = s_assetTypeToColumnFamily.find(assetType);
    if (cfIt == s_assetTypeToColumnFamily.end())
    {
        throw std::invalid_argument("Invalid asset type: " + assetType);
    }

    auto keyPrefixIt = s_assetTypeToKeyPrefix.find(assetType);
    auto namePrefixIt = s_assetTypeToNamePrefix.find(assetType);
    if (keyPrefixIt == s_assetTypeToKeyPrefix.end() || namePrefixIt == s_assetTypeToNamePrefix.end())
    {
        throw std::invalid_argument("No prefix configuration for asset type: " + assetType);
    }

    return getByIdOrName(name.fullName(), cfIt->second, keyPrefixIt->second, namePrefixIt->second);
}

bool CTIStorageDB::assetExists(const base::Name& name, const std::string& assetType) const
{
    auto cfIt = s_assetTypeToColumnFamily.find(assetType);
    if (cfIt == s_assetTypeToColumnFamily.end())
    {
        return false;
    }

    auto keyPrefixIt = s_assetTypeToKeyPrefix.find(assetType);
    auto namePrefixIt = s_assetTypeToNamePrefix.find(assetType);
    if (keyPrefixIt == s_assetTypeToKeyPrefix.end() || namePrefixIt == s_assetTypeToNamePrefix.end())
    {
        return false;
    }

    return existsByIdOrName(name.fullName(), cfIt->second, keyPrefixIt->second, namePrefixIt->second);
}

std::vector<std::string> CTIStorageDB::getKVDBList() const
{
    std::vector<std::string> kvdbs;
    rocksdb::ReadOptions ro;
    ro.total_order_seek = true;
    auto it = std::unique_ptr<rocksdb::Iterator>(m_db->NewIterator(ro, getColumnFamily(ColumnFamily::KVDB)));
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

std::vector<std::string> CTIStorageDB::getKVDBList(const base::Name& integrationName) const
{
    try
    {
        json::Json integration = getByIdOrName(integrationName.fullName(), ColumnFamily::INTEGRATION, "integration:", "name:integration:");
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

std::vector<std::string> CTIStorageDB::getRelatedAssets(const std::string& integrationId, const std::string& relationshipKey) const
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
    return existsByIdOrName(kvdbName, ColumnFamily::KVDB, "kvdb:", "name:kvdb:");
}

json::Json CTIStorageDB::kvdbDump(const std::string& kvdbName) const
{
    json::Json kvdbDoc = getByIdOrName(kvdbName, ColumnFamily::KVDB, "kvdb:", "name:kvdb:");

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

std::vector<base::Name> CTIStorageDB::getPolicyIntegrationList() const
{
    std::vector<base::Name> integrations;
    rocksdb::ReadOptions ro;
    ro.total_order_seek = true;
    auto it = std::unique_ptr<rocksdb::Iterator>(m_db->NewIterator(ro, getColumnFamily(ColumnFamily::POLICY)));
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

base::Name CTIStorageDB::getPolicyDefaultParent() const
{
    return base::Name("wazuh");
}

void CTIStorageDB::clearAll()
{
    rocksdb::WriteBatch batch;

    auto clearColumnFamily = [&](rocksdb::ColumnFamilyHandle* cf) {
        auto it = std::unique_ptr<rocksdb::Iterator>(m_db->NewIterator(rocksdb::ReadOptions(), cf));
        for (it->SeekToFirst(); it->Valid(); it->Next())
        {
            batch.Delete(cf, it->key());
        }
    };

    clearColumnFamily(m_cfHandles.metadata);
    clearColumnFamily(m_cfHandles.policy);
    clearColumnFamily(m_cfHandles.integration);
    clearColumnFamily(m_cfHandles.decoder);
    clearColumnFamily(m_cfHandles.kvdb);

    auto status = m_db->Write(rocksdb::WriteOptions(), &batch);
    if (!status.ok())
    {
        throw std::runtime_error("Failed to clear database: " + status.ToString());
    }
}

size_t CTIStorageDB::getStorageStats(ColumnFamily cf) const
{
    size_t count = 0;
    auto it = std::unique_ptr<rocksdb::Iterator>(m_db->NewIterator(rocksdb::ReadOptions(), getColumnFamily(cf)));

    for (it->SeekToFirst(); it->Valid(); it->Next())
    {
        ++count;
    }

    return count;
}

bool CTIStorageDB::validateDocument(const json::Json& doc, const std::string& expectedType) const
{
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
