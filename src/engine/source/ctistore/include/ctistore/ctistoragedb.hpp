#ifndef _CTI_STORE_STORAGE_DB_HPP
#define _CTI_STORE_STORAGE_DB_HPP

#include <memory>
#include <string>
#include <vector>
#include <unordered_map>

#include <rocksdb/db.h>
#include <rocksdb/write_batch.h>

#include <base/json.hpp>
#include <base/name.hpp>

namespace cti::store
{

class CTIStorageDB
{
public:
    enum class ColumnFamily : std::uint8_t
    {
        METADATA,
        POLICY,
        INTEGRATION,
        DECODER,
        KVDB
    };

    explicit CTIStorageDB(const std::string& dbPath, bool useSharedBuffers = true);
    ~CTIStorageDB() = default;

    CTIStorageDB(const CTIStorageDB&) = delete;
    CTIStorageDB& operator=(const CTIStorageDB&) = delete;

    bool isOpen() const { return m_db != nullptr; }

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

    size_t getStorageStats(ColumnFamily cf) const;

    bool validateDocument(const json::Json& doc, const std::string& expectedType) const;

private:
    struct ColumnFamilyHandles
    {
        rocksdb::ColumnFamilyHandle* metadata;
        rocksdb::ColumnFamilyHandle* policy;
        rocksdb::ColumnFamilyHandle* integration;
        rocksdb::ColumnFamilyHandle* decoder;
        rocksdb::ColumnFamilyHandle* kvdb;
    };

    std::unique_ptr<rocksdb::DB> m_db;
    ColumnFamilyHandles m_cfHandles;
    std::shared_ptr<rocksdb::Cache> m_readCache;
    std::shared_ptr<rocksdb::WriteBufferManager> m_writeManager;

    void initializeColumnFamilies(const std::string& dbPath, bool useSharedBuffers);

    rocksdb::ColumnFamilyHandle* getColumnFamily(ColumnFamily cf) const;

    std::string extractIdFromJson(const json::Json& doc) const;
    std::string extractTitleFromJson(const json::Json& doc) const;
    std::string extractIntegrationIdFromJson(const json::Json& doc) const;

    void storeWithIndex(const json::Json& doc,
                       ColumnFamily cf,
                       const std::string& keyPrefix,
                       const std::string& namePrefix);

    json::Json getByIdOrName(const std::string& identifier,
                           ColumnFamily cf,
                           const std::string& keyPrefix,
                           const std::string& namePrefix) const;

    bool existsByIdOrName(const std::string& identifier,
                         ColumnFamily cf,
                         const std::string& keyPrefix,
                         const std::string& namePrefix) const;

    void updateRelationshipIndexes(const json::Json& integrationDoc);

    std::vector<std::string> getRelatedAssets(const std::string& integrationId, const std::string& relationshipKey) const;

    static const std::unordered_map<std::string, ColumnFamily> s_assetTypeToColumnFamily;
    static const std::unordered_map<std::string, std::string> s_assetTypeToKeyPrefix;
    static const std::unordered_map<std::string, std::string> s_assetTypeToNamePrefix;
};

} // namespace cti::store

#endif // _CTI_STORE_STORAGE_DB_HPP
