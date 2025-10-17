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
#include <json.hpp>

namespace cti::store
{

// String constants for prefixes and keys
namespace constants
{

    // Tables type strings
    constexpr std::string_view INTEGRATION_TABLE = "integration";
    constexpr std::string_view DECODER_TABLE = "decoder";
    constexpr std::string_view POLICY_TABLE = "policy";
    constexpr std::string_view KVDB_TABLE = "kvdb";
    constexpr std::string_view METADATA_TABLE = "metadata";

    // Asset type strings
    constexpr std::string_view INTEGRATION_TYPE = "integration";
    constexpr std::string_view DECODER_TYPE = "decoder";
    constexpr std::string_view POLICY_TYPE = "policy";
    constexpr std::string_view KVDB_TYPE = "kvdb";

    // Key prefixes
    constexpr std::string_view INTEGRATION_PREFIX = "integration:";
    constexpr std::string_view DECODER_PREFIX = "decoder:";
    constexpr std::string_view POLICY_PREFIX = "policy:";
    constexpr std::string_view KVDB_PREFIX = "kvdb:";

    // Name index prefixes
    constexpr std::string_view NAME_INTEGRATION_PREFIX = "name:integration:";
    constexpr std::string_view NAME_DECODER_PREFIX = "name:decoder:";
    constexpr std::string_view NAME_POLICY_PREFIX = "name:policy:";
    constexpr std::string_view NAME_KVDB_PREFIX = "name:kvdb:";

    // Relationship index prefixes
    constexpr std::string_view IDX_INTEGRATION_DECODERS = "idx:integration_decoders:";
    constexpr std::string_view IDX_INTEGRATION_KVDBS = "idx:integration_kvdbs:";

    // Default parent
    constexpr std::string_view DEFAULT_PARENT = "wazuh";

    // JSON paths
    constexpr std::string_view JSON_NAME = "/name";
    constexpr std::string_view JSON_PAYLOAD_TITLE = "/payload/title";
    constexpr std::string_view JSON_DOCUMENT_TITLE = "/payload/document/title";
    constexpr std::string_view JSON_DOCUMENT_NAME = "/payload/document/name";
    constexpr std::string_view JSON_PAYLOAD_INTEGRATION_ID = "/payload/integration_id";
    constexpr std::string_view JSON_PAYLOAD_TYPE = "/payload/type";
    constexpr std::string_view JSON_PAYLOAD = "/payload";
    constexpr std::string_view JSON_PAYLOAD_DOCUMENT = "/payload/document";
    constexpr std::string_view JSON_PAYLOAD_INTEGRATIONS = "/payload/integrations";
    constexpr std::string_view JSON_PAYLOAD_DOCUMENT_INTEGRATIONS = "/payload/document/integrations";
    constexpr std::string_view JSON_PAYLOAD_DOCUMENT_DECODERS = "/payload/document/decoders";
    constexpr std::string_view JSON_PAYLOAD_DOCUMENT_KVDBS = "/payload/document/kvdbs";
    constexpr std::string_view JSON_PAYLOAD_DOCUMENT_CONTENT = "/payload/document/content";

    // JSON paths for unwrapped documents (after getByIdOrName strips /payload)
    constexpr std::string_view JSON_UNWRAPPED_DOCUMENT_TITLE = "/document/title";
    constexpr std::string_view JSON_UNWRAPPED_DOCUMENT_NAME = "/document/name";
    constexpr std::string_view JSON_UNWRAPPED_DOCUMENT_CONTENT = "/document/content";

    // Memory configuration
    constexpr size_t READ_CACHE_SIZE = 32 * 1024 * 1024;  // LRU cache size for reading blocks from SST files (32MB)
    constexpr size_t WRITE_BUFFER_SIZE = 64 * 1024 * 1024; // Total memory budget for write buffers across all column families (64MB)
    constexpr size_t WRITE_BUFFER_SIZE_PER_CF = 32 * 1024 * 1024; // Memtable size before flush to disk per column family (32MB)

    // RocksDB configuration
    constexpr int BLOOM_FILTER_BITS = 10; // Bits per key for bloom filter (higher = less false positives, more memory)
    // Log files are stored in the database directory (dbPath) as LOG (current) and LOG.old.* (rotated)
    constexpr int KEEP_LOG_FILE_NUM = 5; // Number of info log files to keep before deletion
    constexpr size_t MAX_LOG_FILE_SIZE = 5 * 1024 * 1024; // Maximum size of each info log file before rotation (5MB)
    constexpr int RECYCLE_LOG_FILE_NUM = 5; // Number of log files to recycle instead of deleting
    constexpr int MAX_OPEN_FILES = 32; // Maximum number of file descriptors to keep open (-1 = unlimited)
    constexpr int NUM_LEVELS = 4; // Number of levels in LSM tree (fewer levels = less compaction overhead)
    constexpr int MAX_WRITE_BUFFER_NUMBER = 3; // Maximum number of memtables to maintain before blocking writes
    constexpr int MAX_BACKGROUND_JOBS = 4; // Maximum concurrent background compaction and flush jobs
}

/**
 * @brief PIMPL (Pointer to Implementation) pattern implementation.
 *
 * This internal implementation class encapsulates all RocksDB-specific details,
 * keeping the public interface clean and hiding implementation dependencies.
 * It manages the database connection, column families, caching, and all storage operations.
 */
struct CTIStorageDB::Impl
{
    /**
     * @brief RAII wrapper for RocksDB column family handles.
     *
     * Manages the lifetime of a column family handle, ensuring proper cleanup
     * through RocksDB's DestroyColumnFamilyHandle API. Implements move-only
     * semantics to prevent accidental handle duplication.
     */
    class CFHandle
    {
    public:
        CFHandle() = default;

        /**
         * @brief Constructs a CFHandle from raw RocksDB pointers.
         * @param handle The RocksDB column family handle to manage
         * @param db The parent database instance for cleanup operations
         */
        CFHandle(rocksdb::ColumnFamilyHandle* handle, rocksdb::DB* db)
            : m_handle(handle), m_db(db) {}

        /**
         * @brief Destroys the column family handle through RocksDB API.
         */
        ~CFHandle()
        {
            if (m_handle && m_db) {
                m_db->DestroyColumnFamilyHandle(m_handle);
            }
        }

        CFHandle(const CFHandle&) = delete;
        CFHandle& operator=(const CFHandle&) = delete;

        /**
         * @brief Move constructor - transfers ownership of the handle.
         * @param other The CFHandle to move from
         */
        CFHandle(CFHandle&& other) noexcept
            : m_handle(other.m_handle), m_db(other.m_db)
        {
            other.m_handle = nullptr;
            other.m_db = nullptr;
        }

        /**
         * @brief Move assignment operator - transfers ownership of the handle.
         * @param other The CFHandle to move from
         * @return Reference to this instance
         */
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

        /**
         * @brief Gets the raw RocksDB column family handle.
         * @return Pointer to the RocksDB ColumnFamilyHandle
         */
        rocksdb::ColumnFamilyHandle* get() const { return m_handle; }

    private:
        rocksdb::ColumnFamilyHandle* m_handle = nullptr;
        rocksdb::DB* m_db = nullptr;
    };

    /**
     * @brief Container for all column family handles used by the CTI storage.
     *
     * RocksDB column families provide logical partitioning within a single database,
     * allowing separate configuration and optimization for different data types:
     * - defaultCF: RocksDB required default column family (unused)
     * - metadata: Name-to-ID mappings and relationship indexes
     * - policy: Policy documents (cyber threat intelligence policies)
     * - integration: Integration documents (data source integrations)
     * - decoder: Decoder documents (log parsing decoders)
     * - kvdb: Key-value database documents (lookup tables)
     */
    struct ColumnFamilyHandles
    {
        CFHandle defaultCF;
        CFHandle metadata;
        CFHandle policy;
        CFHandle integration;
        CFHandle decoder;
        CFHandle kvdb;
    };

    // ========== Member Variables ==========

    /** @brief RocksDB database instance handle. */
    std::unique_ptr<rocksdb::DB> m_db;

    /** @brief All column family handles for logical data partitioning. */
    ColumnFamilyHandles m_cfHandles;

    /** @brief Shared LRU block cache for SST file reads (optional, for memory efficiency). */
    std::shared_ptr<rocksdb::Cache> m_readCache;

    /** @brief Shared write buffer manager across column families (optional, for memory control). */
    std::shared_ptr<rocksdb::WriteBufferManager> m_writeManager;

    /**
     * @brief Reader-writer mutex for thread-safe access.
     *
     * Implements single-writer, multiple-reader concurrency pattern:
     * - Write operations (store*, clear) acquire exclusive lock
     * - Read operations (get*, exists*, list*) acquire shared lock
     */
    mutable std::shared_mutex m_rwMutex;

    // ========== Database Lifecycle Methods ==========

    /**
     * @brief Initializes RocksDB and creates/opens all column families.
     * @param dbPath Filesystem path to the RocksDB directory
     * @param useSharedBuffers Whether to use shared memory buffers across column families
     * @throws std::runtime_error if database cannot be opened or column families cannot be created
     */
    void initializeColumnFamilies(const std::string& dbPath, bool useSharedBuffers);

    /**
     * @brief Retrieves the RocksDB handle for a specific column family.
     * @param cf The column family enum value
     * @return Raw pointer to the RocksDB ColumnFamilyHandle
     * @throws std::runtime_error if the column family is invalid
     */
    rocksdb::ColumnFamilyHandle* getColumnFamily(CTIStorageDB::ColumnFamily cf) const;

    /**
     * @brief Creates RocksDB options with optimized configuration.
     * @return Configured rocksdb::Options struct with tuned parameters
     */
    rocksdb::Options createRocksDBOptions() const;

    /**
     * @brief Gracefully shuts down the database, flushing pending writes.
     */
    void shutdown();

    // ========== JSON Document Parsing ==========

    /**
     * @brief Extracts the unique identifier (ID) from a JSON document.
     * @param doc The JSON document to parse
     * @return The ID string from the /name field
     * @throws std::runtime_error if the ID field is missing
     */
    std::string extractIdFromJson(const json::Json& doc) const;

    /**
     * @brief Extracts the human-readable name from a JSON document.
     * @param doc The JSON document to parse
     * @return The name string from payload/document/title (integration, policy, kvdb) or payload/document/name (decoder)
     * @throws std::runtime_error if the name field is missing
     */
    std::string extractNameFromJson(const json::Json& doc) const;

    // ========== Metadata Column Family Operations ==========

    /**
     * @brief Stores a key-value pair in the metadata column family.
     * @param key The metadata key
     * @param value The metadata value
     * @return true if successful, false otherwise
     */
    bool putMetadata(const std::string& key, const std::string& value);

    /**
     * @brief Retrieves a value from the metadata column family.
     * @param key The metadata key to look up
     * @return The value if found, std::nullopt otherwise
     */
    std::optional<std::string> getMetadata(const std::string& key) const;

    /**
     * @brief Deletes a key-value pair from the metadata column family.
     * @param key The metadata key to delete
     * @return true if successful, false otherwise
     */
    bool deleteMetadata(const std::string& key);

    // ========== Core Storage Operations ==========

    /**
     * @brief Stores a document with automatic indexing by ID and name.
     * @param doc The JSON document to store
     * @param cf The target column family
     * @param keyPrefix Prefix for the ID-based key (e.g., "integration:")
     * @param namePrefix Prefix for the name-based metadata index (e.g., "name:integration:")
     *
     * Creates two entries:
     * 1. [cf] keyPrefix + ID -> full JSON document
     * 2. [metadata] namePrefix + name -> ID (for name-to-ID lookup)
     */
    void storeWithIndex(const json::Json& doc,
                        CTIStorageDB::ColumnFamily cf,
                        const std::string& keyPrefix,
                        const std::string& namePrefix);

    /**
     * @brief Retrieves a document by ID or name.
     * @param identifier The ID or name to look up
     * @param cf The column family to search
     * @param keyPrefix Prefix for ID-based lookup
     * @param namePrefix Prefix for name-based metadata lookup
     * @return The JSON document
     * @throws std::runtime_error if not found
     */
    json::Json getByIdOrName(const std::string& identifier,
                             CTIStorageDB::ColumnFamily cf,
                             const std::string& keyPrefix,
                             const std::string& namePrefix) const;

    /**
     * @brief Checks if a document exists by ID or name.
     * @param identifier The ID or name to check
     * @param cf The column family to search
     * @param keyPrefix Prefix for ID-based lookup
     * @param namePrefix Prefix for name-based metadata lookup
     * @return true if the document exists, false otherwise
     */
    bool existsByIdOrName(const std::string& identifier,
                          CTIStorageDB::ColumnFamily cf,
                          const std::string& keyPrefix,
                          const std::string& namePrefix) const;

    // ========== Relationship Index Management ==========

    /**
     * @brief Updates metadata indexes for integration-decoder and integration-kvdb relationships.
     * @param integrationDoc The integration document containing decoder and kvdb arrays
     *
     * Creates indexes:
     * - idx:integration_decoders:<integration_id> -> comma-separated decoder IDs
     * - idx:integration_kvdbs:<integration_id> -> comma-separated kvdb IDs
     */
    void updateRelationshipIndexes(const json::Json& integrationDoc);

    /**
     * @brief Retrieves related asset IDs for an integration.
     * @param integrationId The integration ID
     * @param relationshipKey The metadata key prefix (e.g., "idx:integration_decoders:")
     * @return Vector of related asset IDs
     */
    std::vector<std::string> getRelatedAssets(const std::string& integrationId,
                                              const std::string& relationshipKey) const;

    // ========== Public API Implementations ==========

    /**
     * @brief Stores a policy document.
     * @param policyDoc JSON document with type="policy"
     */
    void storePolicy(const json::Json& policyDoc);

    /**
     * @brief Stores an integration document with relationship indexing.
     * @param integrationDoc JSON document with type="integration"
     */
    void storeIntegration(const json::Json& integrationDoc);

    /**
     * @brief Stores a decoder document.
     * @param decoderDoc JSON document with type="decoder"
     */
    void storeDecoder(const json::Json& decoderDoc);

    /**
     * @brief Stores a KVDB document.
     * @param kvdbDoc JSON document with type="kvdb"
     */
    void storeKVDB(const json::Json& kvdbDoc);

    /**
     * @brief Deletes an asset by resource ID across all column families.
     * @param resourceId The UUID resource identifier
     * @return true if found and deleted, false if not found
     */
    bool deleteAsset(const std::string& resourceId);

    /**
     * @brief Updates an asset by resource ID with JSON Patch operations.
     * @param resourceId The UUID resource identifier
     * @param operations JSON array of patch operations
     * @return true if found and updated, false if not found
     */
    bool updateAsset(const std::string& resourceId, const json::Json& operations);

    /**
     * @brief Finds which column family contains an asset with the given resource ID.
     * @param resourceId The UUID resource identifier
     * @return Optional pair of {ColumnFamily, assetType string} if found
     */
    std::optional<std::pair<CTIStorageDB::ColumnFamily, std::string>> findAssetColumnFamily(const std::string& resourceId) const;

    /**
     * @brief Lists all asset names of a specific type.
     * @param assetType "integration", "decoder", or "policy"
     * @return Vector of base::Name objects
     */
    std::vector<base::Name> getAssetList(const std::string& assetType) const;

    /**
     * @brief Retrieves an asset document by name.
     * @param name The asset name (supports namespace/name format)
     * @param assetType "integration", "decoder", or "policy"
     * @return The JSON document
     */
    json::Json getAsset(const base::Name& name, const std::string& assetType) const;

    /**
     * @brief Checks if an asset exists.
     * @param name The asset name
     * @param assetType "integration", "decoder", or "policy"
     * @return true if exists, false otherwise
     */
    bool assetExists(const base::Name& name, const std::string& assetType) const;


    std::string resolveNameFromUUID(const std::string& uuid, const std::string& assetType) const;

    /**
     * @brief Lists all KVDB names.
     * @return Vector of KVDB name strings
     */
    std::vector<std::string> getKVDBList() const;

    /**
     * @brief Lists KVDBs belonging to a specific integration.
     * @param integrationName The integration name
     * @return Vector of KVDB name strings
     */
    std::vector<std::string> getKVDBList(const base::Name& integrationName) const;

    /**
     * @brief Checks if a KVDB exists.
     * @param kvdbName The KVDB name
     * @return true if exists, false otherwise
     */
    bool kvdbExists(const std::string& kvdbName) const;

    /**
     * @brief Retrieves the full content of a KVDB.
     * @param kvdbName The KVDB name
     * @return JSON document containing KVDB data
     */
    json::Json kvdbDump(const std::string& kvdbName) const;

    /**
     * @brief Lists all integrations referenced by policies.
     * @return Vector of integration names from policy documents
     */
    std::vector<base::Name> getPolicyIntegrationList() const;

    /**
     * @brief Gets a policy document by ID or title.
     * @param name Policy identifier
     * @return JSON policy document
     */
    json::Json getPolicy(const base::Name& name) const;

    /**
     * @brief Lists all available policy names.
     * @return Vector of policy names
     */
    std::vector<base::Name> getPolicyList() const;

    /**
     * @brief Checks if a policy exists.
     * @param name Policy identifier
     * @return true if exists, false otherwise
     */
    bool policyExists(const base::Name& name) const;

    /**
     * @brief Deletes all data from all column families.
     */
    void clearAll();

    /**
     * @brief Gets the approximate number of keys in a column family.
     * @param cf The column family to query
     * @return Approximate key count
     */
    size_t getStorageStats(CTIStorageDB::ColumnFamily cf) const;

    /**
     * @brief Validates that a document has the expected type field.
     * @param doc The JSON document to validate
     * @param expectedType The expected value of /payload/type
     * @return true if valid, false otherwise
     */
    bool validateDocument(const json::Json& doc, const std::string& expectedType) const;
};

const std::unordered_map<std::string, CTIStorageDB::ColumnFamily>& CTIStorageDB::getAssetTypeToColumnFamily()
{
    static const std::unordered_map<std::string, ColumnFamily> s_map = {
        {std::string(constants::INTEGRATION_TYPE), ColumnFamily::INTEGRATION},
        {std::string(constants::DECODER_TYPE), ColumnFamily::DECODER},
        {std::string(constants::POLICY_TYPE), ColumnFamily::POLICY},
        {std::string(constants::KVDB_TYPE), ColumnFamily::KVDB}
    };
    return s_map;
}

const std::unordered_map<std::string, std::string>& CTIStorageDB::getAssetTypeToKeyPrefix()
{
    static const std::unordered_map<std::string, std::string> s_map = {
        {std::string(constants::INTEGRATION_TYPE), std::string(constants::INTEGRATION_PREFIX)},
        {std::string(constants::DECODER_TYPE), std::string(constants::DECODER_PREFIX)},
        {std::string(constants::POLICY_TYPE), std::string(constants::POLICY_PREFIX)},
        {std::string(constants::KVDB_TYPE), std::string(constants::KVDB_PREFIX)}
    };
    return s_map;
}

const std::unordered_map<std::string, std::string>& CTIStorageDB::getAssetTypeToNamePrefix()
{
    static const std::unordered_map<std::string, std::string> s_map = {
        {std::string(constants::INTEGRATION_TYPE), std::string(constants::NAME_INTEGRATION_PREFIX)},
        {std::string(constants::DECODER_TYPE), std::string(constants::NAME_DECODER_PREFIX)},
        {std::string(constants::POLICY_TYPE), std::string(constants::NAME_POLICY_PREFIX)},
        {std::string(constants::KVDB_TYPE), std::string(constants::NAME_KVDB_PREFIX)}
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

CTIStorageDB::~CTIStorageDB()
{
    if (m_pImpl && m_pImpl->m_db)
    {
        try
        {
            m_pImpl->shutdown();
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("Exception during CTIStorageDB destructor shutdown: {}", e.what());
        }
    }
}

bool CTIStorageDB::isOpen() const
{
    std::shared_lock<std::shared_mutex> lock(m_pImpl->m_rwMutex); // Shared read lock
    return m_pImpl->m_db != nullptr;
}

void CTIStorageDB::shutdown()
{
    m_pImpl->shutdown();
}

rocksdb::Options CTIStorageDB::Impl::createRocksDBOptions() const
{
    rocksdb::BlockBasedTableOptions tableOptions;
    tableOptions.block_cache = m_readCache;
    tableOptions.filter_policy.reset(rocksdb::NewBloomFilterPolicy(constants::BLOOM_FILTER_BITS, false));

    rocksdb::Options options;
    options.table_factory.reset(rocksdb::NewBlockBasedTableFactory(tableOptions));
    options.create_if_missing = true;
    options.create_missing_column_families = true;
    options.info_log_level = rocksdb::InfoLogLevel::INFO_LEVEL;
    options.keep_log_file_num = constants::KEEP_LOG_FILE_NUM;
    options.max_log_file_size = constants::MAX_LOG_FILE_SIZE;
    options.recycle_log_file_num = constants::RECYCLE_LOG_FILE_NUM;
    options.max_open_files = constants::MAX_OPEN_FILES;
    options.write_buffer_manager = m_writeManager;
    options.num_levels = constants::NUM_LEVELS;
    options.write_buffer_size = constants::WRITE_BUFFER_SIZE_PER_CF;
    options.max_write_buffer_number = constants::MAX_WRITE_BUFFER_NUMBER;
    options.max_background_jobs = constants::MAX_BACKGROUND_JOBS;

    return options;
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
        m_readCache = rocksdb::NewLRUCache(constants::READ_CACHE_SIZE);
        m_writeManager = std::make_shared<rocksdb::WriteBufferManager>(constants::WRITE_BUFFER_SIZE, m_readCache);
    }

    rocksdb::Options options = createRocksDBOptions();

    std::vector<rocksdb::ColumnFamilyDescriptor> columnFamilies = {
        rocksdb::ColumnFamilyDescriptor(rocksdb::kDefaultColumnFamilyName, options),
        rocksdb::ColumnFamilyDescriptor(std::string(constants::METADATA_TABLE), options),
        rocksdb::ColumnFamilyDescriptor(std::string(constants::POLICY_TABLE), options),
        rocksdb::ColumnFamilyDescriptor(std::string(constants::INTEGRATION_TABLE), options),
        rocksdb::ColumnFamilyDescriptor(std::string(constants::DECODER_TABLE), options),
        rocksdb::ColumnFamilyDescriptor(std::string(constants::KVDB_TABLE), options)
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

    if (handles.size() != columnFamilies.size())
    {
        for (auto* handle : handles) { if (handle) delete handle; }
        throw std::runtime_error("Unexpected number of column family handles");
    }

    m_cfHandles.defaultCF = CFHandle(handles[0], m_db.get());
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

bool CTIStorageDB::Impl::putMetadata(const std::string& key, const std::string& value)
{
    auto status = m_db->Put(rocksdb::WriteOptions(), getColumnFamily(ColumnFamily::METADATA), key, value);
    return status.ok();
}

std::optional<std::string> CTIStorageDB::Impl::getMetadata(const std::string& key) const
{
    std::string value;
    auto status = m_db->Get(rocksdb::ReadOptions(), getColumnFamily(ColumnFamily::METADATA), key, &value);

    if (status.ok())
    {
        return value;
    }

    return std::nullopt;
}

bool CTIStorageDB::Impl::deleteMetadata(const std::string& key)
{
    auto status = m_db->Delete(rocksdb::WriteOptions(), getColumnFamily(ColumnFamily::METADATA), key);
    return status.ok();
}

void CTIStorageDB::Impl::shutdown()
{
    std::unique_lock<std::shared_mutex> lock(m_rwMutex); // Exclusive write lock

    if (!m_db)
    {
        return; // Already closed
    }

    LOG_INFO("Initiating controlled shutdown of CTIStorageDB");

    // Flush all column families to ensure all data is persisted
    rocksdb::FlushOptions flushOptions;
    flushOptions.wait = true; // Wait for flush to complete

    std::vector<rocksdb::ColumnFamilyHandle*> columnFamilies;
    if (m_cfHandles.defaultCF.get()) columnFamilies.push_back(m_cfHandles.defaultCF.get());
    if (m_cfHandles.metadata.get()) columnFamilies.push_back(m_cfHandles.metadata.get());
    if (m_cfHandles.policy.get()) columnFamilies.push_back(m_cfHandles.policy.get());
    if (m_cfHandles.integration.get()) columnFamilies.push_back(m_cfHandles.integration.get());
    if (m_cfHandles.decoder.get()) columnFamilies.push_back(m_cfHandles.decoder.get());
    if (m_cfHandles.kvdb.get()) columnFamilies.push_back(m_cfHandles.kvdb.get());

    if (!columnFamilies.empty())
    {
        auto status = m_db->Flush(flushOptions, columnFamilies);
        if (!status.ok())
        {
            LOG_WARNING("Failed to flush column families during shutdown: {}", status.ToString());
        }
    }

    // Sync WAL (Write-Ahead Log) to ensure durability
    auto status = m_db->SyncWAL();
    if (!status.ok())
    {
        LOG_WARNING("Failed to sync WAL during shutdown: {}", status.ToString());
    }

    // Destroy column family handles before closing the database
    m_cfHandles.defaultCF = CFHandle();
    m_cfHandles.metadata = CFHandle();
    m_cfHandles.policy = CFHandle();
    m_cfHandles.integration = CFHandle();
    m_cfHandles.decoder = CFHandle();
    m_cfHandles.kvdb = CFHandle();

    // Close the database
    status = m_db->Close();
    if (!status.ok())
    {
        throw std::runtime_error("Failed to close database during shutdown: " + status.ToString());
    }

    // Release the database handle
    m_db.reset();

    LOG_INFO("CTIStorageDB shutdown completed successfully");
}

std::string CTIStorageDB::Impl::extractIdFromJson(const json::Json& doc) const
{
    return doc.getString(constants::JSON_NAME).value_or("");
}

std::string CTIStorageDB::Impl::extractNameFromJson(const json::Json& doc) const
{
    // Try common paths first to minimize type checking overhead
    // Most documents (integration, kvdb) use /payload/document/title
    auto title = doc.getString(constants::JSON_DOCUMENT_TITLE);
    if (title)
    {
        return *title;
    }

    // Decoder uses /payload/document/name
    auto name = doc.getString(constants::JSON_DOCUMENT_NAME);
    if (name)
    {
        return *name;
    }

    // Fallback to legacy flat format for backward compatibility
    title = doc.getString(constants::JSON_PAYLOAD_TITLE);
    if (title)
    {
        return *title;
    }

    // If we get here, document is missing required field
    // Determine type for better error message
    auto typeOpt = doc.getString(constants::JSON_PAYLOAD_TYPE);
    std::string type = typeOpt.value_or("unknown");

    if (type == constants::DECODER_TYPE)
    {
        throw std::runtime_error("Decoder document missing required field: /payload/document/name");
    }
    else if (type == constants::POLICY_TYPE)
    {
        throw std::runtime_error("Policy document missing required field: /payload/title or /payload/document/title");
    }
    else
    {
        throw std::runtime_error("Document missing required field: /payload/document/title");
    }
}


void CTIStorageDB::Impl::storeWithIndex(const json::Json& doc,
                                        CTIStorageDB::ColumnFamily cf,
                                        const std::string& keyPrefix,
                                        const std::string& namePrefix)
{
    std::string id = extractIdFromJson(doc);
    std::string name = extractNameFromJson(doc);

    if (id.empty())
    {
        throw std::invalid_argument("Document missing required 'name' field");
    }

    const std::string primaryKey = keyPrefix + id;
    rocksdb::WriteBatch batch;
    std::string docJson = doc.str();

    // Remove outdated alias before writing the new document.
    std::string existingValue;
    auto readStatus = m_db->Get(rocksdb::ReadOptions(), getColumnFamily(cf), primaryKey, &existingValue);
    if (readStatus.ok())
    {
        try
        {
            json::Json existingDoc(existingValue.c_str());
            std::string previousName = extractNameFromJson(existingDoc);
            if (!previousName.empty() && previousName != name)
            {
                batch.Delete(getColumnFamily(ColumnFamily::METADATA), namePrefix + previousName);
            }
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("Failed to parse stored document while cleaning alias for {}: {}", id, e.what());
        }
    }
    else if (!readStatus.IsNotFound())
    {
        throw std::runtime_error("Failed to read existing document: " + readStatus.ToString());
    }

    batch.Put(getColumnFamily(cf), primaryKey, docJson);

    if (!name.empty())
    {
        batch.Put(getColumnFamily(ColumnFamily::METADATA), namePrefix + name, id);
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

bool CTIStorageDB::deleteAsset(const std::string& resourceId)
{
    return m_pImpl->deleteAsset(resourceId);
}

bool CTIStorageDB::updateAsset(const std::string& resourceId, const json::Json& operations)
{
    return m_pImpl->updateAsset(resourceId, operations);
}

void CTIStorageDB::Impl::updateRelationshipIndexes(const json::Json& integrationDoc)
{
    std::string integrationId = extractIdFromJson(integrationDoc);
    if (integrationId.empty()) return;

    rocksdb::WriteBatch batch;

    if (integrationDoc.exists(constants::JSON_PAYLOAD_DOCUMENT_DECODERS))
    {
        auto decoders = integrationDoc.getArray(constants::JSON_PAYLOAD_DOCUMENT_DECODERS);
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
                     std::string(constants::IDX_INTEGRATION_DECODERS) + integrationId,
                     decoderList.str());
        }
    }

    if (integrationDoc.exists(constants::JSON_PAYLOAD_DOCUMENT_KVDBS))
    {
        auto kvdbs = integrationDoc.getArray(constants::JSON_PAYLOAD_DOCUMENT_KVDBS);
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
                     std::string(constants::IDX_INTEGRATION_KVDBS) + integrationId,
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
        // Try to resolve the name to an ID via metadata
        auto actualIdOpt = getMetadata(namePrefix + identifier);

        if (actualIdOpt)
        {
            status = m_db->Get(rocksdb::ReadOptions(), getColumnFamily(cf), keyPrefix + *actualIdOpt, &value);
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
        // Return the document exactly as stored in RocksDB (raw data)
        // No transformations - let the adapter handle that
        json::Json doc(value.c_str());
        return doc;
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
        // Try to resolve the name to an ID via metadata
        auto actualIdOpt = getMetadata(namePrefix + identifier);

        if (actualIdOpt)
        {
            status = m_db->Get(rocksdb::ReadOptions(), getColumnFamily(cf), keyPrefix + *actualIdOpt, &value);
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

std::string CTIStorageDB::resolveNameFromUUID(const std::string& uuid, const std::string& assetType) const
{
    return m_pImpl->resolveNameFromUUID(uuid, assetType);
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
    auto valueOpt = getMetadata(relationshipKey + integrationId);

    if (!valueOpt)
    {
        return {};
    }

    try
    {
        json::Json assetList(valueOpt->c_str());
        std::vector<std::string> result;

        if (!assetList.isArray())
        {
            return result;
        }

        auto arrayOpt = assetList.getArray();
        if (!arrayOpt)
        {
            return result;
        }

        // Reserve space to avoid reallocations during iteration
        const auto& array = *arrayOpt;
        result.reserve(array.size());

        for (const auto& item : array)
        {
            if (auto itemStr = item.getString())
            {
                result.push_back(*itemStr);
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


json::Json CTIStorageDB::getPolicy(const base::Name& name) const
{
    return m_pImpl->getPolicy(name);
}

std::vector<base::Name> CTIStorageDB::getPolicyList() const
{
    return m_pImpl->getPolicyList();
}

bool CTIStorageDB::policyExists(const base::Name& name) const
{
    return m_pImpl->policyExists(name);
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
    storeWithIndex(policyDoc, CTIStorageDB::ColumnFamily::POLICY, std::string(constants::POLICY_PREFIX), std::string(constants::NAME_POLICY_PREFIX));
}

void CTIStorageDB::Impl::storeIntegration(const json::Json& integrationDoc)
{
    std::unique_lock<std::shared_mutex> lock(m_rwMutex); // Exclusive write lock
    if (!validateDocument(integrationDoc, "integration"))
    {
        throw std::invalid_argument("Invalid integration document format");
    }
    storeWithIndex(integrationDoc, CTIStorageDB::ColumnFamily::INTEGRATION, std::string(constants::INTEGRATION_PREFIX), std::string(constants::NAME_INTEGRATION_PREFIX));
    updateRelationshipIndexes(integrationDoc);
}

void CTIStorageDB::Impl::storeDecoder(const json::Json& decoderDoc)
{
    std::unique_lock<std::shared_mutex> lock(m_rwMutex); // Exclusive write lock
    if (!validateDocument(decoderDoc, "decoder"))
    {
        throw std::invalid_argument("Invalid decoder document format");
    }
    storeWithIndex(decoderDoc, CTIStorageDB::ColumnFamily::DECODER, std::string(constants::DECODER_PREFIX), std::string(constants::NAME_DECODER_PREFIX));
}

void CTIStorageDB::Impl::storeKVDB(const json::Json& kvdbDoc)
{
    std::unique_lock<std::shared_mutex> lock(m_rwMutex); // Exclusive write lock
    if (!validateDocument(kvdbDoc, "kvdb"))
    {
        throw std::invalid_argument("Invalid KVDB document format");
    }
    storeWithIndex(kvdbDoc, CTIStorageDB::ColumnFamily::KVDB, std::string(constants::KVDB_PREFIX), std::string(constants::NAME_KVDB_PREFIX));
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
            std::string title = extractNameFromJson(doc);
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

std::string CTIStorageDB::Impl::resolveNameFromUUID(const std::string& uuid, const std::string& assetType) const
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

    try
    {
        json::Json doc = getByIdOrName(uuid, cfIt->second, keyPrefixIt->second, namePrefixIt->second);

        // Try /document/title first (integrations, policies)
        auto title = doc.getString(constants::JSON_UNWRAPPED_DOCUMENT_TITLE);
        if (title && !title->empty())
        {
            return *title;
        }

        // Try /document/name (decoders)
        auto name = doc.getString(constants::JSON_DOCUMENT_NAME);
        if (name && !name->empty())
        {
            return *name;
        }

        throw std::runtime_error(fmt::format("Document for UUID '{}' missing title/name field", uuid));
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error("Failed to resolve name from UUID: " + std::string(e.what()));
    }
}

std::vector<std::string> CTIStorageDB::Impl::getKVDBList() const
{
    std::shared_lock<std::shared_mutex> lock(m_rwMutex); // Shared read lock

    std::vector<std::string> kvdbs;
    rocksdb::ReadOptions ro;
    ro.total_order_seek = true;
    auto it = std::unique_ptr<rocksdb::Iterator>(m_db->NewIterator(ro, getColumnFamily(CTIStorageDB::ColumnFamily::KVDB)));
    constexpr auto prefix = constants::KVDB_PREFIX;

    for (it->Seek(prefix); it->Valid() &&
         it->key().ToString().compare(0, prefix.size(), prefix) == 0; it->Next())
    {
        try
        {
            json::Json doc(it->value().ToString().c_str());
            std::string title = extractNameFromJson(doc);
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
        json::Json integration = getByIdOrName(integrationName.fullName(), CTIStorageDB::ColumnFamily::INTEGRATION, std::string(constants::INTEGRATION_PREFIX), std::string(constants::NAME_INTEGRATION_PREFIX));
        std::string integrationId = extractIdFromJson(integration);

        if (integrationId.empty())
        {
            return {};
        }

        return getRelatedAssets(integrationId, std::string(constants::IDX_INTEGRATION_KVDBS));
    }
    catch (const std::exception&)
    {
        return {};
    }
}

bool CTIStorageDB::Impl::kvdbExists(const std::string& kvdbName) const
{
    std::shared_lock<std::shared_mutex> lock(m_rwMutex); // Shared read lock
    return existsByIdOrName(kvdbName, CTIStorageDB::ColumnFamily::KVDB, std::string(constants::KVDB_PREFIX), std::string(constants::NAME_KVDB_PREFIX));
}

json::Json CTIStorageDB::Impl::kvdbDump(const std::string& kvdbName) const
{
    std::shared_lock<std::shared_mutex> lock(m_rwMutex);

    // Return raw KVDB document - adapter will extract content if needed
    return getByIdOrName(kvdbName,
                        CTIStorageDB::ColumnFamily::KVDB,
                        std::string(constants::KVDB_PREFIX),
                        std::string(constants::NAME_KVDB_PREFIX));
}

std::vector<base::Name> CTIStorageDB::Impl::getPolicyIntegrationList() const
{
    std::shared_lock<std::shared_mutex> lock(m_rwMutex); // Shared read lock

    std::vector<base::Name> integrations;
    rocksdb::ReadOptions ro;
    ro.total_order_seek = true;
    auto it = std::unique_ptr<rocksdb::Iterator>(m_db->NewIterator(ro, getColumnFamily(CTIStorageDB::ColumnFamily::POLICY)));
    constexpr auto prefix = constants::POLICY_PREFIX;

    for (it->Seek(prefix); it->Valid() &&
         it->key().ToString().compare(0, prefix.size(), prefix) == 0; it->Next())
    {
        try
        {
            json::Json doc(it->value().ToString().c_str());

            std::optional<std::vector<json::Json>> integrationArray;

            // Try nested format first
            if (doc.exists(constants::JSON_PAYLOAD_DOCUMENT_INTEGRATIONS))
            {
                integrationArray = doc.getArray(constants::JSON_PAYLOAD_DOCUMENT_INTEGRATIONS);
            }
            // Fallback to legacy flat format
            else if (doc.exists(constants::JSON_PAYLOAD_INTEGRATIONS))
            {
                integrationArray = doc.getArray(constants::JSON_PAYLOAD_INTEGRATIONS);
            }

            if (integrationArray && !integrationArray->empty())
            {
                for (const auto& integration : *integrationArray)
                {
                    if (auto integrationId = integration.getString())
                    {
                        // Resolve integration ID to title/name
                        try
                        {
                            std::string value;
                            auto status = m_db->Get(ro, getColumnFamily(CTIStorageDB::ColumnFamily::INTEGRATION),
                                                   std::string(constants::INTEGRATION_PREFIX) + *integrationId, &value);
                            if (status.ok())
                            {
                                json::Json integrationDoc(value.c_str());
                                std::string title = extractNameFromJson(integrationDoc);
                                if (!title.empty())
                                {
                                    integrations.emplace_back(title);
                                }
                                else
                                {
                                    // Fallback to ID if no title
                                    integrations.emplace_back(*integrationId);
                                }
                            }
                        }
                        catch (const std::exception& e)
                        {
                            LOG_WARNING("Failed to resolve integration ID {}: {}", *integrationId, e.what());
                            integrations.emplace_back(*integrationId);
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


json::Json CTIStorageDB::Impl::getPolicy(const base::Name& name) const
{
    std::shared_lock<std::shared_mutex> lock(m_rwMutex); // Shared read lock
    return getByIdOrName(name.fullName(),
                        CTIStorageDB::ColumnFamily::POLICY,
                        std::string(constants::POLICY_PREFIX),
                        std::string(constants::NAME_POLICY_PREFIX));
}

std::vector<base::Name> CTIStorageDB::Impl::getPolicyList() const
{
    std::shared_lock<std::shared_mutex> lock(m_rwMutex); // Shared read lock

    std::vector<base::Name> policies;
    rocksdb::ReadOptions ro;
    ro.total_order_seek = true;
    auto it = std::unique_ptr<rocksdb::Iterator>(
        m_db->NewIterator(ro, getColumnFamily(CTIStorageDB::ColumnFamily::POLICY)));
    constexpr auto prefix = constants::POLICY_PREFIX;

    for (it->Seek(prefix); it->Valid() &&
         it->key().ToString().compare(0, prefix.size(), prefix) == 0; it->Next())
    {
        try
        {
            json::Json doc(it->value().ToString().c_str());
            std::string title = extractNameFromJson(doc);
            if (!title.empty())
            {
                policies.emplace_back(title);
            }
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("Failed to parse policy document while listing: {}", e.what());
        }
    }

    return policies;
}

bool CTIStorageDB::Impl::policyExists(const base::Name& name) const
{
    std::shared_lock<std::shared_mutex> lock(m_rwMutex); // Shared read lock
    return existsByIdOrName(name.fullName(),
                           CTIStorageDB::ColumnFamily::POLICY,
                           std::string(constants::POLICY_PREFIX),
                           std::string(constants::NAME_POLICY_PREFIX));
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
    if (!doc.exists(constants::JSON_NAME) || extractIdFromJson(doc).empty())
    {
        return false;
    }

    if (!doc.exists(constants::JSON_PAYLOAD))
    {
        return false;
    }

    if (doc.exists(constants::JSON_PAYLOAD_TYPE))
    {
        auto type = doc.getString(constants::JSON_PAYLOAD_TYPE);
        if (type && *type != expectedType)
        {
            return false;
        }
    }

    if (expectedType != std::string(constants::POLICY_TYPE) && !doc.exists(constants::JSON_PAYLOAD_DOCUMENT))
    {
        return false;
    }

    return true;
}

std::optional<std::pair<CTIStorageDB::ColumnFamily, std::string>>
CTIStorageDB::Impl::findAssetColumnFamily(const std::string& resourceId) const
{
    struct AssetTypeInfo {
        CTIStorageDB::ColumnFamily cf;
        std::string_view prefix;
        std::string_view type;
    };

    constexpr std::array<AssetTypeInfo, 4> assetTypes = {{
        {CTIStorageDB::ColumnFamily::INTEGRATION, constants::INTEGRATION_PREFIX, constants::INTEGRATION_TYPE},
        {CTIStorageDB::ColumnFamily::DECODER, constants::DECODER_PREFIX, constants::DECODER_TYPE},
        {CTIStorageDB::ColumnFamily::POLICY, constants::POLICY_PREFIX, constants::POLICY_TYPE},
        {CTIStorageDB::ColumnFamily::KVDB, constants::KVDB_PREFIX, constants::KVDB_TYPE}
    }};

    rocksdb::ReadOptions ro;
    for (const auto& assetType : assetTypes)
    {
        const std::string key = std::string(assetType.prefix) + resourceId;
        std::string value;
        auto status = m_db->Get(ro, getColumnFamily(assetType.cf), key, &value);

        if (status.ok())
        {
            return std::make_pair(assetType.cf, std::string(assetType.type));
        }
    }

    return std::nullopt;
}

bool CTIStorageDB::Impl::deleteAsset(const std::string& resourceId)
{
    std::unique_lock<std::shared_mutex> lock(m_rwMutex); // Exclusive write lock

    LOG_TRACE("Attempting to delete asset with resource ID: {}", resourceId);

    // First, find which column family contains this asset
    auto cfInfo = findAssetColumnFamily(resourceId);
    if (!cfInfo)
    {
        LOG_DEBUG("Asset with resource ID '{}' not found in any column family", resourceId);
        return false;
    }

    const auto& [cf, assetType] = *cfInfo;

    // Get the corresponding prefixes for this asset type
    auto keyPrefixIt = CTIStorageDB::getAssetTypeToKeyPrefix().find(assetType);
    auto namePrefixIt = CTIStorageDB::getAssetTypeToNamePrefix().find(assetType);

    if (keyPrefixIt == CTIStorageDB::getAssetTypeToKeyPrefix().end() ||
        namePrefixIt == CTIStorageDB::getAssetTypeToNamePrefix().end())
    {
        throw std::runtime_error("Internal error: missing prefix configuration for asset type: " + assetType);
    }

    const std::string& keyPrefix = keyPrefixIt->second;
    const std::string& namePrefix = namePrefixIt->second;
    const std::string primaryKey = keyPrefix + resourceId;

    // Read the document to get its name for secondary index deletion
    std::string docValue;
    rocksdb::ReadOptions ro;
    auto status = m_db->Get(ro, getColumnFamily(cf), primaryKey, &docValue);

    if (!status.ok())
    {
        LOG_WARNING("Failed to read asset document before deletion: {}", status.ToString());
        return false;
    }

    std::string assetName;
    try
    {
        json::Json doc(docValue.c_str());
        assetName = extractNameFromJson(doc);
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("Failed to parse asset document for name extraction: {}", e.what());
        // Continue with deletion even if we can't extract the name
    }

    rocksdb::WriteBatch batch;
    rocksdb::WriteOptions wo;

    // Delete primary key (from asset column family)
    batch.Delete(getColumnFamily(cf), primaryKey);

    // Delete secondary name index (from metadata column family)
    if (!assetName.empty())
    {
        const std::string nameKey = namePrefix + assetName;
        batch.Delete(getColumnFamily(CTIStorageDB::ColumnFamily::METADATA), nameKey);
    }

    // If it's an integration, also delete relationship indexes
    if (assetType == constants::INTEGRATION_TYPE)
    {
        const std::string decodersKey = std::string(constants::IDX_INTEGRATION_DECODERS) + resourceId;
        const std::string kvdbsKey = std::string(constants::IDX_INTEGRATION_KVDBS) + resourceId;
        batch.Delete(getColumnFamily(CTIStorageDB::ColumnFamily::METADATA), decodersKey);
        batch.Delete(getColumnFamily(CTIStorageDB::ColumnFamily::METADATA), kvdbsKey);
    }

    // Execute the batch
    status = m_db->Write(wo, &batch);
    if (!status.ok())
    {
        throw std::runtime_error("Failed to delete asset: " + status.ToString());
    }

    LOG_INFO("Successfully deleted asset type='{}' resource_id='{}'", assetType, resourceId);
    return true;
}

bool CTIStorageDB::Impl::updateAsset(const std::string& resourceId, const json::Json& operations)
{
    std::unique_lock<std::shared_mutex> lock(m_rwMutex); // Exclusive write lock

    LOG_TRACE("Attempting to update asset with resource ID: {}", resourceId);

    // Validate operations is an array
    auto opsArray = operations.getArray();
    if (!opsArray || opsArray->empty())
    {
        throw std::invalid_argument("operations must be a non-empty JSON array");
    }

    // Find which column family contains this asset
    auto cfInfo = findAssetColumnFamily(resourceId);
    if (!cfInfo)
    {
        LOG_DEBUG("Asset with resource ID '{}' not found in any column family", resourceId);
        return false;
    }

    const auto& [cf, assetType] = *cfInfo;

    // Get the corresponding prefixes for this asset type
    auto keyPrefixIt = CTIStorageDB::getAssetTypeToKeyPrefix().find(assetType);
    if (keyPrefixIt == CTIStorageDB::getAssetTypeToKeyPrefix().end())
    {
        throw std::runtime_error("Internal error: missing prefix configuration for asset type: " + assetType);
    }

    const std::string& keyPrefix = keyPrefixIt->second;
    const std::string primaryKey = keyPrefix + resourceId;

    // Read the current document
    std::string docValue;
    rocksdb::ReadOptions ro;
    auto status = m_db->Get(ro, getColumnFamily(cf), primaryKey, &docValue);

    if (!status.ok())
    {
        LOG_WARNING("Failed to read asset document for update: {}", status.ToString());
        return false;
    }

    // Parse the document using nlohmann::json for RFC 6902 JSON Patch support
    nlohmann::json jsonData;
    try
    {
        jsonData = nlohmann::json::parse(docValue);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error("Failed to parse existing asset document: " + std::string(e.what()));
    }

    // Convert operations from base::json::Json to nlohmann::json
    nlohmann::json patchOperations;
    try
    {
        // Serialize base::json::Json operations to string and parse with nlohmann::json
        std::string opsStr = operations.str();
        patchOperations = nlohmann::json::parse(opsStr);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error("Failed to convert patch operations: " + std::string(e.what()));
    }

    // Adjust patch operation paths to account for /payload wrapper
    // Operations come with paths like /document/... but we store /payload/document/...
    for (auto& op : patchOperations)
    {
        if (op.contains("path") && op["path"].is_string())
        {
            std::string path = op["path"].get<std::string>();

            // Special case: empty path with replace means replacing entire payload
            if (path.empty() && op.contains("op") && op["op"].get<std::string>() == "replace")
            {
                // If value contains the new payload structure, wrap it properly
                if (op.contains("value") && op["value"].is_object())
                {
                    op["path"] = "/payload";
                    LOG_TRACE("Adjusted empty patch path to /payload for full replace");
                }
            }
            // If path starts with /document, prefix it with /payload
            else if (path.rfind("/document", 0) == 0)
            {
                op["path"] = "/payload" + path;
                LOG_TRACE("Adjusted patch path: {} -> {}", path, op["path"].get<std::string>());
            }
        }
        // Also adjust "from" field for move/copy operations
        if (op.contains("from") && op["from"].is_string())
        {
            std::string fromPath = op["from"].get<std::string>();
            if (fromPath.rfind("/document", 0) == 0)
            {
                op["from"] = "/payload" + fromPath;
                LOG_TRACE("Adjusted patch 'from' path: {} -> {}", fromPath, op["from"].get<std::string>());
            }
        }
    }

    // Apply JSON Patch operations (RFC 6902)
    try
    {
        jsonData.patch_inplace(patchOperations);
        LOG_TRACE("Successfully applied {} patch operations to asset", opsArray->size());
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Failed to apply JSON Patch operations: {}", e.what());
        throw std::runtime_error("JSON Patch application failed: " + std::string(e.what()));
    }

    // Convert back to base::json::Json for validation and storage
    json::Json doc;
    try
    {
        std::string updatedJsonStr = jsonData.dump();
        doc = json::Json(updatedJsonStr.c_str());
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error("Failed to convert patched document back to base::json: " + std::string(e.what()));
    }

    // Validate the updated document
    if (!validateDocument(doc, assetType))
    {
        throw std::invalid_argument("Updated document failed validation for type: " + assetType);
    }

    // Store the updated document back (reusing storeWithIndex logic would be ideal,
    // but we need to handle it directly here to maintain the lock)
    const std::string updatedDoc = jsonData.dump();
    rocksdb::WriteOptions wo;
    status = m_db->Put(wo, getColumnFamily(cf), primaryKey, updatedDoc);

    if (!status.ok())
    {
        throw std::runtime_error("Failed to write updated asset: " + status.ToString());
    }

    // Update relationship indexes if it's an integration
    if (assetType == constants::INTEGRATION_TYPE)
    {
        updateRelationshipIndexes(doc);
    }

    LOG_INFO("Successfully updated asset type='{}' resource_id='{}' with {} operations",
             assetType, resourceId, opsArray->size());
    return true;
}

} // namespace cti::store
