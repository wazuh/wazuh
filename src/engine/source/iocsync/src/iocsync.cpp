#include <chrono>
#include <set>
#include <stdexcept>
#include <thread>
#include <utility>

#include <fmt/format.h>

#include <base/error.hpp>
#include <base/json.hpp>
#include <base/logging.hpp>
#include <base/name.hpp>
#include <base/utils/generator.hpp>

#include <iocsync/iocsync.hpp>

namespace
{

const base::Name STORE_NAME_IOCSYNC {"iocsync/status/0"}; ///< Name of the internal store document
constexpr std::string_view IOC_INDEX {".cti-iocs"};       ///< IOC index name

/**
 * @brief Execute an operation with retry logic
 *
 * @tparam Func Callable type that performs the operation
 * @param operation The operation to execute
 * @param operationName Name of the operation for logging purposes
 * @param maxAttempts Maximum number of retry attempts
 * @param waitSeconds Seconds to wait between retries
 * @return decltype(auto) Result of the operation
 * @throw std::exception if all retry attempts fail
 */
template<typename Func>
decltype(auto)
executeWithRetry(Func&& operation, std::string_view operationName, std::size_t maxAttempts, std::size_t waitSeconds)
{
    for (std::size_t attempt = 1; attempt <= maxAttempts; ++attempt)
    {
        try
        {
            return operation();
        }
        catch (const std::exception& e)
        {
            LOG_WARNING_L(
                operationName.data(), "[IocSync::{}] Attempt {}/{}: {}", operationName, attempt, maxAttempts, e.what());
            if (attempt < maxAttempts)
            {
                std::this_thread::sleep_for(std::chrono::seconds(waitSeconds));
            }
            else
            {
                throw;
            }
        }
    }
    throw std::runtime_error(fmt::format("Unreachable code in IocSync::{}", operationName));
}

/**
 * @brief Locks a weak pointer and returns a shared pointer.
 *
 * @tparam T Type of the resource
 * @param weakPtr Weak pointer to lock
 * @param resourceName Name of the resource for error messages
 * @return std::shared_ptr<T> Shared pointer to the resource
 * @throw std::runtime_error if the resource is not available
 */
template<typename T>
std::shared_ptr<T> lockWeakPtr(const std::weak_ptr<T>& weakPtr, const std::string& resourceName)
{
    auto sharedPtr = weakPtr.lock();
    if (!sharedPtr)
    {
        throw std::runtime_error(resourceName + " resource is not available");
    }
    return sharedPtr;
}

/**
 * @brief Generate a random database name for the given IOC type
 *
 * @param iocType IOC type name
 * @return std::string Generated database name
 */
std::string generateDBName(std::string_view iocType)
{
    return fmt::format("iocsync_{}_{}", iocType, base::utils::generators::randomHexString(4));
}

/**
 * @brief Generate a fixed database name for the given IOC type (target DB)
 *
 * @param iocType IOC type name
 * @return std::string Fixed database name
 */
std::string generateTargetDBName(std::string_view iocType)
{
    // Use a fixed name for the target database (no random suffix)
    return fmt::format("ioc-{}", iocType);
}

} // namespace

namespace ioc::sync
{

/**
 * @brief Represents an IOC database being synchronized from the indexer
 */
class SyncedIOCDatabase
{
private:
    std::string m_iocType;      ///< IOC type from enrichments.indicator.type (e.g., ipv4-addr, domain-name, url, file)
    std::string m_lastDataHash; ///< Last known data hash
    std::string m_dbName;       ///< Database name in kvdbioc manager

    static constexpr std::string_view JPATH_IOC_TYPE = "/ioc_type";             ///< JSON path for IOC type
    static constexpr std::string_view JPATH_LAST_DATA_HASH = "/last_data_hash"; ///< JSON path for last data hash
    static constexpr std::string_view JPATH_DB_NAME = "/db_name";               ///< JSON path for database name

public:
    SyncedIOCDatabase() = delete;
    explicit SyncedIOCDatabase(std::string_view iocType)
        : m_iocType(iocType)
        , m_lastDataHash()
        , m_dbName() // Empty by default - will be set after first successful sync
    {
    }

    SyncedIOCDatabase(std::string_view iocType, std::string_view lastDataHash, std::string_view dbName)
        : m_iocType(iocType)
        , m_lastDataHash(lastDataHash)
        , m_dbName(dbName)
    {
    }

    /* Getters and Setters */
    const std::string& getIocType() const { return m_iocType; }
    const std::string& getLastDataHash() const { return m_lastDataHash; }
    const std::string& getDBName() const { return m_dbName; }
    void setLastDataHash(std::string_view hash) { m_lastDataHash = hash; }
    void setDBName(std::string_view dbName) { m_dbName = dbName; }
    void setIocType(std::string_view iocType) { m_iocType = iocType; }

    /**
     * @brief Serialize the SyncedIOCDatabase to a JSON object
     *
     * @return json::Json JSON representation of the SyncedIOCDatabase
     */
    json::Json toJson() const
    {
        json::Json j {};
        j.setString(m_iocType, JPATH_IOC_TYPE);
        j.setString(m_lastDataHash, JPATH_LAST_DATA_HASH);
        j.setString(m_dbName, JPATH_DB_NAME);
        return j;
    }

    /**
     * @brief Deserialize a SyncedIOCDatabase from a JSON object
     *
     * @param j JSON object to deserialize
     * @return SyncedIOCDatabase Deserialized SyncedIOCDatabase
     * @throw std::runtime_error if required fields are missing or invalid
     */
    static SyncedIOCDatabase fromJson(const json::Json& j)
    {
        auto optIocType = j.getString(JPATH_IOC_TYPE);
        if (!optIocType.has_value() || optIocType->empty())
        {
            throw std::runtime_error("SyncedIOCDatabase::fromJson: Missing/empty ioc_type field");
        }

        auto optDbName = j.getString(JPATH_DB_NAME);
        if (!optDbName.has_value())
        {
            throw std::runtime_error("SyncedIOCDatabase::fromJson: Missing db_name field");
        }

        auto optLastHash = j.getString(JPATH_LAST_DATA_HASH);
        if (!optLastHash.has_value())
        {
            throw std::runtime_error("SyncedIOCDatabase::fromJson: Missing last_data_hash field");
        }
        const auto& lastHash = *optLastHash;

        return {*optIocType, lastHash, *optDbName};
    }
};

IocSync::IocSync(const std::shared_ptr<wiconnector::IWIndexerConnector>& indexerPtr,
                 const std::shared_ptr<kvdbioc::IKVDBManager>& kvdbiocManagerPtr,
                 const std::shared_ptr<::store::IStore>& storePtr)
    : m_indexerPtr(indexerPtr)
    , m_kvdbiocManagerPtr(kvdbiocManagerPtr)
    , m_store(storePtr)
    , m_mutex()
    , m_attemps(3)
    , m_waitSeconds(5)
{
    // Check if is the first setup
    if (storePtr->existsDoc(STORE_NAME_IOCSYNC))
    {
        loadStateFromStore();
        return;
    }

    LOG_INFO("[IOC::Sync] First setup detected, initializing default IOC types to sync");

    // Add default IOC types to sync (based on enrichments.indicator.type values)
    addIOCTypeToSync("ipv4-addr");
    addIOCTypeToSync("domain-name");
    addIOCTypeToSync("url");
    addIOCTypeToSync("file");
    saveStateToStore();
}

IocSync::~IocSync() = default;

bool IocSync::existIndexInRemote(std::string_view indexName)
{
    auto indexerPtr = lockWeakPtr(m_indexerPtr, "IndexerConnector");

    return executeWithRetry([&indexerPtr, indexName]() { return indexerPtr->existsIndex(indexName); },
                            fmt::format("exist '{}' index in wazuh-indexer", indexName),
                            m_attemps,
                            m_waitSeconds);
}

std::string IocSync::getDataHashFromRemote(std::string_view iocType)
{
    auto indexerPtr = lockWeakPtr(m_indexerPtr, "Indexer Connector");

    return executeWithRetry(
        [&indexerPtr, iocType]()
        {
            // Query to count documents of this specific IOC type
            // Use .keyword for exact match on text fields
            std::string queryBody = fmt::format(R"({{"term": {{"threat.indicator.type": "{}"}}}})", iocType);

            // Query with match_all to get total count from the indexer
            // We need to do a real query to get document count
            auto results = indexerPtr->query(IOC_INDEX, queryBody, 1);

            // Get the actual document count from indexer for this type
            // For now use a simple approach: query a small sample and use results size as indicator
            // TODO: Implement proper count query or aggregation
            std::size_t count = 0;
            try
            {
                // Do a larger query to get a better count estimate
                auto allResults = indexerPtr->query(IOC_INDEX, queryBody, 10000);

                // Simply count the results - each document matches the type filter
                count = allResults.size();
            }
            catch (...)
            {
                // If query fails, return 0
                count = 0;
            }

            // Simple hash based on document count for this type
            // This will trigger re-sync when docs are added/removed
            return fmt::format("{}", count);
        },
        fmt::format("getDataHashFromRemote('{}')", IOC_INDEX),
        m_attemps,
        m_waitSeconds);
}

void IocSync::downloadAndPopulateDB(std::string_view iocType, const std::string& dbName)
{
    auto indexerPtr = lockWeakPtr(m_indexerPtr, "IndexerConnector");
    auto kvdbiocPtr = lockWeakPtr(m_kvdbiocManagerPtr, "KVDBIOCManager");

    LOG_INFO("[IOC::Sync] Downloading IOCs of type '{}' to database '{}'", iocType, dbName);

    // Create the database
    kvdbiocPtr->add(dbName);

    try
    {
        // Query only documents that have enrichments of this specific IOC type
        // This dramatically reduces data transfer compared to match_all + client-side filtering
        std::string queryBody = fmt::format(R"({{"term": {{"enrichments.indicator.type": "{}"}}}})", iocType);

        // Download documents in batches to avoid memory issues
        const std::size_t BATCH_SIZE = 1000;
        std::size_t processedDocs = 0;
        std::size_t stored = 0;
        std::size_t skipped = 0;
        bool hasMore = true;

        LOG_INFO("[IOC::Sync] Starting filtered download for type '{}' (batch size: {})", iocType, BATCH_SIZE);

        while (hasMore)
        {
            // Download batch
            auto results = indexerPtr->query(IOC_INDEX, queryBody, BATCH_SIZE);

            if (results.empty())
            {
                hasMore = false;
                break;
            }

            processedDocs += results.size();

            // Process batch
            for (const auto& doc : results)
            {
                // Get the enrichments array
                auto optEnrichments = doc.getArray("/enrichments");
                if (!optEnrichments.has_value())
                {
                    continue; // Skip documents without enrichments
                }

                // Process each enrichment in the array
                for (const auto& enrichment : *optEnrichments)
                {
                    // Check if this enrichment matches our IOC type
                    auto optType = enrichment.getString("/indicator/type");
                    if (!optType.has_value() || *optType != iocType)
                    {
                        continue; // Skip enrichments of different types
                    }

                    // Extract the indicator name (this will be our key)
                    auto optName = enrichment.getString("/indicator/name");
                    if (!optName.has_value() || optName->empty())
                    {
                        LOG_WARNING("[IOC::Sync] Enrichment without indicator.name field, skipping");
                        skipped++;
                        continue;
                    }

                    // Store the enrichment object (not the full document) using indicator.name as key
                    kvdbiocPtr->put(dbName, *optName, enrichment.str());
                    stored++;
                }
            }

            // Log progress
            if (processedDocs % 5000 == 0)
            {
                LOG_INFO("[IOC::Sync] Progress: processed {} documents, stored {} IOCs of type '{}'",
                         processedDocs,
                         stored,
                         iocType);
            }

            // Check if we got fewer results than requested (end of data)
            if (results.size() < BATCH_SIZE)
            {
                hasMore = false;
            }
        }

        LOG_INFO("[IOC::Sync] Successfully downloaded {} IOCs of type '{}' to database '{}' (processed {} docs, "
                 "skipped: {})",
                 stored,
                 iocType,
                 dbName,
                 processedDocs,
                 skipped);

        if (stored == 0)
        {
            LOG_WARNING("[IOC::Sync] No IOCs found for type '{}'", iocType);
        }
    }
    catch (const std::exception& e)
    {
        // Rollback: remove the database
        try
        {
            kvdbiocPtr->remove(dbName);
        }
        catch (const std::exception& ex)
        {
            LOG_WARNING("[IocSync::downloadAndPopulateDB] Failed to rollback database '{}' after download failure: {}",
                        dbName,
                        ex.what());
        }
        throw std::runtime_error(fmt::format("Failed to download IOCs to database '{}': {}", dbName, e.what()));
    }
}

void IocSync::addIOCTypeToSync(std::string_view iocType)
{
    std::unique_lock lock(m_mutex);

    // Check if the IOC type is already in the sync list
    for (const auto& syncedDB : m_databasesState)
    {
        if (syncedDB.getIocType() == iocType)
        {
            throw std::runtime_error(fmt::format("IOC type '{}' is already in the sync list", iocType));
        }
    }

    // Add the new IOC type to the sync list
    m_databasesState.emplace_back(iocType);

    LOG_INFO("[IOC::Sync] Added IOC type '{}' to the sync list", iocType);

    saveStateToStore();
}

void IocSync::removeIOCTypeFromSync(std::string_view iocType)
{
    std::unique_lock lock(m_mutex);

    auto it = std::remove_if(m_databasesState.begin(),
                             m_databasesState.end(),
                             [iocType](const SyncedIOCDatabase& syncedDB) { return syncedDB.getIocType() == iocType; });
    if (it == m_databasesState.end())
    {
        throw std::runtime_error(fmt::format("IOC type '{}' is not in the sync list", iocType));
    }

    m_databasesState.erase(it, m_databasesState.end());

    LOG_INFO("[IOC::Sync] Removed IOC type '{}' from the sync list", iocType);

    saveStateToStore();
}

void IocSync::loadStateFromStore()
{
    auto storePtr = lockWeakPtr(m_store, "Store");

    auto optDoc = storePtr->readDoc(STORE_NAME_IOCSYNC);
    if (base::isError(optDoc))
    {
        throw std::runtime_error(
            fmt::format("Failed to load iocsync state from store: {}", base::getError(optDoc).message));
    }

    const auto& j = base::getResponse(optDoc);

    auto optArrayConf = j.getArray();
    if (!optArrayConf.has_value())
    {
        throw std::runtime_error("IocSync::loadStateFromStore: Invalid iocsync state document: missing array config");
    }

    m_databasesState.clear();
    for (const auto& jSyncedDB : *optArrayConf)
    {
        m_databasesState.emplace_back(SyncedIOCDatabase::fromJson(jSyncedDB));
    }
}

void IocSync::saveStateToStore()
{
    auto storePtr = lockWeakPtr(m_store, "StoreInternal");

    json::Json j {};
    j.setArray();
    for (const auto& syncedDB : m_databasesState)
    {
        j.appendJson(syncedDB.toJson());
    }

    if (auto optErr = storePtr->upsertDoc(STORE_NAME_IOCSYNC, j); base::isError(optErr))
    {
        throw std::runtime_error(
            fmt::format("Failed to save iocsync state to store: {}", base::getError(optErr).message));
    }
}

void IocSync::synchronize()
{
    LOG_DEBUG("[IOC::Sync] Checking for IOC database updates to synchronize");

    const auto kvdbiocPtr = lockWeakPtr(m_kvdbiocManagerPtr, "KVDBIOCManager");
    std::unique_lock lock(m_mutex); // Lock the sync process, only 1 at a time

    // Check if the .cti-iocs index exists
    if (!existIndexInRemote(IOC_INDEX))
    {
        LOG_WARNING("[IOC::Sync] Index '.cti-iocs' does not exist in indexer. Skipping all synchronization...");
        return;
    }

    for (auto& dbState : m_databasesState)
    {
        try
        {
            LOG_DEBUG("[IOC::Sync] Synchronizing database for IOC type '{}'", dbState.getIocType());

            // Get remote data hash
            const auto remoteHash = getDataHashFromRemote(dbState.getIocType());

            // Check if the data has changed
            if (remoteHash == dbState.getLastDataHash() && !dbState.getDBName().empty())
            {
                LOG_DEBUG("[IOC::Sync] No changes detected for IOC type '{}'", dbState.getIocType());
                continue;
            }

            LOG_INFO("[IOC::Sync] Changes detected for IOC type '{}', updating...", dbState.getIocType());

            // Generate temporary database name for downloading
            const auto tempDBName = generateDBName(dbState.getIocType());

            // Always use the fixed target database name
            const auto targetDBName = generateTargetDBName(dbState.getIocType());

            // Download and populate the temporary database
            try
            {
                downloadAndPopulateDB(dbState.getIocType(), tempDBName);
            }
            catch (const std::exception& e)
            {
                LOG_ERROR("[IOC::Sync] Failed to download IOCs for type '{}': {}", dbState.getIocType(), e.what());
                continue;
            }

            // Perform atomic hot-swap if there's an old database
            if (!dbState.getDBName().empty())
            {
                try
                {
                    kvdbiocPtr->hotSwap(tempDBName, targetDBName);
                    LOG_INFO("[IOC::Sync] Successfully hot-swapped database for IOC type '{}'", dbState.getIocType());
                }
                catch (const std::exception& e)
                {
                    // Rollback temporary database
                    try
                    {
                        kvdbiocPtr->remove(tempDBName);
                    }
                    catch (const std::exception& ex)
                    {
                        LOG_WARNING(
                            "[IocSync::synchronize] Failed to rollback temporary database '{}' after swap failure: {}",
                            tempDBName,
                            ex.what());
                    }
                    LOG_ERROR("[IOC::Sync] Failed to hot-swap database for IOC type '{}': {}",
                              dbState.getIocType(),
                              e.what());
                    continue;
                }
            }
            else
            {
                // First time setup - rename temporary DB to target name
                try
                {
                    // Create an empty target DB first
                    kvdbiocPtr->add(targetDBName);
                    // Then swap the populated temp DB into it
                    kvdbiocPtr->hotSwap(tempDBName, targetDBName);
                    LOG_INFO("[IOC::Sync] Created initial database '{}' for IOC type '{}'",
                             targetDBName,
                             dbState.getIocType());
                }
                catch (const std::exception& e)
                {
                    // Rollback temporary database
                    try
                    {
                        kvdbiocPtr->remove(tempDBName);
                    }
                    catch (const std::exception& ex)
                    {
                        LOG_WARNING("[IocSync::synchronize] Failed to rollback temporary database '{}': {}",
                                    tempDBName,
                                    ex.what());
                    }
                    LOG_ERROR("[IOC::Sync] Failed to create initial database for IOC type '{}': {}",
                              dbState.getIocType(),
                              e.what());
                    continue;
                }
            }

            // Update the database name to the target (fixed) name
            dbState.setDBName(targetDBName);

            // Update and save the sync state
            dbState.setLastDataHash(remoteHash);
            try
            {
                saveStateToStore();
            }
            catch (const std::exception& e)
            {
                LOG_WARNING("[IOC::Sync] Failed to save sync state to store after synchronization: {}", e.what());
            }

            LOG_INFO("[IOC::Sync] Successfully synchronized IOC type '{}'", dbState.getIocType());
        }
        catch (const std::exception& e)
        {
            LOG_WARNING(
                "[IOC::Sync] Failed to synchronize database for IOC type '{}': {}", dbState.getIocType(), e.what());
        }
    }

    LOG_DEBUG("[IOC::Sync] Finished synchronization of IOC databases");
}

} // namespace ioc::sync
