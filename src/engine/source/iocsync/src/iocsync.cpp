#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include <fmt/format.h>

#include <base/error.hpp>
#include <base/json.hpp>
#include <base/logging.hpp>
#include <base/name.hpp>
#include <base/utils/generator.hpp>
#include <base/utils/retryUtils.hpp>

#include <iocsync/iocsync.hpp>

namespace
{

const base::Name STORE_NAME_IOCSYNC {"iocsync/status/0"}; ///< Name of the internal store document
constexpr std::size_t IOC_SYNC_BATCH_SIZE {1000};         ///< Documents per search page for IOC sync

void ensureTargetDbExists(const std::shared_ptr<kvdbioc::IKVDBManager>& kvdbiocPtr, std::string_view targetDBName)
{
    // Check if handle exists and has a valid instance
    if (kvdbiocPtr->hasInstance(targetDBName))
    {
        return;
    }

    try
    {
        // If handle exists but has no instance, remove it first
        if (kvdbiocPtr->exists(targetDBName))
        {
            LOG_WARNING("[IOC::Sync] Target database '{}' exists but has no instance, removing handle", targetDBName);
            kvdbiocPtr->remove(targetDBName);
        }

        kvdbiocPtr->add(targetDBName);
        LOG_INFO("[IOC::Sync] Created target database '{}'", targetDBName);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Failed to ensure target database '{}': {}", targetDBName, e.what()));
    }
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
    std::string m_iocType;      ///< IOC type from document.type (e.g., ipv4-addr, domain-name, url, file)
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
    , m_attempts(3)
    , m_waitSeconds(5)
{
    // Check if is the first setup
    if (storePtr->existsDoc(STORE_NAME_IOCSYNC))
    {
        loadStateFromStore();
        return;
    }

    LOG_INFO("[IOC::Sync] First setup detected, initializing default IOC types to sync");

    // Add default IOC types to sync from indexer connector policy
    for (const auto& iocType : indexerPtr->getDefaultIocTypes())
    {
        addIOCTypeToSync(iocType);
    }
    saveStateToStore();
}

IocSync::~IocSync() = default;

bool IocSync::existIocDataInRemote()
{
    auto indexerPtr = base::utils::lockWeakPtr(m_indexerPtr, "IndexerConnector");

    return base::utils::executeWithRetry([&indexerPtr]() { return indexerPtr->existsIocDataIndex(); },
                                         "exist IOC data index in wazuh-indexer",
                                         "IocSync",
                                         m_attempts,
                                         m_waitSeconds);
}

std::unordered_map<std::string, std::string> IocSync::getRemoteHashesFromRemote()
{
    auto indexerPtr = base::utils::lockWeakPtr(m_indexerPtr, "Indexer Connector");

    return base::utils::executeWithRetry([&indexerPtr]() { return indexerPtr->getIocTypeHashes(); },
                                         "getRemoteHashesFromRemote",
                                         "IocSync",
                                         m_attempts,
                                         m_waitSeconds);
}

void IocSync::downloadAndPopulateDB(std::string_view iocType, const std::string& dbName)
{
    auto indexerPtr = base::utils::lockWeakPtr(m_indexerPtr, "IndexerConnector");
    auto kvdbiocPtr = base::utils::lockWeakPtr(m_kvdbiocManagerPtr, "KVDBIOCManager");

    LOG_INFO("[IOC::Sync] Downloading IOCs of type '{}' to database '{}'", iocType, dbName);

    // Create the database
    kvdbiocPtr->add(dbName);

    try
    {
        std::size_t processedDocs = 0;
        std::size_t stored = 0;
        std::size_t duplicates = 0;
        std::unordered_set<std::string> seenKeys;

        LOG_INFO("[IOC::Sync] Starting filtered download for type '{}'", iocType);

        processedDocs = indexerPtr->streamIocsByType(
            iocType,
            IOC_SYNC_BATCH_SIZE,
            [&stored, &duplicates, &seenKeys, &kvdbiocPtr, &dbName](const std::string& key, const std::string& value)
            {
                if (seenKeys.emplace(key).second)
                {
                    kvdbiocPtr->put(dbName, key, value);
                    stored++;
                    return;
                }

                auto existingValue = kvdbiocPtr->get(dbName, key);
                if (!existingValue.has_value())
                {
                    kvdbiocPtr->put(dbName, key, value);
                    stored++;
                    return;
                }

                json::Json mergedValue {};
                if (existingValue->isArray())
                {
                    mergedValue = json::Json {existingValue->str().c_str()};
                }
                else
                {
                    mergedValue.setArray();
                    mergedValue.appendJson(*existingValue);
                }

                mergedValue.appendJson(json::Json {value.c_str()});
                kvdbiocPtr->put(dbName, key, mergedValue.str());
                duplicates++;
            });

        LOG_INFO("[IOC::Sync] Successfully downloaded {} IOCs of type '{}' to database '{}' (processed {} docs, "
                 "duplicates: {})",
                 stored,
                 iocType,
                 dbName,
                 processedDocs,
                 duplicates);

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
    auto storePtr = base::utils::lockWeakPtr(m_store, "Store");

    auto optDoc = storePtr->readDoc(STORE_NAME_IOCSYNC);
    if (base::isError(optDoc))
    {
        throw std::runtime_error(
            fmt::format("Failed to load iocsync state from store: {}", base::getError(optDoc).message));
    }

    const auto& j = base::getResponse(optDoc);

    std::optional<std::vector<json::Json>> optArrayConf;

    if (j.isArray())
    {
        optArrayConf = j.getArray();
    }
    else if (j.isObject())
    {
        optArrayConf = j.getArray("/databases");
    }

    if (!optArrayConf.has_value())
    {
        throw std::runtime_error("IocSync::loadStateFromStore: Invalid iocsync state document");
    }

    m_databasesState.clear();
    for (const auto& jSyncedDB : *optArrayConf)
    {
        m_databasesState.emplace_back(SyncedIOCDatabase::fromJson(jSyncedDB));
    }
}

void IocSync::saveStateToStore()
{
    auto storePtr = base::utils::lockWeakPtr(m_store, "StoreInternal");

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

    const auto kvdbiocPtr = base::utils::lockWeakPtr(m_kvdbiocManagerPtr, "KVDBIOCManager");
    std::unique_lock lock(m_mutex); // Lock the sync process, only 1 at a time

    std::unordered_map<std::string, std::string> remoteTypeHashes;
    bool canProceed = true;

    try
    {
        const bool remoteExists = existIocDataInRemote();
        if (!remoteExists)
        {
            LOG_WARNING("[IOC::Sync] Remote IOC data index does not exist; skipping sync cycle");
            canProceed = false;
        }
        else
        {
            remoteTypeHashes = getRemoteHashesFromRemote();
        }
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("[IOC::Sync] Failed to query remote IOC hashes/index: {}", e.what());
        canProceed = false;
    }

    if (canProceed)
    {
        bool stateChanged = false;
        for (auto& dbState : m_databasesState)
        {
            try
            {
                LOG_DEBUG("[IOC::Sync] Synchronizing database for IOC type '{}'", dbState.getIocType());

                const auto remoteHashIt = remoteTypeHashes.find(dbState.getIocType());
                if (remoteHashIt == remoteTypeHashes.end())
                {
                    LOG_WARNING("[IOC::Sync] Hash not found for IOC type '{}', skipping", dbState.getIocType());
                    continue;
                }

                const auto& remoteHash = remoteHashIt->second;

                // Always use the fixed target database name
                const auto targetDBName = fmt::format("ioc-{}", dbState.getIocType());

                // Check if the database has a valid instance (handles physical deletion recovery)
                const bool hasValidInstance = kvdbiocPtr->hasInstance(targetDBName);

                // Check if the data has changed or if the database instance is missing
                if (remoteHash == dbState.getLastDataHash() && !dbState.getDBName().empty() && hasValidInstance)
                {
                    LOG_DEBUG("[IOC::Sync] No changes detected for IOC type '{}'", dbState.getIocType());
                    continue;
                }

                if (!hasValidInstance)
                {
                    LOG_WARNING("[IOC::Sync] Database '{}' for IOC type '{}' has no valid instance (physical "
                                "deletion detected), forcing full resync",
                                targetDBName,
                                dbState.getIocType());
                }
                else
                {
                    LOG_INFO("[IOC::Sync] Changes detected for IOC type '{}', updating...", dbState.getIocType());
                }

                // Generate temporary database name for downloading
                const auto tempDBName =
                    fmt::format("iocsync_{}_{}", dbState.getIocType(), base::utils::generators::randomHexString(4));

                // Download and populate the temporary database
                try
                {
                    downloadAndPopulateDB(dbState.getIocType(), tempDBName);
                }
                catch (const std::exception& e)
                {
                    LOG_WARNING(
                        "[IOC::Sync] Failed to download IOCs for type '{}': {}", dbState.getIocType(), e.what());
                    continue;
                }

                // Ensure target DB handler exists (important after KVDB root purge + persisted iocsync state)
                try
                {
                    ensureTargetDbExists(kvdbiocPtr, targetDBName);
                }
                catch (const std::exception& e)
                {
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
                    LOG_WARNING("[IOC::Sync] Failed to ensure target database for IOC type '{}': {}",
                                dbState.getIocType(),
                                e.what());
                    continue;
                }

                // Perform atomic hot-swap
                try
                {
                    kvdbiocPtr->hotSwap(tempDBName, targetDBName);
                    LOG_DEBUG("[IOC::Sync] Successfully hot-swapped database for IOC type '{}'", dbState.getIocType());
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
                    LOG_WARNING("[IOC::Sync] Failed to hot-swap database for IOC type '{}': {}",
                                dbState.getIocType(),
                                e.what());
                    continue;
                }

                // Update the database name to the target (fixed) name
                dbState.setDBName(targetDBName);

                // Update and save the sync state
                dbState.setLastDataHash(remoteHash);
                stateChanged = true;

                LOG_INFO("[IOC::Sync] Successfully synchronized IOC type '{}'", dbState.getIocType());
            }
            catch (const std::exception& e)
            {
                LOG_WARNING(
                    "[IOC::Sync] Failed to synchronize database for IOC type '{}': {}", dbState.getIocType(), e.what());
            }
        }

        if (stateChanged)
        {
            try
            {
                saveStateToStore();
            }
            catch (const std::exception& e)
            {
                LOG_WARNING("[IOC::Sync] Failed to save sync state to store: {}", e.what());
            }
        }

        LOG_DEBUG("[IOC::Sync] Finished synchronization of IOC databases");
    }
}

} // namespace ioc::sync
