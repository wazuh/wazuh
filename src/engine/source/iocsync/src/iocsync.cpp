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
#include <base/utils/metaHelpers.hpp>
#include <base/utils/stringUtils.hpp>
#include <iockvdb/helpers.hpp>

#include <iocsync/iocsync.hpp>

namespace
{

const base::Name STORE_NAME_IOCSYNC {"iocsync/status/0"}; ///< Name of the internal store document
constexpr std::string_view COMPONENT_NAME = "IOCSync";    ///< Component name for logging

void ensureTargetDbExists(const std::shared_ptr<ioc::kvdb::IKVDBManager>& kvdbiocPtr, std::string_view targetDBName)
{
    // Check if handle exists and has a valid instance
    if (kvdbiocPtr->exists(targetDBName))
    {
        return;
    }

    try
    {
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
    std::string m_iocType;      ///< IOC type from document.type (e.g., connection, url_domain, url_full, hash_md5,
                                ///< hash_sha1, hash_sha256)
    std::string m_lastDataHash; ///< Last known data hash

    static constexpr std::string_view JPATH_IOC_TYPE = "/ioc_type";             ///< JSON path for IOC type
    static constexpr std::string_view JPATH_LAST_DATA_HASH = "/last_data_hash"; ///< JSON path for last data hash

public:
    SyncedIOCDatabase() = delete;
    explicit SyncedIOCDatabase(std::string_view iocType)
        : m_iocType(iocType)
        , m_lastDataHash()
    {
    }

    SyncedIOCDatabase(std::string_view iocType, std::string_view lastDataHash)
        : m_iocType(iocType)
        , m_lastDataHash(lastDataHash)
    {
    }

    /* Getters and Setters */
    const std::string& getIocType() const { return m_iocType; }
    const std::string& getLastDataHash() const { return m_lastDataHash; }
    void setLastDataHash(std::string_view hash) { m_lastDataHash = hash; }
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

        auto optLastHash = j.getString(JPATH_LAST_DATA_HASH);
        if (!optLastHash.has_value())
        {
            throw std::runtime_error("SyncedIOCDatabase::fromJson: Missing last_data_hash field");
        }

        return {*optIocType, *optLastHash};
    }
};

IocSync::IocSync(const std::shared_ptr<wiconnector::IWIndexerConnector>& indexerPtr,
                 const std::shared_ptr<ioc::kvdb::IKVDBManager>& kvdbiocManagerPtr,
                 const std::shared_ptr<::store::IStore>& storePtr,
                 const size_t maxRetries,
                 const size_t retryIntervalSeconds,
                 const size_t iocSyncBatchSize)
    : m_indexerPtr(indexerPtr)
    , m_kvdbiocManagerPtr(kvdbiocManagerPtr)
    , m_store(storePtr)
    , m_mutex()
    , m_attempts(maxRetries)
    , m_waitSeconds(retryIntervalSeconds)
    , m_iocSyncBatchSize(iocSyncBatchSize)
{
    // Check if is the first setup
    if (storePtr->existsDoc(STORE_NAME_IOCSYNC))
    {
        loadStateFromStore();
        return;
    }

    LOG_INFO("[IOC::Sync] First setup detected, initializing default IOC types to sync");

    // Add default IOC types to sync from indexer connector policy
    for (const auto& iocType : ioc::kvdb::details::getSupportedIocTypes())
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
                                         fmt::format("{}::existIocDataInRemote()", COMPONENT_NAME),
                                         "Check if IOC data index exists in remote indexer",
                                         m_attempts,
                                         m_waitSeconds);
}

std::unordered_map<std::string, std::string> IocSync::getRemoteHashesFromRemote()
{
    auto indexerPtr = base::utils::lockWeakPtr(m_indexerPtr, "Indexer Connector");

    return base::utils::executeWithRetry([&indexerPtr]() { return indexerPtr->getIocTypeHashes(); },
                                         fmt::format("{}::getRemoteHashesFromRemote()", COMPONENT_NAME),
                                         "Get IOC type hashes from remote indexer",
                                         m_attempts,
                                         m_waitSeconds);
}

void IocSync::downloadAndPopulateDB(std::string_view iocType, const std::string& dbName)
{
    auto indexerPtr = base::utils::lockWeakPtr(m_indexerPtr, "IndexerConnector");
    auto kvdbiocPtr = base::utils::lockWeakPtr(m_kvdbiocManagerPtr, "KVDBIOCManager");

    // Create the database
    kvdbiocPtr->add(dbName);

    try
    {
        std::size_t processedDocs = 0;
        std::size_t stored = 0;

        processedDocs = indexerPtr->streamIocsByType(
            iocType,
            m_iocSyncBatchSize,
            [&stored, &kvdbiocPtr, &dbName](const std::string& key, const std::string& value)
            {
                // Normalize key to lowercase for case-insensitive matching
                const auto normalizedKey = base::utils::string::toLowerCase(key);
                json::Json valueJson {value.c_str()};
                ioc::kvdb::details::updateValueInDB(kvdbiocPtr, dbName, normalizedKey, valueJson);
                stored++;
            });

        LOG_DEBUG("[IOC::Sync] Downloaded {} IOCs of type '{}' (processed {} docs)", stored, iocType, processedDocs);

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

bool IocSync::syncIOCType(SyncedIOCDatabase& dbState,
                          const std::unordered_map<std::string, std::string>& remoteTypeHashes,
                          const std::shared_ptr<ioc::kvdb::IKVDBManager>& kvdbiocPtr)
{
    try
    {
        LOG_DEBUG("[IOC::Sync] Synchronizing database for IOC type '{}'", dbState.getIocType());

        // Check if hash exists for this type
        const auto remoteHashIt = remoteTypeHashes.find(dbState.getIocType());
        if (remoteHashIt == remoteTypeHashes.end())
        {
            LOG_WARNING("[IOC::Sync] Hash not found for IOC type '{}', skipping", dbState.getIocType());
            return false;
        }

        const auto& remoteHash = remoteHashIt->second;
        const auto targetDBName = ioc::kvdb::details::getDbNameFromType(dbState.getIocType());
        const bool existDb = kvdbiocPtr->exists(targetDBName);

        // Check if sync is needed
        if (remoteHash == dbState.getLastDataHash() && existDb)
        {
            LOG_DEBUG("[IOC::Sync] No changes detected for IOC type '{}'", dbState.getIocType());
            return false;
        }

        // Log sync reason
        if (!existDb)
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

        // Download to temporary database
        const auto tempDBName =
            fmt::format("iocsync_{}_{}", dbState.getIocType(), base::utils::generators::randomHexString(4));

        try
        {
            downloadAndPopulateDB(dbState.getIocType(), tempDBName);
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("[IOC::Sync] Failed to download IOCs for type '{}': {}", dbState.getIocType(), e.what());
            return false;
        }

        // Ensure target DB exists
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
                LOG_WARNING("[IOC::Sync] Failed to rollback temporary database '{}': {}", tempDBName, ex.what());
            }
            LOG_WARNING(
                "[IOC::Sync] Failed to ensure target database for IOC type '{}': {}", dbState.getIocType(), e.what());
            return false;
        }

        // Perform atomic hot-swap
        try
        {
            kvdbiocPtr->hotSwap(tempDBName, targetDBName);
        }
        catch (const std::exception& e)
        {
            try
            {
                kvdbiocPtr->remove(tempDBName);
            }
            catch (const std::exception& ex)
            {
                LOG_WARNING("[IOC::Sync] Failed to rollback temporary database '{}' after swap failure: {}",
                            tempDBName,
                            ex.what());
            }
            LOG_WARNING(
                "[IOC::Sync] Failed to hot-swap database for IOC type '{}': {}", dbState.getIocType(), e.what());
            return false;
        }

        // Update state
        dbState.setLastDataHash(remoteHash);

        LOG_INFO("[IOC::Sync] Synchronized IOC type '{}'", dbState.getIocType());
        return true;
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("[IOC::Sync] Failed to synchronize database for IOC type '{}': {}", dbState.getIocType(), e.what());
        return false;
    }
}

void IocSync::synchronize()
{
    LOG_DEBUG("[IOC::Sync] Checking for IOC database updates to synchronize");

    try
    {
        // Lock weak pointers and acquire mutex
        const auto kvdbiocPtr = base::utils::lockWeakPtr(m_kvdbiocManagerPtr, "KVDBIOCManager");
        std::unique_lock lock(m_mutex);

        // Check if remote index exists
        if (!existIocDataInRemote())
        {
            LOG_WARNING("[IOC::Sync] Remote IOC data index does not exist; skipping sync cycle");
            return;
        }

        // Get remote hashes
        const auto remoteTypeHashes = getRemoteHashesFromRemote();

        // Synchronize each IOC type
        bool stateChanged = false;
        for (auto& dbState : m_databasesState)
        {
            if (syncIOCType(dbState, remoteTypeHashes, kvdbiocPtr))
            {
                stateChanged = true;
            }
        }

        // Save state if changed
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
    catch (const std::exception& e)
    {
        LOG_WARNING("[IOC::Sync] Synchronization cycle failed: {}", e.what());
    }
}

} // namespace ioc::sync
