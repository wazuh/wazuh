#include <ctime>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <fmt/format.h>

#include <base/error.hpp>
#include <base/json.hpp>
#include <base/logging.hpp>
#include <base/name.hpp>
#include <base/utils/metaHelpers.hpp>
#include <base/utils/vectorHelpers.hpp>
#include <cmcontent/contentTopic.hpp>
#include <contentOnDemand.hpp>
#include <iockvdb/helpers.hpp>

#include <iocsync/iocsync.hpp>

namespace
{

const base::Name STORE_NAME_IOCSYNC {"iocsync/status/0"}; ///< Name of the internal store document
constexpr std::string_view COMPONENT_NAME = "IOC::Sync";  ///< Component name for logging

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
    uint32_t m_lastSuccessfulUpdate {0};                     ///< Unix timestamp of last successful sync
    base::SyncStatus m_syncStatus {base::SyncStatus::READY}; ///< Per-type sync status

    static constexpr std::string_view JPATH_IOC_TYPE = "/ioc_type";             ///< JSON path for IOC type
    static constexpr std::string_view JPATH_LAST_DATA_HASH = "/last_data_hash"; ///< JSON path for last data hash
    static constexpr std::string_view JPATH_LAST_SUCCESSFUL_UPDATE =
        "/last_successful_update"; ///< JSON path for last successful update timestamp

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
    uint32_t getLastSuccessfulUpdate() const { return m_lastSuccessfulUpdate; }
    void setLastSuccessfulUpdate(uint32_t ts) { m_lastSuccessfulUpdate = ts; }
    base::SyncStatus getSyncStatus() const { return m_syncStatus; }
    void setSyncStatus(base::SyncStatus s) { m_syncStatus = s; }

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
        j.setInt64(static_cast<int64_t>(m_lastSuccessfulUpdate), JPATH_LAST_SUCCESSFUL_UPDATE);
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
        std::string iocType;
        if (j.getString(iocType, JPATH_IOC_TYPE) != json::RetGet::Success || iocType.empty())
        {
            throw std::runtime_error("SyncedIOCDatabase::fromJson: Missing/empty ioc_type field");
        }

        std::string lastHash;
        if (j.getString(lastHash, JPATH_LAST_DATA_HASH) != json::RetGet::Success)
        {
            throw std::runtime_error("SyncedIOCDatabase::fromJson: Missing last_data_hash field");
        }

        SyncedIOCDatabase db {iocType, lastHash};
        // Restore the last successful update timestamp if present (absent in older state documents).
        if (const auto ts = j.getInt64(JPATH_LAST_SUCCESSFUL_UPDATE); ts.has_value())
        {
            db.setLastSuccessfulUpdate(static_cast<uint32_t>(*ts));
        }
        return db;
    }
};

IocSync::IocSync(const std::shared_ptr<wiconnector::IWIndexerConnector>& indexerPtr,
                 const std::shared_ptr<ioc::kvdb::IKVDBManager>& kvdbiocManagerPtr,
                 const std::shared_ptr<::store::IStore>& storePtr,
                 nlohmann::json indexerConnection,
                 const size_t maxRetries,
                 const size_t retryIntervalSeconds,
                 cmcontent::Options contentOptions,
                 cmcontent::TopicFactory topicFactory)
    : m_indexerPtr(indexerPtr)
    , m_kvdbiocManagerPtr(kvdbiocManagerPtr)
    , m_store(storePtr)
    , m_attempts(maxRetries)
    , m_waitSeconds(retryIntervalSeconds)
    , m_indexerConnection(std::move(indexerConnection))
    , m_contentOptions(std::move(contentOptions))
    , m_topicFactory(topicFactory ? std::move(topicFactory) : cmcontent::defaultTopicFactory())
    , m_mutex()
{
    // Check if is the first setup
    if (storePtr->existsDoc(STORE_NAME_IOCSYNC))
    {
        loadStateFromStore();

        std::unique_lock lock(m_mutex);
        for (const auto& dbState : m_databasesState)
        {
            registerTopic(dbState.getIocType(), dbState.getLastDataHash());
        }
        lock.unlock();

        updateIocStatusSnapshot(); // Publish initial status
        return;
    }

    LOG_INFO("[{}] First setup detected, initializing default IOC types to sync", COMPONENT_NAME);

    // Add default IOC types to sync from indexer connector policy. Each call persists the state, so
    // no extra write is needed afterwards.
    for (const auto& iocType : ioc::kvdb::details::getSupportedIocTypes())
    {
        addIOCTypeToSync(iocType);
    }
    updateIocStatusSnapshot(); // Publish initial status
}

IocSync::~IocSync() = default;

bool IocSync::existIocDataInRemote()
{
    auto indexerPtr = base::utils::lockWeakPtr(m_indexerPtr, "IndexerConnector");

    return base::utils::executeWithRetry([&indexerPtr]() { return indexerPtr->existsIocDataIndex(); },
                                         fmt::format("{}", COMPONENT_NAME),
                                         "Check if IOC data index exists in wazuh-indexer",
                                         m_attempts,
                                         m_waitSeconds,
                                         m_shutdownRequested);
}

void IocSync::registerTopic(std::string_view iocType, const std::string& initialToken)
{
    const auto topicName = cmcontent::iocTopic(iocType);

    {
        std::lock_guard<std::mutex> containerLock(m_registrationsMutex);
        if (m_registrations.find(topicName) != m_registrations.end())
        {
            return;
        }
    }

    Registration registration;
    registration.sink = std::make_shared<cmcontent::IocTypeSink>(m_kvdbiocManagerPtr, std::string {iocType});

    // The cycle reads and writes the token through this cell, never through m_databasesState. An
    // on-demand cycle runs on a content-manager lane worker while this object's own sync thread may
    // be iterating that vector under m_mutex, so a token store reaching into it would be a data race
    // on a std::string — and on the vector itself, which add/remove can reallocate.
    registration.token = std::make_shared<cmcontent::TokenCell>(initialToken);

    registration.topic = m_topicFactory(topicName,
                                        cmcontent::iocParameters(m_indexerConnection, iocType, m_contentOptions),
                                        registration.sink,
                                        cmcontent::cellTokenStore(registration.token));

    std::lock_guard<std::mutex> containerLock(m_registrationsMutex);
    m_registrations.emplace(topicName, std::move(registration));
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
    registerTopic(iocType, {});

    LOG_INFO("[{}] Added IOC type '{}' to the sync list", COMPONENT_NAME, iocType);

    saveStateToStore();
}

void IocSync::removeIOCTypeFromSync(std::string_view iocType)
{
    // Moved out under the lock and destroyed after it is released. ~ContentRegister blocks until
    // any in-flight cycle for that topic has drained, and that cycle reaches back into this object
    // through the token store; destroying it while holding m_mutex would deadlock against itself.
    Registration doomed;

    {
        std::unique_lock lock(m_mutex);

        // addIOCTypeToSync() rejects duplicates, so at most one element can match here. Element order in
        // m_databasesState is not semantically observed, so this is removed in O(1) via swap-with-back.
        const auto erased = base::utils::eraseFirstBySwap(
            m_databasesState, [iocType](const SyncedIOCDatabase& syncedDB) { return syncedDB.getIocType() == iocType; });
        if (!erased)
        {
            throw std::runtime_error(fmt::format("IOC type '{}' is not in the sync list", iocType));
        }

        {
            std::lock_guard<std::mutex> containerLock(m_registrationsMutex);
            if (const auto it = m_registrations.find(cmcontent::iocTopic(iocType)); it != m_registrations.end())
            {
                doomed = std::move(it->second);
                m_registrations.erase(it);
            }
        }

        LOG_INFO("[{}] Removed IOC type '{}' from the sync list", COMPONENT_NAME, iocType);

        saveStateToStore();
    }
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

bool IocSync::syncIOCType(SyncedIOCDatabase& dbState, const std::shared_ptr<ioc::kvdb::IKVDBManager>& kvdbiocPtr)
{
    const auto topicName = cmcontent::iocTopic(dbState.getIocType());

    Registration* registration = nullptr;
    {
        std::lock_guard<std::mutex> containerLock(m_registrationsMutex);
        const auto it = m_registrations.find(topicName);
        if (it == m_registrations.end())
        {
            LOG_WARNING("[{}] No content registration for IOC type '{}'", COMPONENT_NAME, dbState.getIocType());
            return false;
        }
        registration = &it->second;
    }

    content_manager::RunRequest request;

    // A hash that matches the remote one means the *content* has not moved — it says nothing about
    // whether the database holding it still exists. A physically deleted database has to be
    // rebuilt, and the only way to express that is to ask for a forced full reload: the cycle would
    // otherwise decide there is nothing to fetch and deliver no documents to swap in.
    const auto targetDbName = ioc::kvdb::details::getDbNameFromType(dbState.getIocType());
    if (!kvdbiocPtr->exists(targetDbName))
    {
        if (!dbState.getLastDataHash().empty())
        {
            LOG_WARNING("[{}] Database '{}' for IOC type '{}' has no valid instance (physical deletion detected), "
                        "forcing full resync",
                        COMPONENT_NAME,
                        targetDbName,
                        dbState.getIocType());
        }
        request.forceFullReload = true;
    }

    content_manager::CycleOutcome outcome;
    try
    {
        // executeWithRetry retries on a thrown exception, but runOnce is noexcept and reports by
        // status, so a retryable outcome is rethrown here to drive it. The existing
        // analysisd.ioc_indexer_connector_{max_retries,retry_interval} keys keep their meaning and
        // now guard the whole cycle instead of a single query.
        outcome = base::utils::executeWithRetry(
            [&]()
            {
                auto result = registration->topic->runOnce(request);
                if (result.retryAfter.count() > 0)
                {
                    throw std::runtime_error(result.detail);
                }
                return result;
            },
            fmt::format("{}", COMPONENT_NAME),
            fmt::format("Synchronize IOC type '{}'", dbState.getIocType()),
            m_attempts,
            m_waitSeconds,
            m_shutdownRequested);
    }
    catch (const std::exception& e)
    {
        LOG_WARNING(
            "[{}] Failed to synchronize IOC type '{}': {}", COMPONENT_NAME, dbState.getIocType(), e.what());
        // An on-demand cycle may have committed a new hash while this one was failing; reconciling
        // regardless is what keeps the persisted state from contradicting the database on disk.
        return reconcileToken(dbState, *registration);
    }

    if (outcome.status == content_manager::CycleStatus::SkippedAlreadyRunning)
    {
        // An on-demand update for this type is in flight. Nothing was observed here, so nothing is
        // concluded here either: the type keeps whatever status it had, and the next scheduled pass
        // picks up whatever that cycle committed. Reporting this as a failure would flip a healthy
        // type to FAILED purely because the API had been used a moment earlier.
        LOG_DEBUG("[{}] An update for IOC type '{}' was already running; leaving its state untouched",
                  COMPONENT_NAME,
                  dbState.getIocType());
        return reconcileToken(dbState, *registration);
    }

    const bool tokenChanged = reconcileToken(dbState, *registration);

    if (outcome.status == content_manager::CycleStatus::Updated)
    {
        dbState.setLastSuccessfulUpdate(static_cast<uint32_t>(std::time(nullptr)));
        return true;
    }

    if (outcome.status == content_manager::CycleStatus::Unchanged)
    {
        LOG_DEBUG("[{}] No changes detected for IOC type '{}'", COMPONENT_NAME, dbState.getIocType());
    }

    return tokenChanged;
}

bool IocSync::reconcileToken(SyncedIOCDatabase& dbState, const Registration& registration)
{
    if (!registration.token)
    {
        return false;
    }

    auto token = registration.token->get();
    if (token == dbState.getLastDataHash())
    {
        return false;
    }

    dbState.setLastDataHash(token);
    return true;
}

void IocSync::synchronize()
{
    LOG_DEBUG("[{}] Checking for IOC database updates to synchronize", COMPONENT_NAME);

    if (m_shutdownRequested.load(std::memory_order_relaxed))
    {
        LOG_INFO("[{}] Synchronization aborted before start", COMPONENT_NAME);
        return;
    }

    try
    {
        // Lock weak pointers and acquire mutex
        const auto kvdbiocPtr = base::utils::lockWeakPtr(m_kvdbiocManagerPtr, "KVDBIOCManager");
        std::unique_lock lock(m_mutex);

        // Pre-flight check: verify the IOC consumer is ready AND has data (local_offset != 0).
        // The content cycle validates readiness again inside its own snapshot — that is the
        // correctness gate — but one cheap query here short-circuits every registration at once,
        // and it additionally covers local_offset, which the in-snapshot check does not.
        {
            auto indexerPtr = base::utils::lockWeakPtr(m_indexerPtr, "IndexerConnector");
            const bool ready = base::utils::executeWithRetry(
                [&indexerPtr]() { return indexerPtr->isConsumerReadyForSync(wiconnector::IOC_ENRICHMENT_CONSUMER_ID); },
                fmt::format("{}", COMPONENT_NAME),
                "Check IOC consumer readiness",
                m_attempts,
                m_waitSeconds,
                m_shutdownRequested);

            if (!ready)
            {
                LOG_INFO("[{}] IOC synchronization skipped because the wazuh-indexer consumer for IOCs is not ready "
                         "for sync (might be updating or no data yet)",
                         COMPONENT_NAME);
                reportSyncFailure(); // types without a usable version → FAILED (could not sync)
                return;
            }
        }

        // Check if remote index exists
        if (!existIocDataInRemote())
        {
            LOG_WARNING("[{}] Remote IOC data index does not exist; skipping sync cycle", COMPONENT_NAME);
            reportSyncFailure();
            return;
        }

        // Synchronize each IOC type
        bool stateChanged = false;
        for (auto& dbState : m_databasesState)
        {
            if (m_shutdownRequested.load(std::memory_order_relaxed))
            {
                LOG_INFO("[{}] Synchronization aborted during IOC type iteration", COMPONENT_NAME);
                updateIocStatusSnapshot();
                return;
            }

            // Mark this type as running and publish
            dbState.setSyncStatus(base::SyncStatus::UPDATING);
            updateIocStatusSnapshot();

            if (syncIOCType(dbState, kvdbiocPtr))
            {
                stateChanged = true;
            }

            dbState.setSyncStatus(base::SyncStatus::READY);
            updateIocStatusSnapshot();
        }

        // Save state if changed. One write per cycle, from the single thread that owns the state:
        // the token store deliberately only mutates memory for exactly this reason.
        if (stateChanged)
        {
            try
            {
                saveStateToStore();
            }
            catch (const std::exception& e)
            {
                LOG_WARNING("[{}] Failed to save sync state to store: {}", COMPONENT_NAME, e.what());
            }
        }

        LOG_DEBUG("[{}] Finished synchronization of IOC databases", COMPONENT_NAME);
    }
    catch (const std::exception& e)
    {
        if (m_shutdownRequested.load(std::memory_order_relaxed))
        {
            LOG_INFO("[{}] Synchronization aborted during remote operation", COMPONENT_NAME);
            // Reset any in-progress types
            for (auto& dbState : m_databasesState)
            {
                if (dbState.getSyncStatus() == base::SyncStatus::UPDATING)
                {
                    dbState.setSyncStatus(base::SyncStatus::READY);
                }
            }
            updateIocStatusSnapshot();
            return;
        }
        LOG_WARNING("[{}] Synchronization cycle failed: {}", COMPONENT_NAME, e.what());
        // Mark in-progress and never-synced types as failed (the failure may have occurred during the
        // pre-flight, before any type was set RUNNING).
        reportSyncFailure();
        return;
    }

    updateIocStatusSnapshot();
}

void IocSync::requestShutdown()
{
    m_shutdownRequested.store(true, std::memory_order_relaxed);

    // Wind down anything mid-cycle: without this, a registration destroyed during teardown would
    // block until its current page loop finished on its own. Only the container is locked here --
    // m_mutex is held by the very cycle this is trying to interrupt.
    std::lock_guard<std::mutex> containerLock(m_registrationsMutex);
    for (auto& [_, registration] : m_registrations)
    {
        if (registration.topic)
        {
            registration.topic->requestStop();
        }
    }

    LOG_INFO("[{}] Shutdown requested", COMPONENT_NAME);
}

std::vector<IocTypeStatus> IocSync::getIocStatus() const
{
    return *m_iocStatus.load();
}

void IocSync::requestOnDemandUpdate(std::string_view iocType)
{
    const auto wanted = iocType.empty() ? std::string {} : cmcontent::iocTopic(iocType);

    std::lock_guard<std::mutex> containerLock(m_registrationsMutex);
    for (const auto& [topicName, registration] : m_registrations)
    {
        if (!wanted.empty() && topicName != wanted)
        {
            continue;
        }

        content_manager::requestOnDemand(topicName,
                                         content_manager::RunRequest {false, true},
                                         [topicName](content_manager::OnDemandResult result)
                                         {
                                             if (result.code == content_manager::OnDemandCode::Completed)
                                             {
                                                 LOG_DEBUG("[{}] On-demand update of '{}' finished",
                                                           COMPONENT_NAME,
                                                           topicName);
                                                 return;
                                             }
                                             LOG_WARNING("[{}] On-demand update of '{}' was not run: {}",
                                                         COMPONENT_NAME,
                                                         topicName,
                                                         result.detail);
                                         });
    }
}

void IocSync::updateIocStatusSnapshot()
{
    // Full rebuild from m_databasesState (sync-thread working state), then publish atomically.
    auto kvdbiocPtr = m_kvdbiocManagerPtr.lock();

    std::vector<IocTypeStatus> result;
    result.reserve(m_databasesState.size());

    for (const auto& dbState : m_databasesState)
    {
        IocTypeStatus entry;
        entry.type = dbState.getIocType();
        entry.hash = dbState.getLastDataHash();
        entry.status = dbState.getSyncStatus();

        if (!entry.hash.empty() && kvdbiocPtr)
        {
            entry.available = kvdbiocPtr->exists(ioc::kvdb::details::getDbNameFromType(dbState.getIocType()));
        }

        entry.lastSuccessfulUpdate = dbState.getLastSuccessfulUpdate();
        result.push_back(std::move(entry));
    }

    m_iocStatus.store(std::move(result));
}

void IocSync::reportSyncFailure()
{
    for (auto& dbState : m_databasesState)
    {
        // No usable version yet, or interrupted mid-sync → the failed attempt is reflected as FAILED.
        // A type that already holds a version (non-empty hash, not running) stays as-is (usable).
        if (dbState.getLastDataHash().empty() || dbState.getSyncStatus() == base::SyncStatus::UPDATING)
        {
            dbState.setSyncStatus(base::SyncStatus::FAILED);
        }
    }
    updateIocStatusSnapshot();
}

} // namespace ioc::sync
