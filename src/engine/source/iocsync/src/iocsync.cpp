// SPDX-License-Identifier: AGPL-3.0-or-later
#include <ctime>
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
#include <cmcontent/engineTokenStore.hpp>
#include <iockvdb/helpers.hpp>

#include <iocsync/iocsync.hpp>

namespace
{

const base::Name STORE_NAME_IOCSYNC {"iocsync/status/0"};
const std::string COMPONENT_NAME {"IOC::Sync"};

constexpr std::string_view JPATH_IOC_TYPE {"/ioc_type"};
constexpr std::string_view JPATH_LAST_DATA_HASH {"/last_data_hash"};
constexpr std::string_view JPATH_LAST_SUCCESSFUL_UPDATE {"/last_successful_update"};

} // namespace

namespace ioc::sync
{

IocSync::IocSync(const std::shared_ptr<ioc::kvdb::IKVDBManager>& kvdbiocManagerPtr,
                 const std::shared_ptr<::store::IStore>& storePtr,
                 const cmcontent::TopicFactory& topicFactory,
                 const cmcontent::Options& contentOptions,
                 cmcontent::RetryPolicy retry)
    : m_kvdbiocManagerPtr(kvdbiocManagerPtr)
    , m_store(storePtr)
    , m_retry(retry)
{
    if (!topicFactory)
    {
        throw std::invalid_argument {"IocSync needs a topic factory"};
    }

    const auto& supported = ioc::kvdb::details::getSupportedIocTypes();
    m_types.reserve(supported.size());
    for (const auto& name : supported)
    {
        IocType type;
        type.type = std::string {name};
        type.targetDb = std::string {ioc::kvdb::details::getDbNameFromType(type.type)};
        type.sink = std::make_shared<cmcontent::IocTypeSink>(kvdbiocManagerPtr, type.type);
        m_types.push_back(std::move(type));
    }

    loadState();

    for (std::size_t index = 0; index < m_types.size(); ++index)
    {
        // The token is the type's persisted hash, read and written only from inside synchronize().
        auto tokenStore = std::make_shared<cmcontent::EngineTokenStore>(
            [this, index](std::string_view) { return m_types[index].hash; },
            [this, index](std::string_view, std::string_view token)
            {
                if (m_types[index].hash != token)
                {
                    m_types[index].hash = std::string {token};
                    m_stateChanged = true;
                }
                return true;
            });

        auto& type = m_types[index];
        type.topic = topicFactory(
            cmcontent::iocTopic(type.type), cmcontent::iocSpec(type.type, contentOptions), type.sink, tokenStore);
    }

    publishStatus();
}

IocSync::~IocSync() = default;

void IocSync::synchronize()
{
    std::lock_guard<std::mutex> lock {m_syncMutex};
    LOG_DEBUG("[{}] Checking for IOC database updates", COMPONENT_NAME);

    const auto kvdb = base::utils::lockWeakPtr(m_kvdbiocManagerPtr, "KVDBIOCManager");
    m_stateChanged = false;
    for (auto& type : m_types)
    {
        if (m_shutdownRequested.load())
        {
            LOG_INFO("[{}] Synchronization aborted by shutdown", COMPONENT_NAME);
            break;
        }
        syncType(type, *kvdb);
    }
    publishStatus();

    if (m_stateChanged)
    {
        try
        {
            persistState();
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("[{}] Failed to persist the sync state: {}", COMPONENT_NAME, e.what());
        }
    }
}

void IocSync::syncType(IocType& type, const ioc::kvdb::IKVDBManager& kvdb)
{
    using content_manager::CycleStatus;

    const auto previous = type.status;
    type.status = base::SyncStatus::UPDATING;
    publishStatus();

    // A matching hash says the *content* has not moved, not that its database still exists: a
    // missing one is rebuilt by a forced full reload.
    content_manager::RunRequest request;
    if (!kvdb.exists(type.targetDb))
    {
        if (!type.hash.empty())
        {
            LOG_WARNING("[{}] Database '{}' for IOC type '{}' is missing; forcing a full resync",
                        COMPONENT_NAME,
                        type.targetDb,
                        type.type);
        }
        request.forceFullReload = true;
    }

    const auto outcome = cmcontent::runWithRetries(*type.topic,
                                                   request,
                                                   m_retry,
                                                   m_shutdownRequested,
                                                   COMPONENT_NAME,
                                                   fmt::format("Synchronize IOC type '{}'", type.type));

    switch (outcome.status)
    {
        case CycleStatus::Updated:
            type.lastSuccessfulUpdate = static_cast<std::uint32_t>(std::time(nullptr));
            type.status = base::SyncStatus::READY;
            m_stateChanged = true;
            break;

        case CycleStatus::Unchanged: type.status = base::SyncStatus::READY; break;

        case CycleStatus::SkippedConsumerNotReady:
        case CycleStatus::SkippedPreconditionUnmet:
            // Deferred, not failed: the database in force is still usable.
            LOG_DEBUG("[{}] Synchronization of IOC type '{}' deferred: {}", COMPONENT_NAME, type.type, outcome.detail);
            type.status = base::SyncStatus::READY;
            break;

        case CycleStatus::SkippedStopRequested:
        case CycleStatus::SkippedAlreadyRunning:
            // Nothing ran, so nothing was observed.
            type.status = previous;
            break;

        case CycleStatus::FailedTransport:
        case CycleStatus::FailedSink:
        case CycleStatus::FailedConfig:
            LOG_WARNING("[{}] Failed to synchronize IOC type '{}': {}", COMPONENT_NAME, type.type, outcome.detail);
            type.status = base::SyncStatus::FAILED;
            break;
    }
}

void IocSync::loadState()
{
    auto storePtr = base::utils::lockWeakPtr(m_store, "Store");
    if (!storePtr->existsDoc(STORE_NAME_IOCSYNC))
    {
        return;
    }

    const auto doc = storePtr->readDoc(STORE_NAME_IOCSYNC);
    if (base::isError(doc))
    {
        throw std::runtime_error(
            fmt::format("Failed to load iocsync state from store: {}", base::getError(doc).message));
    }

    const auto& stored = base::getResponse(doc);
    const auto entries = stored.isArray() ? stored.getArray() : stored.getArray("/databases");
    if (!entries.has_value())
    {
        throw std::runtime_error("Invalid iocsync state document");
    }

    for (const auto& entry : *entries)
    {
        std::string name;
        if (entry.getString(name, JPATH_IOC_TYPE) != json::RetGet::Success)
        {
            continue;
        }
        for (auto& type : m_types)
        {
            if (type.type != name)
            {
                continue;
            }
            if (std::string hash; entry.getString(hash, JPATH_LAST_DATA_HASH) == json::RetGet::Success)
            {
                type.hash = std::move(hash);
            }
            if (const auto ts = entry.getInt64(JPATH_LAST_SUCCESSFUL_UPDATE); ts.has_value())
            {
                type.lastSuccessfulUpdate = static_cast<std::uint32_t>(*ts);
            }
        }
    }
}

void IocSync::persistState()
{
    auto storePtr = base::utils::lockWeakPtr(m_store, "Store");

    json::Json doc {};
    doc.setArray();
    for (const auto& type : m_types)
    {
        json::Json entry {};
        entry.setString(type.type, JPATH_IOC_TYPE);
        entry.setString(type.hash, JPATH_LAST_DATA_HASH);
        entry.setInt64(static_cast<int64_t>(type.lastSuccessfulUpdate), JPATH_LAST_SUCCESSFUL_UPDATE);
        doc.appendJson(entry);
    }

    if (auto error = storePtr->upsertDoc(STORE_NAME_IOCSYNC, doc); base::isError(error))
    {
        throw std::runtime_error(
            fmt::format("Failed to save iocsync state to store: {}", base::getError(error).message));
    }
}

void IocSync::publishStatus()
{
    const auto kvdb = m_kvdbiocManagerPtr.lock();

    std::vector<IocTypeStatus> statuses;
    statuses.reserve(m_types.size());
    for (const auto& type : m_types)
    {
        IocTypeStatus status;
        status.type = type.type;
        status.hash = type.hash;
        status.status = type.status;
        status.available = !type.hash.empty() && kvdb && kvdb->exists(type.targetDb);
        status.lastSuccessfulUpdate = type.lastSuccessfulUpdate;
        statuses.push_back(std::move(status));
    }
    m_status.store(std::move(statuses));
}

void IocSync::requestShutdown()
{
    m_shutdownRequested.store(true);
    for (auto& type : m_types)
    {
        type.topic->requestStop();
    }
    LOG_INFO("[{}] Shutdown requested", COMPONENT_NAME);
}

std::vector<IocTypeStatus> IocSync::getIocStatus() const
{
    return *m_status.load();
}

} // namespace ioc::sync
