/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "agent_sync_protocol.hpp"
#include "agent_sync_protocol_types.hpp"
#include "ipersistent_queue.hpp"
#include "persistent_queue.hpp"
#include "defs.h"
#include "metadata_provider.h"

#include <flatbuffers/flatbuffers.h>
#include <memory>
#include <set>

// Various synchronization functions write a SyncResult into `m_syncState.lastSyncResult`
// We use that to generate a std::string message which will be reported as a warning by each module (FIM, SCA, Syscollector, AgentInfo).
static std::string determineSyncFailureReasonBasedOnSyncResult(SyncResult result)
{
    std::string failureReason;

    switch (result)
    {
        case SyncResult::COMMUNICATION_ERROR:
            failureReason = "Failed to communicate with the manager.";
            break;


        case SyncResult::START_TIMEOUT_ERROR:
            failureReason = "Timed out waiting for manager response to Start message.";
            break;

        case SyncResult::END_TIMEOUT_ERROR:
            failureReason = "Timed out waiting for manager response to End message.";
            break;

        case SyncResult::PROTOCOL_ERROR:
            failureReason = "Manager sent an unexpected or invalid response.";
            break;

        case SyncResult::NO_GROUPS_ERROR:
            failureReason = "No groups available in metadata. Waiting for the server to synchronize the groups. Cannot proceed with synchronization.";
            break;

        // SyncResult::CHECKSUM_ERROR is not returned by either synchronizeModule() or synchronizeMetadataOrGroups()

        default:
            break;
    }

    return failureReason;
}

AgentSyncProtocol::AgentSyncProtocol(const std::string& moduleName, std::optional<std::string> dbPath, LoggerFunc logger,
                                     std::chrono::seconds timeout,
                                     unsigned int retries, std::shared_ptr<IPersistentQueue> queue,
                                     std::shared_ptr<ISyncSessionTransport> syncTransport)
    : m_moduleName(moduleName),
      m_persistentQueue(nullptr), // Ensure initialized to nullptr
      m_logger(std::move(logger)),
      m_timeout(timeout),
      m_retries(retries)
{
    if (!m_logger)
    {
        throw std::invalid_argument("Logger provided to AgentSyncProtocol cannot be null.");
    }

    try
    {
        if (queue)
        {
            m_persistentQueue = std::move(queue);
        }
        else if (dbPath.has_value())
        {
            m_persistentQueue = std::make_shared<PersistentQueue>(dbPath.value(), m_logger);
        }

        // else: m_persistentQueue remains nullptr for in-memory-only operation

        // Sessions go over the STREAM socket instead of the DGRAM queue, which is
        // what removes the 64 KB bound that forced them to be chunked.
        m_syncTransport = syncTransport
                          ? std::move(syncTransport)
                          : std::make_shared<SyncSocketTransport>(SYNCQUEUE, moduleName, m_logger);
    }
    // LCOV_EXCL_START
    catch (const std::exception& ex)
    {
        m_logger(LOG_ERROR, "Failed to initialize PersistentQueue: " + std::string(ex.what()));
        // Re-throw to allow caller to handle gracefully
        throw;
    }

    // LCOV_EXCL_STOP
}

void AgentSyncProtocol::persistDifference(const std::string& id,
                                          Operation operation,
                                          const std::string& index,
                                          const std::string& data,
                                          uint64_t version,
                                          bool isDataContext)
{
    try
    {
        if (!m_persistentQueue)
        {
            throw std::runtime_error("persistDifference() requires a persistent queue. Initialize AgentSyncProtocol with a valid dbPath.");
        }

        m_persistentQueue->submit(id, index, data, operation, version, isDataContext);
    }
    catch (const std::exception& e)
    {
        m_logger(LOG_ERROR, std::string("Failed to persist item: ") + e.what());
    }
}

void AgentSyncProtocol::persistDifferenceInMemory(const std::string& id,
                                                  Operation operation,
                                                  const std::string& index,
                                                  const std::string& data,
                                                  uint64_t version)
{
    try
    {
        PersistedData persistedData;
        persistedData.seq = 0;  // Will be assigned during synchronization
        persistedData.id = id;
        persistedData.index = index;
        persistedData.data = data;
        persistedData.operation = operation;
        persistedData.version = version;

        m_inMemoryData.push_back(std::move(persistedData));
    }
    // LCOV_EXCL_START
    catch (const std::exception& e)
    {
        m_logger(LOG_ERROR, std::string("Failed to persist item in memory: ") + e.what());
    }

    // LCOV_EXCL_STOP
}

SyncModuleResult AgentSyncProtocol::synchronizeModule(Mode mode, Option option)
{
    // Validate synchronization mode
    if (mode != Mode::FULL && mode != Mode::DELTA)
    {
        m_logger(LOG_ERROR, "Invalid synchronization mode: " + std::to_string(static_cast<int>(mode)));
        return {false, {}};
    }

    if (!m_syncTransport->checkStatus())
    {
        // Propagate the reason so the calling module emits a single, informative message at the
        // right level (WARNING on a real failure, INFO "aborted" during shutdown). The transport
        // itself only logs the low-level detail at debug.
        return {false, "Failed to reach the sync intake socket.", shouldStop()};
    }

    // Guard against concurrent calls. The timer thread and the AsyncFlushController
    // background thread may both call this method on the same instance. When a sync is
    // already running the second caller skips its cycle — the in-flight sync drains the
    // shared queue, so a concurrent call would only corrupt the session state.
    bool expected = false;

    if (!m_syncInProgress.compare_exchange_strong(expected, true))
    {
        m_logger(LOG_DEBUG, "Synchronization already in progress, skipping concurrent request");
        return {true, {}};
    }

    struct SyncInProgressGuard
    {
        std::atomic<bool>& flag;
        ~SyncInProgressGuard()
        {
            flag.store(false);
        }
    } syncGuard {m_syncInProgress};

    clearSyncState();

    std::vector<PersistedData> dataToSync;

    if (mode == Mode::FULL)
    {
        // For FULL mode, use in-memory data for recovery scenarios
        dataToSync = m_inMemoryData;
    }
    else
    {
        // For DELTA mode, use traditional database persistence
        try
        {
            if (!m_persistentQueue)
            {
                throw std::runtime_error("DELTA mode requires a persistent queue. Initialize AgentSyncProtocol with a valid dbPath.");
            }

            dataToSync = m_persistentQueue->fetchAndMarkForSync();
        }
        catch (const std::exception& e)
        {
            const std::string reason = std::string("Failed to fetch items for sync: ") + e.what();
            m_logger(LOG_ERROR, reason);
            return {false, {}};
        }
    }

    if (dataToSync.empty())
    {
        const std::string modeStr = (mode == Mode::FULL) ? "FULL" : "DELTA";
        m_logger(LOG_DEBUG, "No items to synchronize in " + modeStr + " mode");
        return {true, {}};
    }

    for (size_t i = 0; i < dataToSync.size(); ++i)
    {
        dataToSync[i].seq = i;
    }

    // Separate DataValue and DataContext items
    std::vector<PersistedData> dataValueItems;
    std::vector<PersistedData> dataContextItems;

    for (auto& item : dataToSync)
    {
        if (item.is_data_context)
        {
            dataContextItems.push_back(std::move(item));
        }
        else
        {
            dataValueItems.push_back(std::move(item));
        }
    }

    // Extract unique indices from the DataValue items
    std::set<std::string> uniqueIndicesSet;

    for (const auto& item : dataValueItems)
    {
        uniqueIndicesSet.insert(item.index);
    }

    SessionContent content;
    content.mode = mode;
    content.indices.assign(uniqueIndicesSet.begin(), uniqueIndicesSet.end());
    content.option = option;
    content.dataValues = std::move(dataValueItems);
    content.dataContexts = std::move(dataContextItems);
    const bool success = runSession(content);

    try
    {
        if (success)
        {
            m_logger(LOG_DEBUG_VERBOSE, "Synchronization completed successfully.");

            if (mode == Mode::FULL)
            {
                // For FULL mode, clear the in-memory data after successful sync
                m_inMemoryData.clear();
            }
            else
            {
                // No need to check m_persistentQueue for nullptr here as it was validated earlier
                // For DELTA mode, clear database synced items
                m_persistentQueue->clearSyncedItems();
            }
        }
        else
        {
            if (mode == Mode::FULL)
            {
                m_inMemoryData.clear();
            }
            else
            {
                // No need to check m_persistentQueue for nullptr here as it was validated earlier
                m_persistentQueue->resetSyncingItems();
            }
        }
    }
    catch (const std::exception& e)
    {
        m_logger(LOG_ERROR, std::string("Failed to finalize sync state: ") + e.what());
    }

    std::string failureReason = determineSyncFailureReasonBasedOnSyncResult(m_syncState.lastSyncResult);
    // Report whether a stop was requested so the caller can demote an expected
    // shutdown-time failure from WARNING to INFO/DEBUG.
    // (shouldStop() reads m_stopRequested, which clearSyncState() does not touch.)
    const bool stopped = shouldStop();
    const bool managerNotReady = m_syncState.lastSyncManagerNotReady;
    const unsigned int consecutiveFailures = trackSyncOutcome(success, stopped);
    clearSyncState();
    return {success, failureReason, stopped, managerNotReady, consecutiveFailures};
}

unsigned int AgentSyncProtocol::trackSyncOutcome(bool success, bool stopped)
{
    if (success)
    {
        m_consecutiveSyncFailures.store(0, std::memory_order_relaxed);
        return 0;
    }

    // A sync aborted because the module is stopping says nothing about the manager, so it must not
    // count towards the streak: the module is torn down on purpose and will start over on restart.
    if (stopped)
    {
        return m_consecutiveSyncFailures.load(std::memory_order_relaxed);
    }

    return m_consecutiveSyncFailures.fetch_add(1, std::memory_order_relaxed) + 1;
}

bool AgentSyncProtocol::requiresFullSync(const std::string& index,
                                         const std::string& checksum)
{
    if (!m_syncTransport->checkStatus())
    {
        return false; // Return false as this is not a checksum error from manager
    }

    clearSyncState();

    // The integrity check is Start + ChecksumModule + End, now one message.
    SessionContent content;
    content.mode = Mode::CHECK;
    content.indices = {index};
    content.checksums = {{index, checksum}};

    if (runSession(content))
    {
        m_logger(LOG_DEBUG, "Module integrity check completed successfully for index: " + index);
        clearSyncState();
        return false; // Integrity is valid, no sync required
    }
    else
    {
        // Only return true if manager explicitly reported Status=Error (CHECKSUM_ERROR)
        // All other errors (communication, timeout, etc.) should return false
        bool result = (m_syncState.lastSyncResult == SyncResult::CHECKSUM_ERROR);

        std::string message =
            (m_syncState.lastSyncResult == SyncResult::CHECKSUM_ERROR)
            ? "Checksum validation failed, full sync required"
            : "Manager is offline";

        m_logger(LOG_DEBUG, "Module integrity check failed for index: " + index + " - " + message);

        clearSyncState();
        return result;
    }
}

void AgentSyncProtocol::clearInMemoryData()
{
    m_inMemoryData.clear();
}

SyncModuleResult AgentSyncProtocol::synchronizeMetadataOrGroups(Mode mode,
                                                                const std::vector<std::string>& indices,
                                                                uint64_t globalVersion)
{
    // Validate synchronization mode - only allow metadata and group modes
    if (mode != Mode::METADATA_DELTA && mode != Mode::METADATA_CHECK &&
            mode != Mode::GROUP_DELTA && mode != Mode::GROUP_CHECK)
    {
        m_logger(LOG_ERROR, "Invalid synchronization mode for metadata/groups: " + std::to_string(static_cast<int>(mode)));
        return {false, {}};
    }

    if (!m_syncTransport->checkStatus())
    {
        // Propagate the reason so the calling module emits a single, informative message at the
        // right level (WARNING on a real failure, INFO "aborted" during shutdown). The transport
        // itself only logs the low-level detail at debug.
        return {false, "Failed to reach the sync intake socket.", shouldStop()};
    }

    clearSyncState();

    // For metadata and group modes, we don't send any data items
    // We only send Start (with Size=0 and the indices array) and End messages
    bool success = false;

    // Metadata and group modes carry no items: just Start and End in one message.
    SessionContent content;
    content.mode = mode;
    content.indices = indices;
    content.globalVersion = globalVersion;
    success = runSession(content);

    if (success)
    {
        const std::string modeStr =
            (mode == Mode::METADATA_DELTA) ? "MetadataDelta" :
            (mode == Mode::METADATA_CHECK) ? "MetadataCheck" :
            (mode == Mode::GROUP_DELTA) ? "GroupDelta" : "GroupCheck";

        m_logger(LOG_DEBUG, "Synchronization completed successfully for mode: " + modeStr);
    }
    else
    {
        m_logger(LOG_DEBUG, "Synchronization failed for metadata/groups mode");
    }

    std::string failureReason = determineSyncFailureReasonBasedOnSyncResult(m_syncState.lastSyncResult);
    // Report whether a stop was requested so the caller can demote an expected
    // shutdown-time failure from WARNING to INFO/DEBUG.
    // (shouldStop() reads m_stopRequested, which clearSyncState() does not touch.)
    const bool stopped = shouldStop();
    const bool managerNotReady = m_syncState.lastSyncManagerNotReady;
    const unsigned int consecutiveFailures = trackSyncOutcome(success, stopped);
    clearSyncState();
    return {success, failureReason, stopped, managerNotReady, consecutiveFailures};
}

bool AgentSyncProtocol::notifyDataClean(const std::vector<std::string>& indices,
                                        Option option)
{
    if (indices.empty())
    {
        m_logger(LOG_ERROR, "Cannot notify data clean with empty indices vector");
        return false;
    }

    if (!m_syncTransport->checkStatus())
    {
        return false;
    }

    clearSyncState();

    // Create PersistedData vector for DataClean messages
    std::vector<PersistedData> dataToSync;

    dataToSync.reserve(indices.size());

    for (size_t i = 0; i < indices.size(); ++i)
    {
        PersistedData item;
        item.seq = i;
        item.index = indices[i];
        // id, data, and operation are not used for DataClean messages
        dataToSync.push_back(std::move(item));
    }

    SessionContent content;
    content.mode = Mode::DELTA;
    content.indices = indices;
    content.option = option;
    content.dataCleans = std::move(dataToSync);
    bool success = runSession(content);

    try
    {
        if (success)
        {
            if (!m_persistentQueue)
            {
                throw std::runtime_error("notifyDataClean() requires a persistent queue. Initialize AgentSyncProtocol with a valid dbPath.");
            }

            m_logger(LOG_DEBUG, "DataClean notification completed successfully. Clearing local database.");

            // Clear the local database after successful notification
            for (const auto& index : indices)
            {
                m_persistentQueue->clearItemsByIndex(index);
            }
        }
        else
        {
            m_logger(LOG_DEBUG, "DataClean notification failed.");
        }
    }
    catch (const std::exception& e)
    {
        m_logger(LOG_ERROR, std::string("Failed to clear local database: ") + e.what());
        success = false;
    }

    clearSyncState();
    return success;
}

flatbuffers::Offset<Wazuh::SyncSchema::Start> AgentSyncProtocol::waitMetadataAndBuildStart(
    flatbuffers::FlatBufferBuilder& builder,
    Mode mode,
    size_t dataSize,
    const std::vector<std::string>& uniqueIndices,
    Option option,
    std::optional<uint64_t> globalVersion)
{
    // Declare metadata variables outside try block for proper cleanup in catch
    agent_metadata_t metadata{};
    bool has_metadata = false;

    try
    {
        // Create module name string
        auto module = builder.CreateString(m_moduleName);

        // Translate DB mode to Schema mode
        const auto protocolMode = toProtocolMode(mode);

        // Wait until metadata is available or stop is requested
        {
            bool logged = false;
            std::unique_lock<std::mutex> lock(m_syncState.mtx);

            while ((has_metadata = (metadata_provider_get(&metadata) == 0)) == false)
            {
                if (m_stopRequested.load(std::memory_order_acquire))
                {
                    return 0;
                }

                if (!logged)
                {
                    m_logger(LOG_DEBUG,
                             "Metadata not available from provider. Agent-info may not be initialized yet. Waiting...");
                    logged = true;
                }

                m_syncState.cv.wait_for(lock, std::chrono::seconds(1));
            }
        }

        // Create groups vector from metadata
        std::vector<flatbuffers::Offset<flatbuffers::String>> groups_vec;

        if (metadata.groups && metadata.groups_count > 0)
        {
            for (size_t i = 0; i < metadata.groups_count; ++i)
            {
                groups_vec.push_back(builder.CreateString(metadata.groups[i]));
            }
        }
        else
        {
            m_logger(LOG_DEBUG, "No groups available in metadata. Waiting for the server to synchronize the groups. Cannot proceed with synchronization.");
            m_syncState.lastSyncResult = SyncResult::NO_GROUPS_ERROR;

            if (has_metadata)
            {
                metadata_provider_free_metadata(&metadata);
            }

            return 0;
        }

        m_logger(LOG_DEBUG, "Metadata available. Proceed with synchronization.");

        // Create flatbuffer strings from metadata
        auto architecture = builder.CreateString(metadata.architecture);
        auto hostname = builder.CreateString(metadata.hostname);
        auto osname = builder.CreateString(metadata.os_name);
        auto ostype = builder.CreateString(metadata.os_type);
        auto osplatform = builder.CreateString(metadata.os_platform);
        auto osversion = builder.CreateString(metadata.os_version);
        auto agentversion = builder.CreateString(metadata.agent_version);
        auto agentname = builder.CreateString(metadata.agent_name);
        auto agentid = builder.CreateString(metadata.agent_id);
        auto clustername = builder.CreateString(metadata.cluster_name);
        auto clusternode = builder.CreateString(metadata.cluster_node);

        auto groups = builder.CreateVector(groups_vec);

        // Create index vector from uniqueIndices parameter
        std::vector<flatbuffers::Offset<flatbuffers::String>> index_vec;

        for (const auto& idx : uniqueIndices)
        {
            index_vec.push_back(builder.CreateString(idx));
        }

        auto indices = builder.CreateVector(index_vec);

        Wazuh::SyncSchema::StartBuilder startBuilder(builder);
        startBuilder.add_module_(module);
        startBuilder.add_mode(protocolMode);
        startBuilder.add_size(static_cast<uint64_t>(dataSize));
        startBuilder.add_index(indices);

        // Translate Option enum to Schema Option
        startBuilder.add_option(toProtocolOption(option));

        startBuilder.add_architecture(architecture);
        startBuilder.add_hostname(hostname);
        startBuilder.add_osname(osname);
        startBuilder.add_osplatform(osplatform);
        startBuilder.add_ostype(ostype);
        startBuilder.add_osversion(osversion);
        startBuilder.add_agentversion(agentversion);
        startBuilder.add_agentname(agentname);
        startBuilder.add_agentid(agentid);
        startBuilder.add_groups(groups);
        startBuilder.add_cluster_name(clustername);
        startBuilder.add_cluster_node(clusternode);

        // Only add global_version if provided
        if (globalVersion.has_value())
        {
            startBuilder.add_global_version(globalVersion.value());
        }

        auto startOffset = startBuilder.Finish();

        if (has_metadata)
        {
            metadata_provider_free_metadata(&metadata);
        }

        return startOffset;
    }
    catch (const std::exception& e)
    {
        // Clean up metadata on exception
        if (has_metadata)
        {
            metadata_provider_free_metadata(&metadata);
        }

        m_logger(LOG_ERROR, std::string("Exception when building the Start message: ") + e.what());
    }

    return 0;
}

uint64_t AgentSyncProtocol::nextSessionId()
{
    // The manager used to hand the session id back in the StartAck. With one
    // message and one response there is no handshake to carry it, so the agent
    // picks it; a retried session reuses the same value and the manager dedups
    // on it. Microseconds since the epoch leave room for a counter in the low
    // bits, so two sessions started in the same microsecond still differ.
    static std::atomic<uint64_t> counter {0};
    const auto now = std::chrono::duration_cast<std::chrono::microseconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                     .count();
    return (static_cast<uint64_t>(now) << 12) | (counter.fetch_add(1) & 0xFFF);
}

std::vector<uint8_t> AgentSyncProtocol::buildFullSessionMessage(uint64_t session,
                                                                const SessionContent& content)
{
    try
    {
        flatbuffers::FlatBufferBuilder builder;

        // The size announced in Start counts every item the session carries.
        const size_t itemCount = content.dataValues.size() +
                                 content.dataContexts.size() +
                                 content.dataCleans.size();

        // Every nested table has to be finished before the parent builder opens,
        // so Start and all the item vectors are built up front.
        const auto startOffset = waitMetadataAndBuildStart(builder,
                                                           content.mode,
                                                           itemCount,
                                                           content.indices,
                                                           content.option,
                                                           content.globalVersion);

        if (startOffset.IsNull())
        {
            return {};
        }

        // One batch holds the lot: the ~60 KB split existed only to fit OS_MAXSTR
        // on the DGRAM queue, and the STREAM socket has no such bound. The field
        // stays a vector so a producer may still group if it ever needs to.
        std::vector<flatbuffers::Offset<Wazuh::SyncSchema::DataValue>> valueOffsets;
        valueOffsets.reserve(content.dataValues.size());

        for (const auto& item : content.dataValues)
        {
            auto idStr = builder.CreateString(item.id);
            auto idxStr = builder.CreateString(item.index);
            auto dataVec = builder.CreateVector(
                               reinterpret_cast<const int8_t*>(item.data.data()), item.data.size());

            Wazuh::SyncSchema::DataValueBuilder dataValueBuilder(builder);
            dataValueBuilder.add_seq(item.seq);
            dataValueBuilder.add_session(session);
            dataValueBuilder.add_id(idStr);
            dataValueBuilder.add_index(idxStr);
            dataValueBuilder.add_version(item.version);
            dataValueBuilder.add_operation((item.operation == Operation::DELETE_)
                                           ? Wazuh::SyncSchema::Operation::Delete
                                           : Wazuh::SyncSchema::Operation::Upsert);
            dataValueBuilder.add_data(dataVec);
            valueOffsets.push_back(dataValueBuilder.Finish());
        }

        std::vector<flatbuffers::Offset<Wazuh::SyncSchema::DataBatch>> batchOffsets;

        if (!valueOffsets.empty())
        {
            auto valuesVec = builder.CreateVector(valueOffsets);
            Wazuh::SyncSchema::DataBatchBuilder dataBatchBuilder(builder);
            dataBatchBuilder.add_values(valuesVec);
            batchOffsets.push_back(dataBatchBuilder.Finish());
        }

        std::vector<flatbuffers::Offset<Wazuh::SyncSchema::DataContext>> contextOffsets;
        contextOffsets.reserve(content.dataContexts.size());

        for (const auto& item : content.dataContexts)
        {
            auto idStr = builder.CreateString(item.id);
            auto idxStr = builder.CreateString(item.index);
            auto dataVec = builder.CreateVector(
                               reinterpret_cast<const int8_t*>(item.data.data()), item.data.size());

            Wazuh::SyncSchema::DataContextBuilder dataContextBuilder(builder);
            dataContextBuilder.add_seq(item.seq);
            dataContextBuilder.add_session(session);
            dataContextBuilder.add_id(idStr);
            dataContextBuilder.add_index(idxStr);
            dataContextBuilder.add_data(dataVec);
            contextOffsets.push_back(dataContextBuilder.Finish());
        }

        std::vector<flatbuffers::Offset<Wazuh::SyncSchema::DataClean>> cleanOffsets;
        cleanOffsets.reserve(content.dataCleans.size());

        for (const auto& item : content.dataCleans)
        {
            auto idxStr = builder.CreateString(item.index);

            Wazuh::SyncSchema::DataCleanBuilder dataCleanBuilder(builder);
            dataCleanBuilder.add_seq(item.seq);
            dataCleanBuilder.add_session(session);
            dataCleanBuilder.add_index(idxStr);
            cleanOffsets.push_back(dataCleanBuilder.Finish());
        }

        std::vector<flatbuffers::Offset<Wazuh::SyncSchema::ChecksumModule>> checksumOffsets;
        checksumOffsets.reserve(content.checksums.size());

        for (const auto& entry : content.checksums)
        {
            auto idxStr = builder.CreateString(entry.index);
            auto checksumStr = builder.CreateString(entry.checksum);

            Wazuh::SyncSchema::ChecksumModuleBuilder checksumBuilder(builder);
            checksumBuilder.add_session(session);
            checksumBuilder.add_index(idxStr);
            checksumBuilder.add_checksum(checksumStr);
            checksumOffsets.push_back(checksumBuilder.Finish());
        }

        Wazuh::SyncSchema::EndBuilder endBuilder(builder);
        endBuilder.add_session(session);
        const auto endOffset = endBuilder.Finish();

        auto batchesVec = builder.CreateVector(batchOffsets);
        auto contextsVec = builder.CreateVector(contextOffsets);
        auto cleansVec = builder.CreateVector(cleanOffsets);
        auto checksumsVec = builder.CreateVector(checksumOffsets);

        Wazuh::SyncSchema::FullSessionBuilder fullSessionBuilder(builder);
        fullSessionBuilder.add_session(session);
        fullSessionBuilder.add_start(startOffset);
        fullSessionBuilder.add_batches(batchesVec);
        fullSessionBuilder.add_contexts(contextsVec);
        fullSessionBuilder.add_cleans(cleansVec);
        fullSessionBuilder.add_checksums(checksumsVec);
        fullSessionBuilder.add_end(endOffset);
        const auto fullSessionOffset = fullSessionBuilder.Finish();

        auto message = Wazuh::SyncSchema::CreateMessage(
                           builder, Wazuh::SyncSchema::MessageType::FullSession, fullSessionOffset.Union());
        builder.Finish(message);

        const uint8_t* bufferPtr = builder.GetBufferPointer();
        return {bufferPtr, bufferPtr + builder.GetSize()};
    }
    catch (const std::exception& e)
    {
        m_logger(LOG_ERROR, std::string("Exception when building the FullSession message: ") + e.what());
    }

    return {};
}

bool AgentSyncProtocol::runSession(const SessionContent& content)
{
    const uint64_t session = nextSessionId();

    {
        std::lock_guard<std::mutex> lock(m_syncState.mtx);
        m_syncState.session = session;
        // The whole session is in flight from the moment it is sent, so the only
        // thing left to wait for is the manager's verdict.
        m_syncState.phase = SyncPhase::WaitingEndAck;
    }

    const auto message = buildFullSessionMessage(session, content);

    if (message.empty())
    {
        return false;
    }

    m_logger(LOG_DEBUG_VERBOSE,
             "Sending session " + std::to_string(session) + " as one message (" +
             std::to_string(message.size()) + " bytes).");

    // A refused hand-off usually means the intake is briefly down (an agentd
    // restart); pausing before the resend keeps the retry budget from being
    // burnt in one connect-refusal burst. The wait sits on the state cv so a
    // stop cuts it short.
    constexpr auto RESEND_BACKOFF = std::chrono::seconds(1);

    // The whole session is retried under the same id; the manager dedups on it,
    // so a resend after a lost answer cannot double-apply anything.
    for (unsigned int attempt = 0; attempt <= m_retries; ++attempt)
    {
        if (shouldStop())
        {
            return false;
        }

        if (!m_syncTransport->sendSession(session, message))
        {
            m_logger(LOG_DEBUG, "Failed to hand session " + std::to_string(session) + " to the agent.");

            std::unique_lock<std::mutex> lock(m_syncState.mtx);
            m_syncState.cv.wait_for(lock, RESEND_BACKOFF, [&]
            {
                return shouldStop();
            });
            continue;
        }

        std::unique_lock<std::mutex> lock(m_syncState.mtx);

        if (m_syncState.cv.wait_for(lock, m_timeout, [&]
    {
        return m_syncState.endAckReceived || m_syncState.syncFailed || shouldStop();
        }))
        {
            if (m_syncState.syncFailed)
            {
                m_logger(LOG_DEBUG, "Synchronization failed: Manager reported an error status.");
                return false;
            }

            if (m_syncState.endAckReceived)
            {
                return true;
            }

            return false; // Woken by the stop.
        }

        m_logger(LOG_DEBUG, "Timed out waiting for the answer to session " +
                 std::to_string(session) + ". Retrying the whole session.");
    }

    if (!shouldStop())
    {
        std::lock_guard<std::mutex> lock(m_syncState.mtx);
        m_syncState.lastSyncResult = SyncResult::END_TIMEOUT_ERROR;
        // Nothing came back for the session: the manager is most likely not ready
        // for this agent yet. The module retries on its next cycle.
        m_syncState.lastSyncManagerNotReady = true;
    }

    return false;
}

bool AgentSyncProtocol::parseResponseBuffer(const uint8_t* data, size_t length)
{
    if (!data)
    {
        m_logger(LOG_ERROR, "Invalid buffer received.");
        return false;
    }

    try
    {
        flatbuffers::Verifier verifier(data, length);

        if (!Wazuh::SyncSchema::VerifyMessageBuffer(verifier))
        {
            m_logger(LOG_ERROR, "Invalid FlatBuffer message");
            return false;
        }

        const auto* message = Wazuh::SyncSchema::GetMessage(data);
        const auto messageType = message->content_type();

        std::unique_lock<std::mutex> lock(m_syncState.mtx);

        switch (messageType)
        {
            case Wazuh::SyncSchema::MessageType::EndAck:
                {
                    const auto* endAck = message->content_as_EndAck();
                    const uint64_t incomingSession = endAck->session();

                    if (!validatePhaseAndSession(SyncPhase::WaitingEndAck, incomingSession))
                    {
                        m_logger(LOG_DEBUG, "Parsing EndAck, invalid phase or session.");
                        break;
                    }

                    if (endAck->status() == Wazuh::SyncSchema::Status::Error ||
                            endAck->status() == Wazuh::SyncSchema::Status::Offline ||
                            endAck->status() == Wazuh::SyncSchema::Status::ChecksumMismatch)
                    {
                        // Store the specific error type for detailed reporting
                        if (endAck->status() == Wazuh::SyncSchema::Status::Offline)
                        {
                            m_syncState.lastSyncResult = SyncResult::COMMUNICATION_ERROR;
                            // The manager reports it cannot serve this agent: same condition as the
                            // manager reporting it cannot serve this agent yet.
                            m_syncState.lastSyncManagerNotReady = true;
                            m_logger(LOG_DEBUG, "Received EndAck with Offline status. Aborting synchronization.");
                        }
                        else if (endAck->status() == Wazuh::SyncSchema::Status::ChecksumMismatch)
                        {
                            m_syncState.lastSyncResult = SyncResult::CHECKSUM_ERROR;
                            m_logger(LOG_DEBUG, "Checksum mismatch detected by manager, full resync will be triggered.");
                        }
                        else if (endAck->status() == Wazuh::SyncSchema::Status::Error)
                        {
                            m_syncState.lastSyncResult = SyncResult::PROTOCOL_ERROR;
                            m_logger(LOG_DEBUG, "Received EndAck with Error status. Aborting synchronization.");
                        }

                        m_syncState.syncFailed = true;
                        m_syncState.cv.notify_all();
                        break;
                    }

                    m_syncState.lastSyncResult = SyncResult::SUCCESS;
                    m_syncState.endAckReceived = true;
                    m_syncState.cv.notify_all();

                    m_logger(LOG_DEBUG, "EndAck session '" + std::to_string(incomingSession) + "' ended" );
                    break;
                }

            default:
                {
                    m_logger(LOG_DEBUG, "Unknown message type: " + std::to_string(static_cast<int>(messageType)));
                    return false;
                }
        }

        return true;
    }
    catch (const std::exception& e)
    {
        m_logger(LOG_ERROR, std::string("Exception while parsing response buffer: ") + e.what());
        return false;
    }
}

bool AgentSyncProtocol::validatePhaseAndSession(const SyncPhase receivedPhase, const uint64_t incomingSession)
{
    if (m_syncState.phase != receivedPhase)
    {
        m_logger(LOG_DEBUG, "Discarded. Received phase '" + std::to_string(static_cast<int>(receivedPhase)) + "' but current phase is '" + std::to_string(static_cast<int>
                 (m_syncState.phase)) + "'.");
        return false;
    }

    if (m_syncState.session != incomingSession)
    {
        m_logger(LOG_DEBUG, "Discarded. Session mismatch. Expected session '" + std::to_string(m_syncState.session) + "' but session received is '" + std::to_string(
                     incomingSession) + "'.");
        return false;
    }

    return true;
}

void AgentSyncProtocol::clearSyncState()
{
    std::lock_guard<std::mutex> lock(m_syncState.mtx);
    m_syncState.reset();
}

Wazuh::SyncSchema::Mode AgentSyncProtocol::toProtocolMode(Mode mode) const
{
    static const std::unordered_map<Mode, Wazuh::SyncSchema::Mode> modeMap =
    {
        {Mode::FULL, Wazuh::SyncSchema::Mode::ModuleFull},
        {Mode::DELTA, Wazuh::SyncSchema::Mode::ModuleDelta},
        {Mode::CHECK, Wazuh::SyncSchema::Mode::ModuleCheck},
        {Mode::METADATA_DELTA, Wazuh::SyncSchema::Mode::MetadataDelta},
        {Mode::METADATA_CHECK, Wazuh::SyncSchema::Mode::MetadataCheck},
        {Mode::GROUP_DELTA, Wazuh::SyncSchema::Mode::GroupDelta},
        {Mode::GROUP_CHECK, Wazuh::SyncSchema::Mode::GroupCheck}
    };

    if (const auto it = modeMap.find(mode); it != modeMap.end())
    {
        return it->second;
    }

    throw std::invalid_argument("Unknown Mode value: " + std::to_string(static_cast<int>(mode)));
}

Wazuh::SyncSchema::Option AgentSyncProtocol::toProtocolOption(Option option) const
{
    static const std::unordered_map<Option, Wazuh::SyncSchema::Option> optionMap =
    {
        {Option::SYNC, Wazuh::SyncSchema::Option::Sync},
        {Option::VDFIRST, Wazuh::SyncSchema::Option::VDFirst},
        {Option::VDSYNC, Wazuh::SyncSchema::Option::VDSync},
    };

    if (const auto it = optionMap.find(option); it != optionMap.end())
    {
        return it->second;
    }

    throw std::invalid_argument("Unknown Option value: " + std::to_string(static_cast<int>(option)));
}

std::vector<PersistedData> AgentSyncProtocol::fetchPendingItems(bool onlyDataValues)
{
    try
    {
        if (!m_persistentQueue)
        {
            throw std::runtime_error("fetchPendingItems() requires a persistent queue. Initialize AgentSyncProtocol with a valid dbPath.");
        }

        return m_persistentQueue->fetchPendingItems(onlyDataValues);
    }
    catch (const std::exception& e)
    {
        m_logger(LOG_ERROR, std::string("Failed to fetch pending items: ") + e.what());
        return std::vector<PersistedData>();
    }
}

void AgentSyncProtocol::clearAllDataContext()
{
    try
    {
        if (!m_persistentQueue)
        {
            throw std::runtime_error("clearAllDataContext() requires a persistent queue. Initialize AgentSyncProtocol with a valid dbPath.");
        }

        m_persistentQueue->clearAllDataContext();
    }
    catch (const std::exception& e)
    {
        m_logger(LOG_ERROR, std::string("Failed to clear DataContext items: ") + e.what());
    }
}

void AgentSyncProtocol::deleteDatabase()
{
    try
    {
        if (!m_persistentQueue)
        {
            throw std::runtime_error("deleteDatabase() requires a persistent queue. Initialize AgentSyncProtocol with a valid dbPath.");
        }

        m_persistentQueue->deleteDatabase();
    }
    catch (const std::exception& e)
    {
        m_logger(LOG_ERROR, std::string("Failed to delete database: ") + e.what());
    }
}

void AgentSyncProtocol::stop()
{
    m_stopRequested.store(true, std::memory_order_release);

    // Wake up any threads waiting on the condition variable to check the stop flag
    // This prevents crashes when the object is destroyed while waiting
    {
        std::lock_guard<std::mutex> lock(m_syncState.mtx);
        m_syncState.cv.notify_all();
    }

    m_logger(LOG_DEBUG, "Stop requested for sync protocol.");
}

void AgentSyncProtocol::reset()
{
    m_stopRequested.store(false, std::memory_order_release);
    m_logger(LOG_DEBUG, "Reset stop flag for sync protocol.");
}

bool AgentSyncProtocol::shouldStop() const
{
    return m_stopRequested.load(std::memory_order_acquire);
}
