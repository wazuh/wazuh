/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "agent_sync_protocol.hpp"
#include "ipersistent_queue.hpp"
#include "persistent_queue.hpp"
#include "defs.h"
#include "metadata_provider.h"

#include <flatbuffers/flatbuffers.h>
#include <thread>
#include <set>

constexpr char SYNC_MQ = 's';

AgentSyncProtocol::AgentSyncProtocol(const std::string& moduleName, const std::string& dbPath, MQ_Functions mqFuncs, LoggerFunc logger, std::shared_ptr<IPersistentQueue> queue)
    : m_moduleName(moduleName),
      m_mqFuncs(mqFuncs),
      m_logger(std::move(logger))
{
    if (!m_logger)
    {
        throw std::invalid_argument("Logger provided to AgentSyncProtocol cannot be null.");
    }

    try
    {
        m_persistentQueue = queue ? std::move(queue) : std::make_shared<PersistentQueue>(dbPath, m_logger);
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
                                          uint64_t version)
{
    try
    {
        m_persistentQueue->submit(id, index, data, operation, version);
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

        m_inMemoryData.push_back(persistedData);
    }
    // LCOV_EXCL_START
    catch (const std::exception& e)
    {
        m_logger(LOG_ERROR, std::string("Failed to persist item in memory: ") + e.what());
    }

    // LCOV_EXCL_STOP
}

bool AgentSyncProtocol::synchronizeModule(Mode mode, std::chrono::seconds timeout, unsigned int retries, size_t maxEps, Option option)
{
    // Validate synchronization mode
    if (mode != Mode::FULL && mode != Mode::DELTA)
    {
        m_logger(LOG_ERROR, "Invalid synchronization mode: " + std::to_string(static_cast<int>(mode)));
        return false;
    }

    if (!ensureQueueAvailable())
    {
        m_logger(LOG_ERROR, "Failed to open queue: " + std::string(DEFAULTQUEUE));
        return false;
    }

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
            dataToSync = m_persistentQueue->fetchAndMarkForSync();
        }
        catch (const std::exception& e)
        {
            m_logger(LOG_ERROR, std::string("Failed to fetch items for sync: ") + e.what());
            return false;
        }
    }

    if (dataToSync.empty())
    {
        const std::string modeStr = (mode == Mode::FULL) ? "FULL" : "DELTA";
        m_logger(LOG_DEBUG, "No items to synchronize for module " + m_moduleName + " in " + modeStr + " mode");
        return true;
    }

    for (size_t i = 0; i < dataToSync.size(); ++i)
    {
        dataToSync[i].seq = i;
    }

    // Extract unique indices from dataToSync
    std::set<std::string> uniqueIndicesSet;

    for (const auto& item : dataToSync)
    {
        uniqueIndicesSet.insert(item.index);
    }

    std::vector<std::string> uniqueIndices(uniqueIndicesSet.begin(), uniqueIndicesSet.end());

    bool success = false;

    if (sendStartAndWaitAck(mode, dataToSync.size(), uniqueIndices, timeout, retries, maxEps, option))
    {
        if (sendDataMessages(m_syncState.session, dataToSync, maxEps))
        {
            if (sendEndAndWaitAck(m_syncState.session, timeout, retries, dataToSync, maxEps))
            {
                success = true;
            }
        }
    }

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
                // For DELTA mode, clear database synced items
                m_persistentQueue->clearSyncedItems();
            }
        }
        else
        {
            m_logger(LOG_WARNING, "Synchronization failed.");

            if (mode == Mode::FULL)
            {
                m_inMemoryData.clear();
            }
            else
            {
                m_persistentQueue->resetSyncingItems();
            }
        }
    }
    catch (const std::exception& e)
    {
        m_logger(LOG_ERROR, std::string("Failed to finalize sync state: ") + e.what());
    }

    clearSyncState();
    return success;
}

bool AgentSyncProtocol::requiresFullSync(const std::string& index,
                                         const std::string& checksum,
                                         std::chrono::seconds timeout,
                                         unsigned int retries,
                                         size_t maxEps)
{
    if (!ensureQueueAvailable())
    {
        m_logger(LOG_ERROR, "Failed to open queue: " + std::string(DEFAULTQUEUE));
        return false; // Return false as this is not a checksum error from manager
    }

    clearSyncState();

    // Step 1: Send Start message with mode ModuleCheck
    std::vector<std::string> indices = {index};

    if (!sendStartAndWaitAck(Mode::CHECK, 1, indices, timeout, retries, maxEps))
    {
        m_logger(LOG_ERROR, "Failed to send Start message for integrity check");
        clearSyncState();
        return false; // Return false as this is not a checksum error from manager
    }

    // Step 2: Send ChecksumModule message
    if (!sendChecksumMessage(m_syncState.session, index, checksum, maxEps))
    {
        m_logger(LOG_ERROR, "Failed to send ChecksumModule message");
        clearSyncState();
        return false; // Return false as this is not a checksum error from manager
    }

    m_logger(LOG_DEBUG, "ChecksumModule message sent for index: " + index);

    // Step 3: Send End message and wait for EndAck
    std::vector<PersistedData> emptyData; // No data to send for integrity check

    if (sendEndAndWaitAck(m_syncState.session, timeout, retries, emptyData, maxEps))
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

        m_logger(LOG_WARNING, "Module integrity check failed for index: " + index + " - " + message);

        clearSyncState();
        return result;
    }
}

void AgentSyncProtocol::clearInMemoryData()
{
    m_inMemoryData.clear();
}

bool AgentSyncProtocol::synchronizeMetadataOrGroups(Mode mode,
                                                    const std::vector<std::string>& indices,
                                                    std::chrono::seconds timeout,
                                                    unsigned int retries,
                                                    size_t maxEps,
                                                    uint64_t globalVersion)
{
    // Validate synchronization mode - only allow metadata and group modes
    if (mode != Mode::METADATA_DELTA && mode != Mode::METADATA_CHECK &&
            mode != Mode::GROUP_DELTA && mode != Mode::GROUP_CHECK)
    {
        m_logger(LOG_ERROR, "Invalid synchronization mode for metadata/groups: " + std::to_string(static_cast<int>(mode)));
        return false;
    }

    if (!ensureQueueAvailable())
    {
        m_logger(LOG_ERROR, "Failed to open queue: " + std::string(DEFAULTQUEUE));
        return false;
    }

    clearSyncState();

    // For metadata and group modes, we don't send any data items
    // We only send Start (with Size=0 and the indices array) and End messages
    bool success = false;

    // Step 1: Send Start message and wait for StartAck
    if (sendStartAndWaitAck(mode, 0, indices, timeout, retries, maxEps, Option::SYNC, globalVersion))
    {
        // Step 2: Send End message and wait for EndAck (no Data messages)
        std::vector<PersistedData> emptyData;

        if (sendEndAndWaitAck(m_syncState.session, timeout, retries, emptyData, maxEps))
        {
            success = true;
        }
    }

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
        m_logger(LOG_WARNING, "Synchronization failed for metadata/groups mode");
    }

    clearSyncState();
    return success;
}

bool AgentSyncProtocol::notifyDataClean(const std::vector<std::string>& indices,
                                        std::chrono::seconds timeout,
                                        unsigned int retries,
                                        size_t maxEps,
                                        Option option)
{
    if (indices.empty())
    {
        m_logger(LOG_ERROR, "Cannot notify data clean with empty indices vector");
        return false;
    }

    if (!ensureQueueAvailable())
    {
        m_logger(LOG_ERROR, "Failed to open queue: " + std::string(DEFAULTQUEUE));
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
        dataToSync.push_back(item);
    }

    bool success = false;

    // Step 1: Send Start message with the indices and size
    if (sendStartAndWaitAck(Mode::DELTA, dataToSync.size(), indices, timeout, retries, maxEps, option))
    {
        // Step 2: Send DataClean message for each index
        if (sendDataCleanMessages(m_syncState.session, dataToSync, maxEps))
        {
            // Step 3: Send End message and wait for EndAck
            if (sendEndAndWaitAck(m_syncState.session, timeout, retries, dataToSync, maxEps))
            {
                success = true;
            }
        }
    }

    try
    {
        if (success)
        {
            m_logger(LOG_DEBUG, "DataClean notification completed successfully. Clearing local database.");

            // Clear the local database after successful notification
            for (const auto& index : indices)
            {
                m_persistentQueue->clearItemsByIndex(index);
            }
        }
        else
        {
            m_logger(LOG_WARNING, "DataClean notification failed.");
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

bool AgentSyncProtocol::ensureQueueAvailable()
{
    try
    {
        if (m_queue < 0)
        {
            m_queue = m_mqFuncs.start(DEFAULTQUEUE, WRITE, 0);

            if (m_queue < 0)
            {
                return false;
            }
        }

        return true;
    }
    catch (const std::exception& e)
    {
        m_logger(LOG_ERROR, std::string("Exception when checking queue availability: ") + e.what());
    }

    return false;
}

bool AgentSyncProtocol::sendStartAndWaitAck(Mode mode,
                                            size_t dataSize,
                                            const std::vector<std::string>& uniqueIndices,
                                            const std::chrono::seconds timeout,
                                            unsigned int retries,
                                            size_t maxEps,
                                            Option option,
                                            std::optional<uint64_t> globalVersion)
{
    // Declare metadata variables outside try block for proper cleanup in catch
    agent_metadata_t metadata{};
    bool has_metadata = false;

    try
    {
        flatbuffers::FlatBufferBuilder builder;

        // Create module name string
        auto module = builder.CreateString(m_moduleName);

        // Translate DB mode to Schema mode
        const auto protocolMode = toProtocolMode(mode);

        // Try to get metadata from provider - fail if not available
        has_metadata = (metadata_provider_get(&metadata) == 0);

        // If metadata not available, abort synchronization
        if (!has_metadata)
        {
            m_logger(LOG_DEBUG,
                     "Metadata not available from provider. Agent-info may not be initialized yet. Cannot proceed with "
                     "synchronization.");
            return false;
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
        auto checksum_metadata = builder.CreateString(metadata.checksum_metadata);

        // Create groups vector from metadata
        std::vector<flatbuffers::Offset<flatbuffers::String>> groups_vec;

        if (metadata.groups && metadata.groups_count > 0)
        {
            for (size_t i = 0; i < metadata.groups_count; ++i)
            {
                groups_vec.push_back(builder.CreateString(metadata.groups[i]));
            }
        }

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
        startBuilder.add_checksum_metadata(checksum_metadata);

        // Only add global_version if provided
        if (globalVersion.has_value())
        {
            startBuilder.add_global_version(globalVersion.value());
        }

        auto startOffset = startBuilder.Finish();

        auto message = Wazuh::SyncSchema::CreateMessage(builder, Wazuh::SyncSchema::MessageType::Start, startOffset.Union());
        builder.Finish(message);

        const uint8_t* buffer_ptr = builder.GetBufferPointer();
        const size_t buffer_size = builder.GetSize();
        std::vector<uint8_t> messageVector(buffer_ptr, buffer_ptr + buffer_size);

        {
            std::lock_guard<std::mutex> lock(m_syncState.mtx);
            m_syncState.phase = SyncPhase::WaitingStartAck;
        }

        for (unsigned int attempt = 0; attempt <= retries; ++attempt)
        {
            if (!sendFlatBufferMessageAsString(messageVector, maxEps))
            {
                m_logger(LOG_ERROR, "Failed to send Start message.");
                continue;
            }

            if (receiveStartAck(timeout))
            {
                std::lock_guard<std::mutex> lock(m_syncState.mtx);

                if (m_syncState.syncFailed)
                {
                    m_logger(LOG_ERROR, "Synchronization failed due to manager error.");
                    return false;
                }

                m_logger(LOG_DEBUG, "StartAck received. Session: " + std::to_string(m_syncState.session));

                // Clean up metadata before returning success
                if (has_metadata)
                {
                    metadata_provider_free_metadata(&metadata);
                }

                return true;
            }

            m_logger(LOG_DEBUG, "Timed out waiting for StartAck. Retrying...");
        }

        // Clean up metadata if we successfully retrieved it
        if (has_metadata)
        {
            metadata_provider_free_metadata(&metadata);
        }

        return false;
    }
    catch (const std::exception& e)
    {
        // Clean up metadata on exception
        if (has_metadata)
        {
            metadata_provider_free_metadata(&metadata);
        }

        m_logger(LOG_ERROR, std::string("Exception when sending Start message: ") + e.what());
    }

    return false;
}

bool AgentSyncProtocol::receiveStartAck(std::chrono::seconds timeout)
{
    std::unique_lock<std::mutex> lock(m_syncState.mtx);
    return m_syncState.cv.wait_for(lock, timeout, [&]
    {
        return m_syncState.startAckReceived || m_syncState.syncFailed || shouldStop();
    });
}

bool AgentSyncProtocol::sendDataMessages(uint64_t session,
                                         const std::vector<PersistedData>& data,
                                         size_t maxEps)
{
    try
    {
        for (const auto& item : data)
        {
            // Check if stop was requested
            if (shouldStop())
            {
                m_logger(LOG_INFO, "Stop requested, aborting data message sending");
                return false;
            }

            flatbuffers::FlatBufferBuilder builder;
            auto idStr = builder.CreateString(item.id);
            auto idxStr = builder.CreateString(item.index);
            auto dataVec = builder.CreateVector(reinterpret_cast<const int8_t*>(item.data.data()), item.data.size());

            Wazuh::SyncSchema::DataValueBuilder dataValueBuilder(builder);
            dataValueBuilder.add_seq(item.seq);
            dataValueBuilder.add_session(session);
            dataValueBuilder.add_id(idStr);
            dataValueBuilder.add_index(idxStr);
            dataValueBuilder.add_version(item.version);

            // Translate DB operation to Schema operation
            const auto protocolOperation = (item.operation == Operation::DELETE_)
                                           ? Wazuh::SyncSchema::Operation::Delete
                                           : Wazuh::SyncSchema::Operation::Upsert;

            dataValueBuilder.add_operation(protocolOperation);
            dataValueBuilder.add_data(dataVec);
            auto dataValueOffset = dataValueBuilder.Finish();

            auto message = Wazuh::SyncSchema::CreateMessage(builder, Wazuh::SyncSchema::MessageType::DataValue, dataValueOffset.Union());
            builder.Finish(message);

            const uint8_t* buffer_ptr = builder.GetBufferPointer();
            const size_t buffer_size = builder.GetSize();
            std::vector<uint8_t> messageVector(buffer_ptr, buffer_ptr + buffer_size);

            if (!sendFlatBufferMessageAsString(messageVector, maxEps))
            {
                return false;
            }
        }

        return true;
    }
    catch (const std::exception& e)
    {
        m_logger(LOG_ERROR, std::string("Exception when sending Data messages: ") + e.what());
    }

    return false;
}

bool AgentSyncProtocol::sendChecksumMessage(uint64_t session,
                                            const std::string& index,
                                            const std::string& checksum,
                                            size_t maxEps)
{
    try
    {
        flatbuffers::FlatBufferBuilder builder;
        auto indexStr = builder.CreateString(index);
        auto checksumStr = builder.CreateString(checksum);

        Wazuh::SyncSchema::ChecksumModuleBuilder checksumBuilder(builder);
        checksumBuilder.add_session(session);
        checksumBuilder.add_index(indexStr);
        checksumBuilder.add_checksum(checksumStr);
        auto checksumOffset = checksumBuilder.Finish();

        auto message = Wazuh::SyncSchema::CreateMessage(builder, Wazuh::SyncSchema::MessageType::ChecksumModule, checksumOffset.Union());
        builder.Finish(message);

        const uint8_t* buffer_ptr = builder.GetBufferPointer();
        const size_t buffer_size = builder.GetSize();
        std::vector<uint8_t> messageVector(buffer_ptr, buffer_ptr + buffer_size);

        if (!sendFlatBufferMessageAsString(messageVector, maxEps))
        {
            return false;
        }

        return true;
    }
    catch (const std::exception& e)
    {
        m_logger(LOG_ERROR, std::string("Exception when sending ChecksumModule message: ") + e.what());
    }

    return false;
}

bool AgentSyncProtocol::sendDataCleanMessages(uint64_t session,
                                              const std::vector<PersistedData>& data,
                                              size_t maxEps)
{
    try
    {
        for (const auto& item : data)
        {
            flatbuffers::FlatBufferBuilder builder;
            auto indexStr = builder.CreateString(item.index);

            Wazuh::SyncSchema::DataCleanBuilder dataCleanBuilder(builder);
            dataCleanBuilder.add_seq(item.seq);
            dataCleanBuilder.add_session(session);
            dataCleanBuilder.add_index(indexStr);
            auto dataCleanOffset = dataCleanBuilder.Finish();

            auto message = Wazuh::SyncSchema::CreateMessage(builder, Wazuh::SyncSchema::MessageType::DataClean, dataCleanOffset.Union());
            builder.Finish(message);

            const uint8_t* buffer_ptr = builder.GetBufferPointer();
            const size_t buffer_size = builder.GetSize();
            std::vector<uint8_t> messageVector(buffer_ptr, buffer_ptr + buffer_size);

            if (!sendFlatBufferMessageAsString(messageVector, maxEps))
            {
                return false;
            }
        }

        return true;
    }
    catch (const std::exception& e)
    {
        m_logger(LOG_ERROR, std::string("Exception when sending DataClean messages: ") + e.what());
    }

    return false;
}

bool AgentSyncProtocol::sendEndAndWaitAck(uint64_t session,
                                          const std::chrono::seconds timeout,
                                          unsigned int retries,
                                          const std::vector<PersistedData>& dataToSync,
                                          size_t maxEps)
{
    try
    {
        flatbuffers::FlatBufferBuilder builder;
        Wazuh::SyncSchema::EndBuilder endBuilder(builder);
        endBuilder.add_session(session);
        auto endOffset = endBuilder.Finish();

        auto message = Wazuh::SyncSchema::CreateMessage(builder, Wazuh::SyncSchema::MessageType::End, endOffset.Union());
        builder.Finish(message);

        const uint8_t* buffer_ptr = builder.GetBufferPointer();
        const size_t buffer_size = builder.GetSize();
        std::vector<uint8_t> messageVector(buffer_ptr, buffer_ptr + buffer_size);

        {
            std::lock_guard<std::mutex> lock(m_syncState.mtx);
            m_syncState.phase = SyncPhase::WaitingEndAck;
        }

        bool sendEnd = true;

        for (unsigned int attempt = 0; attempt <= retries; ++attempt)
        {
            if (sendEnd && !sendFlatBufferMessageAsString(messageVector, maxEps))
            {
                m_logger(LOG_ERROR, "Failed to send End message.");
                continue;
            }

            if (!receiveEndAck(timeout))
            {
                m_logger(LOG_DEBUG, "Timeout waiting for EndAck or ReqRet. Retrying...");
                continue;
            }

            {
                std::lock_guard<std::mutex> lock(m_syncState.mtx);

                if (m_syncState.syncFailed)
                {
                    m_logger(LOG_ERROR, "Synchronization failed: Manager reported an error status.");
                    return false;
                }
            }

            bool wasReqRet = false;
            std::vector<std::pair<uint64_t, uint64_t>> ranges;
            {
                std::lock_guard<std::mutex> lock(m_syncState.mtx);
                wasReqRet = m_syncState.reqRetReceived;

                if (wasReqRet)
                {
                    ranges = std::move(m_syncState.reqRetRanges);
                    m_syncState.reqRetRanges.clear();
                    m_syncState.reqRetReceived = false;
                }
            }

            if (wasReqRet)
            {
                if (ranges.empty())
                {
                    m_logger(LOG_ERROR, "Received ReqRet with empty ranges. Aborting current sync attempt.");
                    return false;
                }

                std::vector<PersistedData> rangeData = filterDataByRanges(dataToSync, ranges);

                if (rangeData.empty())
                {
                    m_logger(LOG_ERROR, "ReqRet asked for ranges that yield no data. Aborting.");
                    return false;
                }

                if (!sendDataMessages(session, rangeData, maxEps))
                {
                    m_logger(LOG_ERROR, "Failed to resend data for ReqRet.");
                    return false;
                }

                sendEnd = false;
                continue;
            }

            {
                std::lock_guard<std::mutex> lock(m_syncState.mtx);

                if (m_syncState.endAckReceived)
                {
                    m_logger(LOG_DEBUG, "EndAck received.");
                    return true;
                }
            }
        }

        return false;
    }
    catch (const std::exception& e)
    {
        m_logger(LOG_ERROR, std::string("Exception when sending End message: ") + e.what());
    }

    return false;
}

bool AgentSyncProtocol::receiveEndAck(std::chrono::seconds timeout)
{
    std::unique_lock<std::mutex> lock(m_syncState.mtx);
    return m_syncState.cv.wait_for(lock, timeout, [&]
    {
        return m_syncState.endAckReceived || m_syncState.reqRetReceived || m_syncState.syncFailed || shouldStop();
    });
}

bool AgentSyncProtocol::sendFlatBufferMessageAsString(const std::vector<uint8_t>& fbData, size_t maxEps)
{
    if (m_mqFuncs.send_binary(m_queue, fbData.data(), fbData.size(), m_moduleName.c_str(), SYNC_MQ) < 0)
    {
        m_logger(LOG_ERROR, "SendMSG failed, attempting to reinitialize queue...");
        m_queue = m_mqFuncs.start(DEFAULTQUEUE, WRITE, 0);

        if (m_queue < 0 || m_mqFuncs.send_binary(m_queue, fbData.data(), fbData.size(), m_moduleName.c_str(), SYNC_MQ) < 0)
        {
            m_logger(LOG_ERROR, "SendMSG failed to send message after retry");
            return false;
        }
    }

    if (maxEps > 0)
    {
        if (++m_msgSent >= maxEps)
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            m_msgSent.store(0);
        }
    }

    return true;
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
            case Wazuh::SyncSchema::MessageType::StartAck:
                {
                    if (m_syncState.phase == SyncPhase::WaitingStartAck)
                    {
                        const auto* startAck = message->content_as_StartAck();

                        if (startAck->status() == Wazuh::SyncSchema::Status::Error ||
                                startAck->status() == Wazuh::SyncSchema::Status::Offline)
                        {
                            m_logger(LOG_ERROR, "Received StartAck with error status. Aborting synchronization.");
                            m_syncState.syncFailed = true;
                            m_syncState.cv.notify_all();
                            break;
                        }

                        const uint64_t incomingSession = startAck->session();
                        m_syncState.session = incomingSession;
                        m_syncState.startAckReceived = true;
                        m_syncState.cv.notify_all();

                        m_logger(LOG_DEBUG, "Received and accepted for new session: " + std::to_string(m_syncState.session));
                    }
                    else
                    {
                        m_logger(LOG_DEBUG, "Discarded. Not in WaitingStartAck phase. Current phase: " + std::to_string(static_cast<int>(m_syncState.phase)));
                    }

                    break;
                }

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
                            endAck->status() == Wazuh::SyncSchema::Status::Offline)
                    {
                        m_logger(LOG_ERROR, "Received EndAck with error status. Aborting synchronization.");

                        // Store the specific error type for detailed reporting
                        if (endAck->status() == Wazuh::SyncSchema::Status::Offline)
                        {
                            m_syncState.lastSyncResult = SyncResult::COMMUNICATION_ERROR;
                        }
                        else if (endAck->status() == Wazuh::SyncSchema::Status::Error)
                        {
                            m_syncState.lastSyncResult = SyncResult::CHECKSUM_ERROR;
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

            case Wazuh::SyncSchema::MessageType::ReqRet:
                {
                    const auto* reqRet = message->content_as_ReqRet();
                    const uint64_t incomingSession = reqRet->session();

                    if (!validatePhaseAndSession(SyncPhase::WaitingEndAck, incomingSession))
                    {
                        m_logger(LOG_DEBUG, "Parsing ReqRet, invalid phase or session.");
                        break;
                    }

                    m_syncState.reqRetRanges.clear();

                    if (reqRet->seq())
                    {
                        for (const auto* pair : *reqRet->seq())
                        {
                            m_syncState.reqRetRanges.emplace_back(pair->begin(), pair->end());
                        }
                    }

                    m_syncState.reqRetReceived = true;

                    m_logger(LOG_DEBUG, "ReqRet received '" + std::to_string(m_syncState.reqRetRanges.size()) + "' ranges" );
                    m_syncState.cv.notify_all();
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

std::vector<PersistedData> AgentSyncProtocol::filterDataByRanges(
    const std::vector<PersistedData>& sourceData,
    const std::vector<std::pair<uint64_t, uint64_t>>& ranges)
{
    std::vector<PersistedData> result;

    if (ranges.empty() || sourceData.empty())
    {
        return result;
    }

    for (const auto& item : sourceData)
    {
        for (const auto& range : ranges)
        {
            if (range.second < range.first)
            {
                m_logger(LOG_ERROR, "Requested set of ranks malformed. Aborting.");
                return {};
            }

            if (item.seq >= range.first && item.seq <= range.second)
            {
                result.push_back(item);
                break;
            }
        }
    }

    return result;
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
        {Option::VDCLEAN, Wazuh::SyncSchema::Option::VDClean}
    };

    if (const auto it = optionMap.find(option); it != optionMap.end())
    {
        return it->second;
    }

    throw std::invalid_argument("Unknown Option value: " + std::to_string(static_cast<int>(option)));
}

void AgentSyncProtocol::deleteDatabase()
{
    try
    {
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

    m_logger(LOG_DEBUG, "Stop requested for sync protocol module: " + m_moduleName);
}

void AgentSyncProtocol::reset()
{
    m_stopRequested.store(false, std::memory_order_release);
    m_logger(LOG_DEBUG, "Reset stop flag for sync protocol module: " + m_moduleName);
}

bool AgentSyncProtocol::shouldStop() const
{
    return m_stopRequested.load(std::memory_order_acquire);
}
