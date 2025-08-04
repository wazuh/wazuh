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

#include <flatbuffers/flatbuffers.h>
#include <iostream>
#include <thread>

constexpr char SYNC_MQ = 's';

AgentSyncProtocol::AgentSyncProtocol(MQ_Functions mqFuncs, std::shared_ptr<IPersistentQueue> queue)
    : m_mqFuncs(mqFuncs),
      m_persistentQueue(queue != nullptr ? std::move(queue) : std::make_shared<PersistentQueue>())
{
}

size_t AgentSyncProtocol::persistDifference(const std::string& id,
                                            Operation operation,
                                            const std::string& index,
                                            const std::string& data)
{
    try
    {
        return m_persistentQueue->submit(id, index, data, operation);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Failed to persist item: " << e.what() << std::endl;
        return 0;
    }
}

bool AgentSyncProtocol::synchronizeModule(const std::string& module, Wazuh::SyncSchema::Mode mode, std::chrono::seconds timeout, unsigned int retries, size_t maxEps)
{
    if (!ensureQueueAvailable())
    {
        std::cerr << "Failed to open queue: " << DEFAULTQUEUE << std::endl;
        return false;
    }

    clearSyncState();

    std::vector<PersistedData> dataToSync;

    try
    {
        dataToSync = m_persistentQueue->fetchAndMarkForSync();
    }
    catch (const std::exception& e)
    {
        std::cerr << "Failed to fetch items for sync: " << e.what() << std::endl;
        return false;
    }

    if (dataToSync.empty())
    {
        std::cout << "[Sync] No pending items to synchronize for module '" << module << "'." << std::endl;
        return true;
    }

    for (size_t i = 0; i < dataToSync.size(); ++i)
    {
        dataToSync[i].seq = i + 1;
    }

    bool success = false;

    if (sendStartAndWaitAck(module, mode, dataToSync.size(), timeout, retries, maxEps))
    {
        if (sendDataMessages(module, m_syncState.session, dataToSync, maxEps))
        {
            if (sendEndAndWaitAck(module, m_syncState.session, timeout, retries, dataToSync, maxEps))
            {
                success = true;
            }
        }
    }

    try
    {
        if (success)
        {
            std::cout << "[Sync] Module '" << module << "' synchronized successfully. Clearing " << dataToSync.size() << " items." << std::endl;
            m_persistentQueue->clearSyncedItems();
        }
        else
        {
            std::cerr << "[Sync] Synchronization failed for module '" << module << "'. Resetting " << dataToSync.size() << " items to pending state." << std::endl;
            m_persistentQueue->resetSyncingItems();
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "CRITICAL: Failed to finalize sync state in DB: " << e.what() << std::endl;
    }

    clearSyncState();
    return success;
}

bool AgentSyncProtocol::ensureQueueAvailable()
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

bool AgentSyncProtocol::sendStartAndWaitAck(const std::string& module,
                                            Wazuh::SyncSchema::Mode mode,
                                            size_t dataSize,
                                            const std::chrono::seconds timeout,
                                            unsigned int retries,
                                            size_t maxEps)
{
    flatbuffers::FlatBufferBuilder builder;
    auto moduleStr = builder.CreateString(module);

    Wazuh::SyncSchema::StartBuilder startBuilder(builder);
    startBuilder.add_mode(mode);
    startBuilder.add_size(static_cast<uint64_t>(dataSize));
    startBuilder.add_module_(moduleStr);
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
        if (!sendFlatBufferMessageAsString(messageVector, module, maxEps))
        {
            std::cerr << "[Sync] Failed to send Start message.\n";
            continue;
        }

        if (receiveStartAck(timeout))
        {
            std::lock_guard<std::mutex> lock(m_syncState.mtx);

            if (m_syncState.syncFailed)
            {
                std::cerr << "[Sync] Synchronization failed due to manager error." << std::endl;
                return false;
            }

            std::cout << "[Sync] StartAck received. Session " << m_syncState.session << " established.\n";
            return true;
        }

        std::cout << "[Sync] Timed out waiting for StartAck. Retrying...\n";
    }

    return false;
}

bool AgentSyncProtocol::receiveStartAck(std::chrono::seconds timeout)
{
    std::unique_lock<std::mutex> lock(m_syncState.mtx);
    return m_syncState.cv.wait_for(lock, timeout, [&]
    {
        return m_syncState.startAckReceived || m_syncState.syncFailed;
    });
}

bool AgentSyncProtocol::sendDataMessages(const std::string& module,
                                         uint64_t session,
                                         const std::vector<PersistedData>& data,
                                         size_t maxEps)
{
    for (const auto& item : data)
    {
        flatbuffers::FlatBufferBuilder builder;
        auto idStr = builder.CreateString(item.id);
        auto idxStr = builder.CreateString(item.index);
        auto dataVec = builder.CreateVector(reinterpret_cast<const int8_t*>(item.data.data()), item.data.size());

        Wazuh::SyncSchema::DataBuilder dataBuilder(builder);
        dataBuilder.add_seq(item.seq);
        dataBuilder.add_session(session);
        dataBuilder.add_id(idStr);
        dataBuilder.add_index(idxStr);

        // Translate DB operation to Schema operation
        const auto protocolOperation = (item.operation == Operation::DELETE)
                                       ? Wazuh::SyncSchema::Operation::Delete
                                       : Wazuh::SyncSchema::Operation::Upsert;

        dataBuilder.add_operation(protocolOperation);
        dataBuilder.add_data(dataVec);
        auto dataOffset = dataBuilder.Finish();

        auto message = Wazuh::SyncSchema::CreateMessage(builder, Wazuh::SyncSchema::MessageType::Data, dataOffset.Union());
        builder.Finish(message);

        const uint8_t* buffer_ptr = builder.GetBufferPointer();
        const size_t buffer_size = builder.GetSize();
        std::vector<uint8_t> messageVector(buffer_ptr, buffer_ptr + buffer_size);

        if (!sendFlatBufferMessageAsString(messageVector, module, maxEps))
        {
            return false;
        }
    }

    return true;
}

bool AgentSyncProtocol::sendEndAndWaitAck(const std::string& module,
                                          uint64_t session,
                                          const std::chrono::seconds timeout,
                                          unsigned int retries,
                                          const std::vector<PersistedData>& dataToSync,
                                          size_t maxEps)
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
        if (sendEnd && !sendFlatBufferMessageAsString(messageVector, module, maxEps))
        {
            std::cerr << "[Sync] Failed to send End message.\n";
            continue;
        }

        if (!receiveEndAck(timeout))
        {
            std::cout << "[Sync] Timeout waiting for EndAck or ReqRet. Retrying...\n";
            continue;
        }

        {
            std::lock_guard<std::mutex> lock(m_syncState.mtx);

            if (m_syncState.syncFailed)
            {
                std::cerr << "[Sync] Synchronization failed: Manager reported an error status." << std::endl;
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
                std::cerr << "[Sync] Received ReqRet with empty ranges. Aborting current sync attempt.\n";
                return false;
            }

            std::vector<PersistedData> rangeData = filterDataByRanges(dataToSync, ranges);

            if (rangeData.empty())
            {
                std::cerr << "[Sync] ReqRet asked for ranges that yield no data. Aborting." << std::endl;
                return false;
            }

            if (!sendDataMessages(module, session, rangeData, maxEps))
            {
                std::cerr << "[Sync] Failed to resend data for ReqRet.\n";
                return false;
            }

            sendEnd = false;
            continue;
        }

        {
            std::lock_guard<std::mutex> lock(m_syncState.mtx);

            if (m_syncState.endAckReceived)
            {
                std::cout << "[Sync] EndAck received.\n";
                return true;
            }
        }
    }

    return false;
}

bool AgentSyncProtocol::receiveEndAck(std::chrono::seconds timeout)
{
    std::unique_lock<std::mutex> lock(m_syncState.mtx);
    return m_syncState.cv.wait_for(lock, timeout, [&]
    {
        return m_syncState.endAckReceived || m_syncState.reqRetReceived || m_syncState.syncFailed;
    });
}

bool AgentSyncProtocol::sendFlatBufferMessageAsString(const std::vector<uint8_t>& fbData, const std::string& module, size_t maxEps)
{
    if (m_mqFuncs.send_binary(m_queue, fbData.data(), fbData.size(), module.c_str(), SYNC_MQ) < 0)
    {
        std::cerr << "SendMSG failed, attempting to reinitialize queue..." << std::endl;
        m_queue = m_mqFuncs.start(DEFAULTQUEUE, WRITE, 0);

        if (m_queue < 0 || m_mqFuncs.send_binary(m_queue, fbData.data(), fbData.size(), module.c_str(), SYNC_MQ) < 0)
        {
            std::cerr << "Failed to send message after retry" << std::endl;
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

bool AgentSyncProtocol::parseResponseBuffer(const uint8_t* data)
{
    if (!data)
    {
        std::cerr << "Invalid buffer received.\n";
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
                        std::cerr << "[Sync] Received StartAck with error status. Aborting synchronization." << std::endl;
                        m_syncState.syncFailed = true;
                        m_syncState.cv.notify_all();
                        break;
                    }

                    const uint64_t incomingSession = startAck->session();
                    m_syncState.session = incomingSession;
                    m_syncState.startAckReceived = true;
                    m_syncState.cv.notify_all();

                    std::cout << "[StartAck] Received and accepted for new session: " << m_syncState.session << "\n";
                }
                else
                {
                    std::cerr << "[StartAck] Discarded. Not in WaitingStartAck phase. Current phase: "
                              << static_cast<int>(m_syncState.phase) << "\n";
                }

                break;
            }

        case Wazuh::SyncSchema::MessageType::EndAck:
            {
                const auto* endAck = message->content_as_EndAck();
                const uint64_t incomingSession = endAck->session();

                if (!validatePhaseAndSession(SyncPhase::WaitingEndAck, incomingSession))
                {
                    std::cout << "[EndAck] invalid phase or session. \n";
                    break;
                }

                if (endAck->status() == Wazuh::SyncSchema::Status::Error ||
                        endAck->status() == Wazuh::SyncSchema::Status::Offline)
                {
                    std::cerr << "[Sync] Received EndAck with error status. Aborting synchronization." << std::endl;
                    m_syncState.syncFailed = true;
                    m_syncState.cv.notify_all();
                    break;
                }

                m_syncState.endAckReceived = true;
                m_syncState.cv.notify_all();

                std::cout << "[EndAck] session ended: " << incomingSession << "\n";
                break;
            }

        case Wazuh::SyncSchema::MessageType::ReqRet:
            {
                const auto* reqRet = message->content_as_ReqRet();
                const uint64_t incomingSession = reqRet->session();

                if (!validatePhaseAndSession(SyncPhase::WaitingEndAck, incomingSession))
                {
                    std::cout << "[ReqRet] invalid phase or session. \n";
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

                std::cout << "[ReqRet] received " << m_syncState.reqRetRanges.size() << " ranges\n";
                m_syncState.cv.notify_all();
                break;
            }

        default:
            {
                std::cerr << "Unknown message type: " << static_cast<int>(messageType) << "\n";
                return false;
            }
    }

    return true;
}

bool AgentSyncProtocol::validatePhaseAndSession(const SyncPhase receivedPhase, const uint64_t incomingSession)
{
    if (m_syncState.phase != receivedPhase)
    {
        std::cerr << "[Sync] Discarded. Received phase " << static_cast<int>(receivedPhase)
                  << " but current phase is " << static_cast<int>(m_syncState.phase) << "\n";
        return false;
    }

    if (m_syncState.session != incomingSession)
    {
        std::cerr << "[Sync] Discarded. Session mismatch. Expected session: "
                  << m_syncState.session << " received: " << incomingSession << "\n";
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
            if (item.seq >= range.first && item.seq <= range.second)
            {
                result.push_back(item);
                break;
            }
        }
    }

    return result;
}
