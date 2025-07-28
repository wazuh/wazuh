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

using namespace Wazuh::SyncSchema;

AgentSyncProtocol::AgentSyncProtocol(MQ_Functions mqFuncs, std::shared_ptr<IPersistentQueue> queue)
    : m_mqFuncs(mqFuncs),
      m_persistentQueue(queue != nullptr ? std::move(queue) : std::make_shared<PersistentQueue>())
{
}

size_t AgentSyncProtocol::persistDifference(const std::string& module,
                                            const std::string& id,
                                            Operation operation,
                                            const std::string& index,
                                            const std::string& data)
{
    return m_persistentQueue->submit(module, id, index, data, operation);
}

bool AgentSyncProtocol::synchronizeModule(const std::string& module, Mode mode, bool realtime, std::chrono::seconds timeout, unsigned int retries)
{
    if (!ensureQueueAvailable())
    {
        std::cerr << "Failed to open queue: " << DEFAULTQUEUE << std::endl;
        return false;
    }

    clearSyncState();

    std::vector<PersistedData> data = m_persistentQueue->fetchAll(module);

    if (!sendStartAndWaitAck(module, mode, realtime, data.size(), timeout, retries))
    {
        std::cerr << "Failed to send start message or timed out.\n";
        clearSyncState();
        return false;
    }

    if (!sendDataMessages(module, m_syncState.session, data))
    {
        std::cerr << "Failed to send data messages.\n";
        clearSyncState();
        return false;
    }

    if (!sendEndAndWaitAck(module, m_syncState.session, timeout, retries))
    {
        std::cerr << "Failed to send end message or timed out.\n";
        clearSyncState();
        return false;
    }

    std::cout << "[Sync] Module '" << module << "' synchronized successfully.\n";
    clearPersistedDifferences(module);
    clearSyncState();

    return true;
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

bool AgentSyncProtocol::sendStartAndWaitAck(const std::string& module, Mode mode, bool realtime, size_t dataSize, const std::chrono::seconds timeout, unsigned int retries)
{
    flatbuffers::FlatBufferBuilder builder;
    auto moduleStr = builder.CreateString(module);

    StartBuilder startBuilder(builder);
    startBuilder.add_mode(mode);
    startBuilder.add_size(static_cast<uint64_t>(dataSize));
    startBuilder.add_realtime(realtime);
    startBuilder.add_module_(moduleStr);
    auto startOffset = startBuilder.Finish();

    auto message = CreateMessage(builder, MessageType::Start, startOffset.Union());
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
        if (!sendFlatBufferMessageAsString(messageVector, module))
        {
            std::cerr << "[Sync] Failed to send Start message.\n";
            continue;
        }

        if (receiveStartAck(timeout))
        {
            std::lock_guard<std::mutex> lock(m_syncState.mtx);
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
        return m_syncState.startAckReceived;
    });
}

bool AgentSyncProtocol::sendDataMessages(const std::string& module,
                                         uint64_t session,
                                         const std::vector<PersistedData>& data)
{
    for (const auto& item : data)
    {
        flatbuffers::FlatBufferBuilder builder;
        auto idStr = builder.CreateString(item.id);
        auto idxStr = builder.CreateString(item.index);
        auto dataVec = builder.CreateVector(reinterpret_cast<const int8_t*>(item.data.data()), item.data.size());

        DataBuilder dataBuilder(builder);
        dataBuilder.add_seq(item.seq);
        dataBuilder.add_session(session);
        dataBuilder.add_id(idStr);
        dataBuilder.add_index(idxStr);
        dataBuilder.add_operation(item.operation);
        dataBuilder.add_data(dataVec);
        auto dataOffset = dataBuilder.Finish();

        auto message = CreateMessage(builder, MessageType::Data, dataOffset.Union());
        builder.Finish(message);

        const uint8_t* buffer_ptr = builder.GetBufferPointer();
        const size_t buffer_size = builder.GetSize();
        std::vector<uint8_t> messageVector(buffer_ptr, buffer_ptr + buffer_size);

        if (!sendFlatBufferMessageAsString(messageVector, module))
        {
            return false;
        }
    }

    return true;
}

bool AgentSyncProtocol::sendEndAndWaitAck(const std::string& module, uint64_t session, const std::chrono::seconds timeout, unsigned int retries)
{
    flatbuffers::FlatBufferBuilder builder;
    EndBuilder endBuilder(builder);
    endBuilder.add_session(session);
    auto endOffset = endBuilder.Finish();

    auto message = CreateMessage(builder, MessageType::End, endOffset.Union());
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
        if (sendEnd && !sendFlatBufferMessageAsString(messageVector, module))
        {
            std::cerr << "[Sync] Failed to send End message.\n";
            continue;
        }

        if (!receiveEndAck(timeout))
        {
            std::cout << "[Sync] Timeout waiting for EndAck or ReqRet. Retrying...\n";
            continue;
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

            std::vector<PersistedData> rangeData = m_persistentQueue->fetchRange(module, ranges);

            if (!sendDataMessages(module, session, rangeData))
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
        return m_syncState.endAckReceived || m_syncState.reqRetReceived;
    });
}

void AgentSyncProtocol::clearPersistedDifferences(const std::string& module)
{
    m_persistentQueue->removeAll(module);
}

bool AgentSyncProtocol::sendFlatBufferMessageAsString(const std::vector<uint8_t>& fbData, const std::string& module)
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
