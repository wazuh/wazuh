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
#include <thread>

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
    catch (const std::exception& ex)
    {
        m_logger(LOG_ERROR_EXIT, "Failed to initialize PersistentQueue: " + std::string(ex.what()));
    }
}

void AgentSyncProtocol::persistDifference(const std::string& id,
                                          Operation operation,
                                          const std::string& index,
                                          const std::string& data)
{
    try
    {
        m_persistentQueue->submit(id, index, data, operation);
    }
    catch (const std::exception& e)
    {
        m_logger(LOG_ERROR, std::string("Failed to persist item: ") + e.what());
    }
}

bool AgentSyncProtocol::synchronizeModule(Mode mode, std::chrono::seconds timeout, unsigned int retries, size_t maxEps)
{
    if (!ensureQueueAvailable())
    {
        m_logger(LOG_ERROR, "Failed to open queue: " + std::string(DEFAULTQUEUE));
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
        m_logger(LOG_ERROR, std::string("Failed to fetch items for sync: ") + e.what());
        return false;
    }

    if (dataToSync.empty())
    {
        m_logger(LOG_DEBUG, "No pending items to synchronize for module " + m_moduleName);
        return true;
    }

    for (size_t i = 0; i < dataToSync.size(); ++i)
    {
        dataToSync[i].seq = i;
    }

    bool success = false;

    if (sendStartAndWaitAck(mode, dataToSync.size(), timeout, retries, maxEps))
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
            m_persistentQueue->clearSyncedItems();
        }
        else
        {
            m_logger(LOG_WARNING, "Synchronization failed.");
            m_persistentQueue->resetSyncingItems();
        }
    }
    catch (const std::exception& e)
    {
        m_logger(LOG_ERROR, std::string("Failed to finalize sync state in DB: ") + e.what());
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
                                            const std::chrono::seconds timeout,
                                            unsigned int retries,
                                            size_t maxEps)
{
    try
    {
        flatbuffers::FlatBufferBuilder builder;

        Wazuh::SyncSchema::StartBuilder startBuilder(builder);

        // Translate DB mode to Schema mode
        const auto protocolMode = (mode == Mode::FULL)
                                  ? Wazuh::SyncSchema::Mode::Full
                                  : Wazuh::SyncSchema::Mode::Delta;

        startBuilder.add_mode(protocolMode);
        startBuilder.add_size(static_cast<uint64_t>(dataSize));
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
                return true;
            }

            m_logger(LOG_DEBUG, "Timed out waiting for StartAck. Retrying...");
        }

        return false;
    }
    catch (const std::exception& e)
    {
        m_logger(LOG_ERROR, std::string("Exception when sending Start message: ") + e.what());
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

bool AgentSyncProtocol::sendDataMessages(uint64_t session,
                                         const std::vector<PersistedData>& data,
                                         size_t maxEps)
{
    try
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
            const auto protocolOperation = (item.operation == Operation::DELETE_)
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
        return m_syncState.endAckReceived || m_syncState.reqRetReceived || m_syncState.syncFailed;
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
                        m_syncState.syncFailed = true;
                        m_syncState.cv.notify_all();
                        break;
                    }

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
