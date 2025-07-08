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

constexpr char SYNC_MQ = 's';

using namespace Wazuh::SyncSchema;

AgentSyncProtocol::AgentSyncProtocol(MQ_Functions mqFuncs, std::shared_ptr<IPersistentQueue> queue)
    : m_mqFuncs(mqFuncs),
      m_persistentQueue(queue != nullptr ? std::move(queue) : std::make_shared<PersistentQueue>())
{
}

void AgentSyncProtocol::persistDifference(const std::string& module,
                                          const std::string& id,
                                          Operation operation,
                                          const std::string& index,
                                          const std::string& data)
{
    m_persistentQueue->submit(module, id, index, data, operation);
}

void AgentSyncProtocol::synchronizeModule(const std::string& module, Mode mode, bool realtime)
{
    if (!ensureQueueAvailable())
    {
        std::cerr << "Failed to open queue: " << DEFAULTQUEUE << std::endl;
        return;
    }

    uint64_t session = 0;
    std::vector<PersistedData> data = m_persistentQueue->fetchAll(module);

    if (!sendStartAndWaitAck(module, mode, realtime, session, data.size()))
    {
        std::cerr << "Failed to send start message" << std::endl;
        return;
    }

    if (!sendDataMessages(module, session, data))
    {
        std::cerr << "Failed to send data messages" << std::endl;
        return;
    }

    if (!sendEndAndWaitAck(module, session))
    {
        std::cerr << "Failed to send end message" << std::endl;
        return;
    }

    clearPersistedDifferences(module);
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

bool AgentSyncProtocol::sendStartAndWaitAck(const std::string& module, Mode mode, bool realtime, uint64_t& session, size_t dataSize)
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

    return sendFlatBufferMessageAsString(builder.GetBufferSpan(), module) && receiveStartAck(session);
}

bool AgentSyncProtocol::receiveStartAck(uint64_t& session)
{
    // Simulated StartAck
    session = 99999;
    return true;
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

        if (!sendFlatBufferMessageAsString(builder.GetBufferSpan(), module))
        {
            return false;
        }
    }

    return true;
}

bool AgentSyncProtocol::sendEndAndWaitAck(const std::string& module, uint64_t session)
{
    flatbuffers::FlatBufferBuilder builder;
    EndBuilder endBuilder(builder);
    endBuilder.add_session(session);
    auto endOffset = endBuilder.Finish();

    auto message = CreateMessage(builder, MessageType::End, endOffset.Union());
    builder.Finish(message);

    if (!sendFlatBufferMessageAsString(builder.GetBufferSpan(), module))
    {
        return false;
    }

    while (true)
    {
        const auto ranges = receiveReqRet();

        if (!ranges.empty())
        {
            std::vector<PersistedData> rangeData = m_persistentQueue->fetchRange(module, ranges);

            if (!sendDataMessages(module, session, rangeData))
            {
                return false;
            }

            continue;
        }

        return receiveEndAck();
    }
}

bool AgentSyncProtocol::receiveEndAck()
{
    // Simulated EndAck
    return true;
}

std::vector<std::pair<uint64_t, uint64_t>> AgentSyncProtocol::receiveReqRet()
{
    // Simulated ReqRet
    static int callCount = 0;
    callCount++;

    if (callCount == 1)
    {
        return {{1, 1}, {3, 3}};
    }
    else if (callCount == 2)
    {
        return {{2, 2}};
    }

    return {};
}

void AgentSyncProtocol::clearPersistedDifferences(const std::string& module)
{
    m_persistentQueue->removeAll(module);
}

bool AgentSyncProtocol::sendFlatBufferMessageAsString(flatbuffers::span<uint8_t> fbData, const std::string& module)
{
    std::string message(reinterpret_cast<const char*>(fbData.data()), fbData.size());

    if (m_mqFuncs.send(m_queue, message.c_str(), module.c_str(), SYNC_MQ) < 0)
    {
        std::cerr << "SendMSG failed, attempting to reinitialize queue..." << std::endl;
        m_queue = m_mqFuncs.start(DEFAULTQUEUE, WRITE, 0);

        if (m_queue < 0 || m_mqFuncs.send(m_queue, message.c_str(), module.c_str(), SYNC_MQ) < 0)
        {
            std::cerr << "Failed to send message after retry" << std::endl;
            return false;
        }
    }

    return true;
}

bool AgentSyncProtocol::parseResponseBuffer(const uint8_t* data, size_t size)
{
    if (!data || size == 0)
    {
        std::cerr << "Invalid buffer received.\n";
        return false;
    }

    const auto* message = Wazuh::SyncSchema::GetMessage(data);
    const auto messageType = message->content_type();

    switch (messageType)
    {
        case Wazuh::SyncSchema::MessageType::StartAck:
            {
                const auto* startAck = message->content_as_StartAck();
                std::cout << "[StartAck] session: " << startAck->session() << "\n";
                break;
            }

        case Wazuh::SyncSchema::MessageType::EndAck:
            {
                std::cout << "[EndAck] received\n";
                break;
            }

        case Wazuh::SyncSchema::MessageType::ReqRet:
            {
                const auto* reqRet = message->content_as_ReqRet();
                std::vector<std::pair<uint64_t, uint64_t>> reqRetRanges;

                for (const auto* pair : *reqRet->seq())
                {
                    reqRetRanges.emplace_back(pair->begin(), pair->end());
                }

                std::cout << "[ReqRet] received " << reqRetRanges.size() << " ranges\n";
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
