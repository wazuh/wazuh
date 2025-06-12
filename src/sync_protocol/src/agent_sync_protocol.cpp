#include "agent_sync_protocol.hpp"

#include <flatbuffers/flatbuffers.h>
#include <iostream>

using namespace Wazuh::SyncSchema;

void AgentSyncProtocol::persistDifference(const std::string& module,
                                          const std::string& id,
                                          Operation operation,
                                          const std::string& index,
                                          const std::string& data)
{
    m_data[module].emplace_back(
        PersistedData {.seq = ++m_seqCounter, .id = id, .index = index, .data = data, .operation = operation});
}

void AgentSyncProtocol::synchronizeModule(const std::string& module, Mode mode, bool realtime)
{
    uint64_t session = 0;
    if (!sendStartAndWaitAck(module, mode, realtime, session))
    {
        std::cerr << "StartAck failed for module: " << module << std::endl;
        return;
    }

    sendDataMessages(module, session);
    sendEnd(session);

    while (true)
    {
        bool success = false;
        if (receiveEndAck(success))
        {
            if (success)
            {
                clearPersistedDifferences(module);
            }
            else
            {
                std::cerr << "EndAck failed for module: " << module << std::endl;
            }
            return;
        }

        const auto ranges = receiveReqRet();
        if (!ranges.empty())
        {
            sendDataMessages(module, session, &ranges);
        }
    }
}

bool AgentSyncProtocol::sendStartAndWaitAck(const std::string& module, Mode mode, bool realtime, uint64_t& session)
{
    flatbuffers::FlatBufferBuilder builder;
    auto moduleStr = builder.CreateString(module);

    StartBuilder startBuilder(builder);
    startBuilder.add_mode(mode);
    startBuilder.add_size(static_cast<uint64_t>(m_data[module].size()));
    startBuilder.add_realtime(realtime);
    startBuilder.add_module_(moduleStr);
    auto startOffset = startBuilder.Finish();

    auto message = CreateMessage(builder, MessageType::Start, startOffset.Union());
    builder.Finish(message);

    sendFlatBufferMessageAsString(builder.GetBufferSpan());

    // Simulated StartAck
    session = 99999;
    return true;
}

void AgentSyncProtocol::sendDataMessages(const std::string& module,
                                         uint64_t session,
                                         const std::vector<std::pair<uint64_t, uint64_t>>* ranges)
{
    for (const auto& item : m_data[module])
    {
        bool inRange = true;
        if (ranges)
        {
            inRange = false;
            for (const auto& [begin, end] : *ranges)
            {
                if (item.seq >= begin && item.seq <= end)
                {
                    inRange = true;
                    break;
                }
            }
        }

        if (!inRange)
        {
            continue;
        }

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

        sendFlatBufferMessageAsString(builder.GetBufferSpan());
    }
}

void AgentSyncProtocol::sendEnd(uint64_t session)
{
    flatbuffers::FlatBufferBuilder builder;
    EndBuilder endBuilder(builder);
    endBuilder.add_session(session);
    auto endOffset = endBuilder.Finish();

    auto message = CreateMessage(builder, MessageType::End, endOffset.Union());
    builder.Finish(message);

    sendFlatBufferMessageAsString(builder.GetBufferSpan());
}

bool AgentSyncProtocol::receiveEndAck(bool& success)
{
    static int attempt = 0;
    attempt++;

    success = (attempt > 2);        // Simulate final success
    return success || attempt == 3; // Return true when EndAck is received
}

std::vector<std::pair<uint64_t, uint64_t>> AgentSyncProtocol::receiveReqRet()
{
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
    m_data.erase(module);
}

void AgentSyncProtocol::sendFlatBufferMessageAsString(flatbuffers::span<uint8_t> fbData)
{
    std::string str(reinterpret_cast<const char*>(fbData.data()), fbData.size());
    std::cout << "[Agent->agentd] Sending message: " << str << std::endl;
}
