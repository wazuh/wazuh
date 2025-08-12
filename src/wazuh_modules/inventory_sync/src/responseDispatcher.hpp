/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * January 20, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _RESPONSE_DISPATCHER_HPP
#define _RESPONSE_DISPATCHER_HPP

#include "context.hpp"
#include "flatbuffers/include/inventorySync_generated.h"
#include "socketClient.hpp"
#include "threadDispatcher.h"
#include <cstdint>
#include <memory>
#include <vector>

using ResponseQueue =
    Utils::AsyncDispatcher<std::shared_ptr<flatbuffers::FlatBufferBuilder>,
                           std::function<void(const std::shared_ptr<flatbuffers::FlatBufferBuilder>&)>>;

constexpr auto EXECQUEUE {"queue/alerts/execq"};

template<typename TQueue>
class ResponseDispatcherImpl
{
private:
    std::unique_ptr<TQueue> m_responseDispatcher;

public:
    explicit ResponseDispatcherImpl()
    {
        auto responseSocketClient =
            std::make_shared<SocketClient<Socket<OSPrimitives, AppendHeaderProtocol>, EpollWrapper>>(EXECQUEUE);
        responseSocketClient->connect(
            [](const char*, uint32_t, const char*, uint32_t)
            {
                std::cout << "OnRead to " << EXECQUEUE << std::endl;
                // Not used
            },
            []()
            {
                std::cout << "Connected to " << EXECQUEUE << std::endl;
                // Not used
            });

        m_responseDispatcher = std::make_unique<ResponseQueue>(
            [responseSocketClient](const std::shared_ptr<flatbuffers::FlatBufferBuilder>& data)
            {
                std::cout << "Sending data: " << data->GetSize() << std::endl;
                responseSocketClient->send(reinterpret_cast<const char*>(data->GetBufferPointer()), data->GetSize());
                // We wait to keep the maximum number of events per second
                // if (reportsWait > 0)
                // {
                //     std::this_thread::sleep_for(std::chrono::microseconds(reportsWait));
                // }
                // logDebug2(WM_VULNSCAN_LOGTAG, "Report sent: %s", data.c_str());
            });
    }

    explicit ResponseDispatcherImpl(TQueue* responseDispatcher)
        : m_responseDispatcher(responseDispatcher)
    {
    }

    void sendStartAck(const Wazuh::SyncSchema::Status status, const std::shared_ptr<Context> ctx) const
    {
        auto fbBuilder = std::make_shared<flatbuffers::FlatBufferBuilder>();
        auto startAckOffset =
            Wazuh::SyncSchema::CreateStartAckDirect(*fbBuilder, status, ctx->sessionId, ctx->moduleName.c_str());

        auto messageOffset = Wazuh::SyncSchema::CreateMessage(
            *fbBuilder, Wazuh::SyncSchema::MessageType_StartAck, startAckOffset.Union());
        fbBuilder->Finish(messageOffset);

        m_responseDispatcher->push(fbBuilder);
    }

    void sendEndAck(const Wazuh::SyncSchema::Status status, const std::shared_ptr<Context> ctx) const
    {
        auto fbBuilder = std::make_shared<flatbuffers::FlatBufferBuilder>();
        auto startAckOffset =
            Wazuh::SyncSchema::CreateEndAckDirect(*fbBuilder, status, ctx->sessionId, ctx->moduleName.c_str());

        auto messageOffset =
            Wazuh::SyncSchema::CreateMessage(*fbBuilder, Wazuh::SyncSchema::MessageType_EndAck, startAckOffset.Union());
        fbBuilder->Finish(messageOffset);

        m_responseDispatcher->push(fbBuilder);
    }

    void sendEndMissingSeq(const uint64_t sessionId, const std::vector<std::pair<uint64_t, uint64_t>>& ranges) const
    {
        auto fbBuilder = std::make_shared<flatbuffers::FlatBufferBuilder>();
        std::vector<flatbuffers::Offset<Wazuh::SyncSchema::Pair>> convertedRanges;
        for (const auto& [first, second] : ranges)
        {
            auto offset = Wazuh::SyncSchema::CreatePair(*fbBuilder, first, second);
            convertedRanges.push_back(offset);
        }

        auto endOffset = Wazuh::SyncSchema::CreateReqRetDirect(*fbBuilder, &convertedRanges, sessionId);
        auto messageOffset =
            Wazuh::SyncSchema::CreateMessage(*fbBuilder, Wazuh::SyncSchema::MessageType_ReqRet, endOffset.Union());
        fbBuilder->Finish(messageOffset);

        m_responseDispatcher->push(fbBuilder);
    }
};

using ResponseDispatcher = ResponseDispatcherImpl<ResponseQueue>;

#endif // _RESPONSE_DISPATCHER_HPP
