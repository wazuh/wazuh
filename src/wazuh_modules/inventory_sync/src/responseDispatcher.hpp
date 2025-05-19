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
#include "threadDispatcher.h"
#include <cstdint>
#include <vector>

using ResponseQueue =
    Utils::AsyncDispatcher<::flatbuffers::Offset<Wazuh::SyncSchema::Message>,
                           std::function<void(const ::flatbuffers::Offset<Wazuh::SyncSchema::Message>&)>>;

class ResponseDispatcher final
{
private:
    std::unique_ptr<ResponseQueue> m_responseQueue;

public:
    ResponseDispatcher()
    {
        m_responseQueue = std::make_unique<ResponseQueue>(
            [](const ::flatbuffers::Offset<Wazuh::SyncSchema::Message>& /*data*/)
            {
                try
                {
                    // Send response to agent. (write to execd queue).
                }
                catch (const std::exception& e)
                {
                    std::cerr << "InventorySyncFacade::start: " << e.what() << std::endl;
                }
            },
            1,
            UNLIMITED_QUEUE_SIZE);
    }

    void sendStartAck(const Wazuh::SyncSchema::Status status, const std::shared_ptr<Context> ctx) const
    {
        flatbuffers::FlatBufferBuilder fbBuilder;
        auto startAckOffset =
            Wazuh::SyncSchema::CreateStartAckDirect(fbBuilder, status, ctx->sessionId, ctx->moduleName.c_str());

        auto messageOffset = Wazuh::SyncSchema::CreateMessage(
            fbBuilder, Wazuh::SyncSchema::MessageType_StartAck, startAckOffset.Union());
        fbBuilder.Finish(messageOffset);

        m_responseQueue->push(messageOffset);
    }

    void sendEndAck(const Wazuh::SyncSchema::Status status, const std::shared_ptr<Context> ctx)
    {
        flatbuffers::FlatBufferBuilder fbBuilder;
        auto startAckOffset =
            Wazuh::SyncSchema::CreateEndAckDirect(fbBuilder, status, ctx->sessionId, ctx->moduleName.c_str());

        auto messageOffset =
            Wazuh::SyncSchema::CreateMessage(fbBuilder, Wazuh::SyncSchema::MessageType_EndAck, startAckOffset.Union());
        fbBuilder.Finish(messageOffset);

        m_responseQueue->push(messageOffset);
    }

    void sendEndMissingSeq(const uint64_t sessionId, const std::vector<std::pair<uint64_t, uint64_t>>& ranges) const
    {
        flatbuffers::FlatBufferBuilder fbBuilder;
        std::vector<flatbuffers::Offset<Wazuh::SyncSchema::Pair>> convertedRanges;
        for (const auto& [first, second] : ranges)
        {
            auto offset = Wazuh::SyncSchema::CreatePair(fbBuilder, first, second);
            convertedRanges.push_back(offset);
        }

        auto endOffset = Wazuh::SyncSchema::CreateReqRetDirect(fbBuilder, &convertedRanges, sessionId);
        auto messageOffset =
            Wazuh::SyncSchema::CreateMessage(fbBuilder, Wazuh::SyncSchema::MessageType_End, endOffset.Union());
        fbBuilder.Finish(messageOffset);

        m_responseQueue->push(messageOffset);
    }
};

#endif // _RESPONSE_DISPATCHER_HPP
