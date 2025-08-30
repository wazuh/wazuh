/*
 * Wazuh inventory sync
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

#include "asyncValueDispatcher.hpp"
#include "flatbuffers/include/inventorySync_generated.h"
#include "loggerHelper.h"
#include "socketClient.hpp"
#include <memory>

struct ResponseMessage
{
    flatbuffers::FlatBufferBuilder builder;
    std::string agentId;
    std::string moduleName;

    // Default constructor
    ResponseMessage() = default;

    // Move constructor
    ResponseMessage(ResponseMessage&& other) noexcept = default;

    // Move assignment operator
    ResponseMessage& operator=(ResponseMessage&& other) noexcept = default;

    // Delete copy constructor and copy assignment operator
    ResponseMessage(const ResponseMessage&) = delete;
    ResponseMessage& operator=(const ResponseMessage&) = delete;

    // Destructor
    ~ResponseMessage() = default;
};

using ResponseQueue = Utils::AsyncValueDispatcher<ResponseMessage, std::function<void(ResponseMessage&&)>>;

constexpr auto ARQUEUE {"queue/alerts/ar"};

template<typename TQueue>
class ResponseDispatcherImpl
{
private:
    std::unique_ptr<TQueue> m_responseDispatcher;

public:
    explicit ResponseDispatcherImpl()
    {
        auto responseSocketClient =
            std::make_shared<SocketClient<Socket<OSPrimitives, NoHeaderProtocol>, EpollWrapper>>(ARQUEUE);
        responseSocketClient->connect(
            [](const char*, uint32_t, const char*, uint32_t)
            {
                logDebug2(LOGGER_DEFAULT_TAG, "OnRead to %s", ARQUEUE);
                // Not used
            },
            []()
            {
                logDebug2(LOGGER_DEFAULT_TAG, "Connected to %s", ARQUEUE);
                // Not used
            },
            SOCK_DGRAM);

        m_responseDispatcher = std::make_unique<ResponseQueue>(
            [responseSocketClient](const ResponseMessage& data)
            {
                thread_local std::vector<uint8_t> messageVector;
                constexpr auto header = "(msg_to_agent) [] N!s ";
                constexpr auto headerLength = 22;
                constexpr auto agentIdLength = 3;
                constexpr auto estimatedModuleNameLength = 20;
                constexpr auto estimatedPayloadLength = 10;
                messageVector.clear();
                messageVector.reserve(headerLength + agentIdLength + estimatedModuleNameLength +
                                      estimatedPayloadLength + data.builder.GetSize());
                messageVector.assign(header, header + headerLength);
                std::ranges::copy(data.agentId, std::back_inserter(messageVector));
                messageVector.push_back(' ');
                // Send the payload size
                std::ranges::copy(std::to_string(data.builder.GetSize()), std::back_inserter(messageVector));
                messageVector.push_back(' ');
                std::ranges::copy(data.moduleName, std::back_inserter(messageVector));
                std::ranges::copy("_sync ", std::back_inserter(messageVector));
                std::ranges::copy(data.builder.GetBufferPointer(),
                                  data.builder.GetBufferPointer() + data.builder.GetSize(),
                                  std::back_inserter(messageVector));

                responseSocketClient->send(reinterpret_cast<const char*>(messageVector.data()), messageVector.size());
            });
    }

    explicit ResponseDispatcherImpl(TQueue* responseDispatcher)
        : m_responseDispatcher(responseDispatcher)
    {
    }

    void sendStartAck(const Wazuh::SyncSchema::Status status,
                      std::string_view agentId,
                      const uint64_t sessionId,
                      std::string_view moduleName) const
    {
        ResponseMessage responseMessage;
        responseMessage.builder.Clear();
        responseMessage.agentId = agentId;
        responseMessage.moduleName = moduleName;
        auto startAckOffset = Wazuh::SyncSchema::CreateStartAck(responseMessage.builder, status, sessionId);

        auto messageOffset = Wazuh::SyncSchema::CreateMessage(
            responseMessage.builder, Wazuh::SyncSchema::MessageType_StartAck, startAckOffset.Union());
        responseMessage.builder.Finish(messageOffset); // Print complete message buffer in hex with spaces

        m_responseDispatcher->push(std::move(responseMessage));
    }

    void sendEndAck(const Wazuh::SyncSchema::Status status,
                    std::string_view agentId,
                    const uint64_t sessionId,
                    std::string_view moduleName) const
    {
        ResponseMessage responseMessage;
        responseMessage.builder.Clear();
        responseMessage.agentId = agentId;
        responseMessage.moduleName = moduleName;
        auto startAckOffset = Wazuh::SyncSchema::CreateEndAck(responseMessage.builder, status, sessionId);

        auto messageOffset = Wazuh::SyncSchema::CreateMessage(
            responseMessage.builder, Wazuh::SyncSchema::MessageType_EndAck, startAckOffset.Union());
        responseMessage.builder.Finish(messageOffset);

        m_responseDispatcher->push(std::move(responseMessage));
    }

    void sendEndMissingSeq(const std::string_view agentId,
                           const uint64_t sessionId,
                           std::string_view moduleName,
                           const std::vector<std::pair<uint64_t, uint64_t>>& ranges) const
    {
        ResponseMessage responseMessage;
        responseMessage.builder.Clear();
        responseMessage.agentId = agentId;
        responseMessage.moduleName = moduleName;
        std::vector<flatbuffers::Offset<Wazuh::SyncSchema::Pair>> convertedRanges;
        for (const auto& [first, second] : ranges)
        {
            auto offset = Wazuh::SyncSchema::CreatePair(responseMessage.builder, first, second);
            convertedRanges.push_back(offset);
        }

        auto endOffset = Wazuh::SyncSchema::CreateReqRetDirect(responseMessage.builder, &convertedRanges, sessionId);
        auto messageOffset = Wazuh::SyncSchema::CreateMessage(
            responseMessage.builder, Wazuh::SyncSchema::MessageType_ReqRet, endOffset.Union());
        responseMessage.builder.Finish(messageOffset);

        m_responseDispatcher->push(std::move(responseMessage));
    }
};

using ResponseDispatcher = ResponseDispatcherImpl<ResponseQueue>;

#endif // _RESPONSE_DISPATCHER_HPP
