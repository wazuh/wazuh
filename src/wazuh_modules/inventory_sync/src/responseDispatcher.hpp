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

constexpr auto ARQUEUE_PATH {"queue/sockets/ar"};
constexpr auto WM_INVENTORY_SYNC_LOGTAG {"wazuh-manager-modulesd:inventory-sync"};

template<typename TQueue>
class ResponseDispatcherImpl
{
private:
    std::unique_ptr<TQueue> m_responseDispatcher;
    LogFn m_logFn;

public:
    explicit ResponseDispatcherImpl()
        : m_logFn(Log::currentModuleLogFn())
    {
        auto responseSocketClient =
            std::make_shared<SocketClient<Socket<OSPrimitives, NoHeaderProtocol>, EpollWrapper>>(ARQUEUE_PATH);
        responseSocketClient->connect(
            [logFn = m_logFn](const char*, uint32_t, const char*, uint32_t)
            {
                LOGFN_DEBUG2(logFn, "OnRead to %s", ARQUEUE_PATH);
                // Not used
            },
            [logFn = m_logFn]()
            {
                LOGFN_DEBUG2(logFn, "Connected to %s", ARQUEUE_PATH);
                // Not used
            },
            SOCK_DGRAM);

        // Response queue callback - uses ARQUEUE for all agents
        m_responseDispatcher = std::make_unique<ResponseQueue>(
            [responseSocketClient, logFn = m_logFn](const ResponseMessage& data)
            {
                LOGFN_DEBUG2(logFn,
                             "ResponseDispatcher: Sending response to agent '%s', module '%s'",
                             data.agentId.c_str(),
                             data.moduleName.c_str());

                // Send via ARQUEUE for all agents
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
        , m_logFn(Log::currentModuleLogFn())
    {
    }
};

using ResponseDispatcher = ResponseDispatcherImpl<ResponseQueue>;

#endif // _RESPONSE_DISPATCHER_HPP
