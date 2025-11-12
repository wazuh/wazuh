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
#include "routerProvider.hpp"
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
constexpr auto AGENT_ZERO_ID {"000"};

template<typename TQueue>
class ResponseDispatcherImpl
{
private:
    std::unique_ptr<TQueue> m_responseDispatcher;
    std::vector<std::pair<std::string, std::unique_ptr<RouterProvider>>> m_routerProviders; // For Agent 0 responses

    /**
     * @brief Gets the Router response topic for a specific module.
     * @param moduleName The name of the module.
     * @return The response topic string.
     */
    static std::string getModuleResponseTopic(const std::string& moduleName)
    {
        return moduleName + "-agent-responses";
    }

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

        // Initialize Router providers for Agent 0 (local IPC) - one per module
        // Make sure to add every new module here
        const std::vector<std::string> modules = {"syscollector", "sca", "fim", "agent-info"};
        for (const auto& moduleName : modules)
        {
            try
            {
                const std::string responseTopic = getModuleResponseTopic(moduleName);
                auto provider = std::make_unique<RouterProvider>(responseTopic, true);
                provider->start();
                m_routerProviders.emplace_back(moduleName, std::move(provider));
                logInfo(LOGGER_DEFAULT_TAG,
                        "ResponseDispatcher: Initialized Router support for Agent 0, module '%s' (topic: %s)",
                        moduleName.c_str(),
                        responseTopic.c_str());
            }
            catch (const std::exception& ex)
            {
                logError(LOGGER_DEFAULT_TAG,
                         "ResponseDispatcher: Failed to initialize RouterProvider for module '%s': %s",
                         moduleName.c_str(),
                         ex.what());
                // Continue without this Router - will use ARQUEUE for this module
            }
        }

        // Response queue callback - handles both Agent 0 (Router) and remote agents (ARQUEUE)
        m_responseDispatcher = std::make_unique<ResponseQueue>(
            [responseSocketClient, routerProviders = &m_routerProviders](const ResponseMessage& data)
            {
                logDebug2(LOGGER_DEFAULT_TAG,
                          "ResponseDispatcher: Sending response to agent '%s', module '%s'",
                          data.agentId.c_str(),
                          data.moduleName.c_str());
                // Check if this is Agent 0
                if (data.agentId == AGENT_ZERO_ID)
                {
                    // Agent 0: Send via Router (local IPC)
                    // Find the right provider for this module
                    RouterProvider* targetProvider = nullptr;
                    for (const auto& [moduleName, provider] : *routerProviders)
                    {
                        if (data.moduleName == moduleName)
                        {
                            targetProvider = provider.get();
                            break;
                        }
                    }

                    if (targetProvider)
                    {
                        try
                        {
                            // Convert FlatBuffer to vector<char> for Router
                            const uint8_t* bufferPtr = data.builder.GetBufferPointer();
                            const size_t bufferSize = data.builder.GetSize();
                            std::vector<char> routerMessage(bufferPtr, bufferPtr + bufferSize);

                            // Send via Router
                            targetProvider->send(routerMessage);
                        }
                        catch (const std::exception& ex)
                        {
                            logError(LOGGER_DEFAULT_TAG,
                                     "ResponseDispatcher: Failed to send to Agent 0 module '%s' via Router: %s",
                                     data.moduleName.c_str(),
                                     ex.what());
                        }
                    }
                    else
                    {
                        logError(LOGGER_DEFAULT_TAG,
                                 "ResponseDispatcher: RouterProvider for module '%s' not initialized, cannot send to "
                                 "Agent 0",
                                 data.moduleName.c_str());
                    }
                }
                else
                {
                    // Remote agents (001+): Send via ARQUEUE
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

                    responseSocketClient->send(reinterpret_cast<const char*>(messageVector.data()),
                                               messageVector.size());
                }
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
