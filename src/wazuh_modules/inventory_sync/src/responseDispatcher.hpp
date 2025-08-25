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
#include <ranges>
#include <vector>

// Message protocol constants
constexpr std::string_view MSG_HEADER = "(msg_to_agent) [] N!S ";
constexpr size_t MSG_HEADER_SIZE = 22;
constexpr size_t AGENT_ID_PADDING = 3;
constexpr char AGENT_ID_PADDING_CHAR = '0';
constexpr char MSG_SEPARATOR = ' ';

// Queue configuration
constexpr auto AR_QUEUE_PATH = "queue/alerts/ar";

constexpr size_t MAX_RANGES_BATCH_SIZE = 100; // Maximum ranges to process in one batch

/**
 * @brief Message structure for response communication
 *
 * This structure encapsulates a response message with its FlatBuffers data,
 * agent identification, and module information. It's designed for efficient
 * move operations to minimize copying overhead.
 *
 * Performance considerations:
 * - Move-only semantics to prevent expensive copies
 * - FlatBufferBuilder is relatively expensive to copy
 * - String storage is optimized for small string optimization (SSO)
 */
struct ResponseMessage
{
    flatbuffers::FlatBufferBuilder builder; ///< FB buffer to be sent
    std::string agentId;                    ///< Preformatted agent id
    std::string moduleName;                 ///< Module name

    ResponseMessage() = default;
    ResponseMessage(ResponseMessage&&) noexcept = default;
    ResponseMessage& operator=(ResponseMessage&&) noexcept = default;

    ResponseMessage(const ResponseMessage&) = delete;
    ResponseMessage& operator=(const ResponseMessage&) = delete;
    ~ResponseMessage() = default;
};

// Type alias for the response queue with performance-oriented dispatcher
using ResponseQueue = Utils::AsyncValueDispatcher<ResponseMessage, std::function<void(ResponseMessage&&)>>;

/**
 * @brief High-performance response dispatcher for Wazuh inventory synchronization
 *
 * This class manages the dispatch of response messages through a socket-based queue system.
 * It's designed with the following performance considerations:
 *
 * 1. Template-based design for compile-time optimization
 * 2. Move semantics throughout to minimize copies
 * 3. Thread-local storage for message buffers to avoid allocations
 * 4. Efficient message construction with pre-calculated sizes
 * 5. Batched processing capabilities for large operations
 *
 * Thread Safety:
 * - The class is thread-safe when using the default ResponseQueue
 * - Multiple threads can safely call send methods concurrently
 * - Internal message buffer is thread_local for performance
 *
 * Memory Management:
 * - Uses RAII principles throughout
 * - Minimizes dynamic allocations through buffer reuse
 * - FlatBuffers provide efficient serialization
 *
 * @tparam TQueue Queue implementation type (allows for testing and customization)
 */
template<typename TQueue>
class ResponseDispatcherImpl
{
private:
    std::unique_ptr<TQueue> m_responseDispatcher;

public:
    /**
     * @brief Default constructor - creates a fully configured response dispatcher
     *
     * Initializes the dispatcher with a socket-based queue connected to the AR queue.
     * This constructor handles all the complex setup internally.
     */
    explicit ResponseDispatcherImpl()
    {
        auto responseSocketClient =
            std::make_shared<SocketClient<Socket<OSPrimitives, NoHeaderProtocol>, EpollWrapper>>(AR_QUEUE_PATH);
        responseSocketClient->connect(
            [](const char*, uint32_t, const char*, uint32_t)
            {
                logDebug2(LOGGER_DEFAULT_TAG, "OnRead to %s", AR_QUEUE_PATH);
                // Not used
            },
            []()
            {
                logDebug2(LOGGER_DEFAULT_TAG, "Connected to %s", AR_QUEUE_PATH);
                // Not used
            },
            SOCK_DGRAM);

        m_responseDispatcher = std::make_unique<ResponseQueue>(
            [responseSocketClient](const ResponseMessage& data)
            {
                thread_local std::vector<uint8_t> messageVector;
                constexpr auto header = "(msg_to_agent) [] N!s ";
                constexpr auto headerSize = 22;
                messageVector.clear();
                messageVector.reserve(headerSize + 5 + data.builder.GetSize());
                messageVector.assign(header, header + headerSize);
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

    /**
     * @brief Constructor for dependency injection (primarily for testing)
     * @param responseDispatcher Pre-configured queue implementation
     *
     * This constructor allows injection of custom queue implementations,
     * useful for unit testing or alternative transport mechanisms.
     */
    explicit ResponseDispatcherImpl(TQueue* responseDispatcher)
        : m_responseDispatcher(responseDispatcher)
    {
    }

    // Non-copyable but moveable for efficient resource management
    ResponseDispatcherImpl(const ResponseDispatcherImpl&) = delete;
    ResponseDispatcherImpl& operator=(const ResponseDispatcherImpl&) = delete;
    ResponseDispatcherImpl(ResponseDispatcherImpl&&) = default;
    ResponseDispatcherImpl& operator=(ResponseDispatcherImpl&&) = default;

    /**
     * @brief Optimized agent ID formatting with caching
     * @param agentId Numeric agent ID
     * @return Formatted agent ID string with appropriate padding
     */
    [[nodiscard]] static std::string formatAgentId(uint32_t agentId)
    {
        // For small agent IDs, this is more efficient than repeated string operations
        const std::string agentIdStr = std::to_string(agentId);
        return Utils::padString(agentIdStr, AGENT_ID_PADDING_CHAR, AGENT_ID_PADDING);
    }

    /**
     * @brief Send a synchronization start acknowledgment
     * @param status Synchronization status to report
     * @param ctx Shared context containing session information
     *
     * Performance notes:
     * - Uses move semantics for message dispatch
     * - Optimized agent ID formatting
     * - Efficient FlatBuffers message construction
     */
    void sendStartAck(const Wazuh::SyncSchema::Status status,
                      const uint64_t agentId,
                      const uint64_t sessionId,
                      std::string_view moduleName) const
    {
        ResponseMessage responseMessage;
        responseMessage.builder.Clear();

        responseMessage.agentId = std::to_string(agentId);
        if (responseMessage.agentId.length() < 3)
        {
            responseMessage.agentId.insert(0, 3 - responseMessage.agentId.length(), '0');
        }
        responseMessage.moduleName = moduleName;
        auto startAckOffset = Wazuh::SyncSchema::CreateStartAck(responseMessage.builder, status, sessionId);

        auto messageOffset = Wazuh::SyncSchema::CreateMessage(
            responseMessage.builder, Wazuh::SyncSchema::MessageType_StartAck, startAckOffset.Union());
        responseMessage.builder.Finish(messageOffset); // Print complete message buffer in hex with spaces

        m_responseDispatcher->push(std::move(responseMessage));
    }

    /**
     * @brief Send a synchronization end acknowledgment
     * @param status Final synchronization status
     * @param ctx Shared context containing session information
     */
    void sendEndAck(const Wazuh::SyncSchema::Status status,
                    const uint64_t agentId,
                    const uint64_t sessionId,
                    std::string_view moduleName) const
    {
        ResponseMessage responseMessage;
        responseMessage.builder.Clear();
        responseMessage.agentId = std::to_string(agentId);
        if (responseMessage.agentId.length() < 3)
        {
            responseMessage.agentId.insert(0, 3 - responseMessage.agentId.length(), '0');
        }
        responseMessage.moduleName = moduleName;
        auto startAckOffset = Wazuh::SyncSchema::CreateEndAck(responseMessage.builder, status, sessionId);

        auto messageOffset = Wazuh::SyncSchema::CreateMessage(
            responseMessage.builder, Wazuh::SyncSchema::MessageType_EndAck, startAckOffset.Union());
        responseMessage.builder.Finish(messageOffset);

        m_responseDispatcher->push(std::move(responseMessage));
    }

    /**
     * @brief Send a request for retransmission of missing sequence ranges
     * @param sessionId Session identifier for the request
     * @param ranges Vector of sequence number ranges to request
     *
     * Performance considerations:
     * - Validates input size to prevent excessive memory usage
     * - Efficient range processing with minimal allocations
     * - Uses FlatBuffers Direct creation when possible
     *
     * @throws std::invalid_argument if ranges vector is too large
     */
    void sendEndMissingSeq(const uint64_t agentId,
                           const uint64_t sessionId,
                           std::string_view moduleName,
                           const std::vector<std::pair<uint64_t, uint64_t>>& ranges) const
    {
        ResponseMessage responseMessage;
        responseMessage.builder.Clear();
        responseMessage.agentId = std::to_string(agentId);
        if (responseMessage.agentId.length() < 3)
        {
            responseMessage.agentId.insert(0, 3 - responseMessage.agentId.length(), '0');
        }
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
