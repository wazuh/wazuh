
/*
 * Wazuh inventory sync
 * Copyright (C) 2015, Wazuh Inc.
 * August 6, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _AGENT_SESSION_HPP
#define _AGENT_SESSION_HPP

#include "asyncValueDispatcher.hpp"
#include "context.hpp"
#include "flatbuffers/include/inventorySync_generated.h"
#include "gapSet.hpp"
#include "responseDispatcher.hpp"
#include "rocksDBWrapper.hpp"
#include <functional>
#include <memory>
#include <string>
#include <utility>

enum class ResponseStatus : std::uint8_t
{
    Ok,
    Error,
};

struct Response
{
    ResponseStatus status;
    std::shared_ptr<Context> context;
};

using WorkersQueue = Utils::AsyncValueDispatcher<std::vector<char>, std::function<void(const std::vector<char>&)>>;
using IndexerQueue = Utils::AsyncValueDispatcher<Response, std::function<void(const Response&)>>;

class AgentSessionException : public std::exception
{
public:
    explicit AgentSessionException(std::string message)
        : m_message(std::move(message))
    {
    }

    const char* what() const noexcept override
    {
        return m_message.c_str();
    }

private:
    std::string m_message;
};

/**
 * @class AgentSessionImpl
 * @brief Manages the lifecycle of a data ingestion session from a specific agent.
 *
 * Handles sequential chunk reception, stores data into RocksDB, tracks missing pieces using GapSet,
 * and sends appropriate acknowledgments or error notifications via dispatcher queues.
 *
 * @tparam TStore Store interface (e.g., RocksDB wrapper).
 * @tparam TIndexerQueue Queue used to notify indexing system upon session completion.
 * @tparam TResponseDispatcher Dispatcher used to send ACK/NACK messages during session flow.
 */

template<typename TStore, typename TIndexerQueue, typename TResponseDispatcher>
class AgentSessionImpl final
{
    std::unique_ptr<GapSet> m_gapSet;   ///< Tracker for received/missing data chunks
    std::shared_ptr<Context> m_context; ///< Shared metadata for the current session
    TStore& m_store;                    ///< Reference to RocksDB store
    TIndexerQueue& m_indexerQueue;      ///< Response queue for indexing subsystem
    bool m_endReceived = false;         ///< Whether the END message has been received
    std::mutex m_mutex;                 ///< Mutex to guard shared state

public:
    explicit AgentSessionImpl(const uint64_t sessionId,
                              Wazuh::SyncSchema::Start const* data,
                              TStore& store,
                              TIndexerQueue& indexerQueue,
                              const TResponseDispatcher& responseDispatcher)
        : m_store {store}
        , m_indexerQueue {indexerQueue}

    {
        if (data == nullptr)
        {
            throw AgentSessionException("Invalid data");
        }

        if (data->module_() == nullptr)
        {
            throw AgentSessionException("Invalid module");
        }

        if (data->agent_id() == 0)
        {
            throw AgentSessionException("Invalid id");
        }

        // Create new session.
        if (data->size() == 0)
        {
            throw AgentSessionException("Invalid size");
        }
        m_gapSet = std::make_unique<GapSet>(data->size());

        m_context = std::make_shared<Context>(Context {.mode = data->mode(),
                                                       .sessionId = sessionId,
                                                       .agentId = data->agent_id(),
                                                       .moduleName = data->module_()->str()});

        std::cout << "AgentSessionImpl: " << m_context->sessionId << " " << m_context->agentId << " "
                  << m_context->moduleName << std::endl;

        responseDispatcher.sendStartAck(Wazuh::SyncSchema::Status_Ok, m_context);
    }

    /// Deleted copy constructor and assignment operator (C.12 compliant).
    AgentSessionImpl(const AgentSessionImpl&) = delete;
    AgentSessionImpl& operator=(const AgentSessionImpl&) = delete;

    /// Deleted move constructor and assignment operator.
    AgentSessionImpl(AgentSessionImpl&&) = delete;
    AgentSessionImpl& operator=(AgentSessionImpl&&) = delete;

    ~AgentSessionImpl() = default;

    /**
     * @brief Handles an incoming data chunk.
     *
     * Stores the raw payload and marks the chunk as observed in the GapSet.
     * Triggers indexing if `handleEnd()` was already called and the session is now complete.
     *
     * @param data Parsed flatbuffer metadata (e.g., sequence number).
     * @param dataRaw Raw binary payload of the chunk.
     */
    void handleData(Wazuh::SyncSchema::Data const* data, const std::vector<char>& dataRaw)
    {
        const auto seq = data->seq();
        const auto session = data->session();

        m_store.put(std::to_string(session) + "_" + std::to_string(seq),
                    rocksdb::Slice(dataRaw.data(), dataRaw.size()));

        std::lock_guard lock(m_mutex);
        m_gapSet->observe(data->seq());

        if (m_endReceived)
        {
            if (m_gapSet->empty())
            {
                m_indexerQueue.push(Response {ResponseStatus::Ok, m_context});
            }
        }
    }

    /**
     * @brief Handles the end-of-transmission signal from the agent.
     *
     * If all chunks were received, pushes the final acknowledgment. Otherwise, triggers missing range dispatch.
     *
     * @param responseDispatcher Dispatcher used to report missing sequences (if any).
     */

    void handleEnd(const TResponseDispatcher& responseDispatcher)
    {
        std::lock_guard lock(m_mutex);
        m_endReceived = true;
        if (m_gapSet->empty())
        {
            std::cout << "End received and gap set is empty\n";
            m_indexerQueue.push(Response {ResponseStatus::Ok, m_context});
        }
        else
        {
            responseDispatcher.sendEndMissingSeq(m_context->sessionId, m_gapSet->ranges());
        }
    }

    /**
     * @brief Checks whether the session has timed out based on last activity.
     * @param timeout The allowed inactivity duration.
     * @return true if the session has been idle for longer than the timeout.
     */
    bool isAlive(const std::chrono::seconds timeout) const
    {
        return m_gapSet->lastUpdate() + timeout < std::chrono::steady_clock::now();
    }
};

using AgentSession = AgentSessionImpl<Utils::RocksDBWrapper, IndexerQueue, ResponseDispatcher>;

#endif // _AGENT_SESSION_HPP
