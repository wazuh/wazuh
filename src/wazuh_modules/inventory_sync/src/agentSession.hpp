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

#include "context.hpp"
#include "flatbuffers/include/inventorySync_generated.h"
#include "gapSet.hpp"
#include "responseDispatcher.hpp"
#include "rocksDBWrapper.hpp"
#include "threadDispatcher.h"
#include <cctype>
#include <functional>
#include <memory>
#include <ranges>
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
    bool m_endEnqueued = false;         ///< Whether the END message has been enqueued

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

        // Extract module
        auto moduleName = data->module_() ? data->module_()->string_view() : std::string_view();

        // Extract agent details
        auto agentId = data->agentid() ? data->agentid()->string_view() : std::string_view();
        auto agentName = data->agentname() ? data->agentname()->string_view() : std::string_view();
        auto agentVersion = data->agentversion() ? data->agentversion()->string_view() : std::string_view();
        auto architecture = data->architecture() ? data->architecture()->string_view() : std::string_view();
        auto hostname = data->hostname() ? data->hostname()->string_view() : std::string_view();
        auto osname = data->osname() ? data->osname()->string_view() : std::string_view();
        auto osplatform = data->osplatform() ? data->osplatform()->string_view() : std::string_view();
        auto ostype = data->ostype() ? data->ostype()->string_view() : std::string_view();
        auto osversion = data->osversion() ? data->osversion()->string_view() : std::string_view();
        auto globalVersion = data->global_version();

        auto agentIdString = std::string(agentId.data(), agentId.size());
        if (agentIdString.length() < 3)
        {
            agentIdString.insert(0, 3 - agentIdString.length(), '0');
        }

        // Extract groups
        std::vector<std::string> groups;
        if (data->groups())
        {
            for (const auto* group : *data->groups())
            {
                if (group)
                {
                    groups.emplace_back(group->str());
                }
            }
        }

        // Extract indices
        std::vector<std::string> indices;
        if (data->index())
        {
            for (const auto* index : *data->index())
            {
                if (index)
                {
                    indices.emplace_back(index->str());
                }
            }
        }

        // Create new session.
        // Size validation: MetadataDelta, MetadataCheck, GroupDelta, GroupCheck don't send data messages, so size can
        // be 0
        if (data->size() == 0 && data->mode() != Wazuh::SyncSchema::Mode_MetadataDelta &&
            data->mode() != Wazuh::SyncSchema::Mode_MetadataCheck &&
            data->mode() != Wazuh::SyncSchema::Mode_GroupDelta && data->mode() != Wazuh::SyncSchema::Mode_GroupCheck)
        {
            responseDispatcher.sendStartAck(Wazuh::SyncSchema::Status_Error, agentId, sessionId, moduleName);
            throw AgentSessionException("Invalid size");
        }

        m_gapSet = std::make_unique<GapSet>(data->size());

        m_context =
            std::make_shared<Context>(Context {.mode = data->mode(),
                                               .option = data->option(),
                                               .sessionId = sessionId,
                                               .moduleName = std::string(moduleName.data(), moduleName.size()),
                                               .indices = std::move(indices),
                                               .agentId = std::move(agentIdString),
                                               .agentName = std::string(agentName.data(), agentName.size()),
                                               .agentVersion = std::string(agentVersion.data(), agentVersion.size()),
                                               .architecture = std::string(architecture.data(), architecture.size()),
                                               .hostname = std::string(hostname.data(), hostname.size()),
                                               .osname = std::string(osname.data(), osname.size()),
                                               .osplatform = std::string(osplatform.data(), osplatform.size()),
                                               .ostype = std::string(ostype.data(), ostype.size()),
                                               .osversion = std::string(osversion.data(), osversion.size()),
                                               .groups = std::move(groups),
                                               .globalVersion = globalVersion});

        logDebug2(LOGGER_DEFAULT_TAG,
                  "New session for module '%s' by agent '%s'. (Session %llu)",
                  m_context->moduleName.c_str(),
                  m_context->agentId.c_str(),
                  m_context->sessionId);

        responseDispatcher.sendStartAck(
            Wazuh::SyncSchema::Status_Ok, m_context->agentId, m_context->sessionId, m_context->moduleName);
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
     * @param dataSize Size of the raw payload.
     */
    void handleData(Wazuh::SyncSchema::DataValue const* data, const uint8_t* dataRaw, size_t dataSize)
    {
        if (data == nullptr)
        {
            throw AgentSessionException("Invalid data on handleData");
        }

        std::lock_guard lock(m_mutex);

        const auto seq = data->seq();
        const auto session = data->session();

        logDebug2(LOGGER_DEFAULT_TAG, "Handling sequence number '%llu' for session '%llu'", seq, session);

        m_store.put(std::format("{}_{}", session, seq),
                    rocksdb::Slice(reinterpret_cast<const char*>(dataRaw), dataSize));

        m_gapSet->observe(data->seq());

        logDebug2(LOGGER_DEFAULT_TAG,
                  "Data received: %s %llu %llu %s",
                  std::format("{}_{}", session, seq).c_str(),
                  m_context->sessionId,
                  m_context->agentId,
                  m_context->moduleName.c_str());

        if (m_endReceived)
        {
            if (m_gapSet->empty())
            {
                m_indexerQueue.push(Response({.status = ResponseStatus::Ok, .context = m_context}));
                m_endEnqueued = true;
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

        if (m_endEnqueued)
        {
            logDebug2(LOGGER_DEFAULT_TAG, "End already enqueued for session %llu", m_context->sessionId);
            return;
        }

        if (m_gapSet->empty())
        {
            logDebug2(LOGGER_DEFAULT_TAG, "All sequences received for session %llu", m_context->sessionId);
            m_indexerQueue.push(Response({.status = ResponseStatus::Ok, .context = m_context}));
            m_endEnqueued = true;
        }
        else
        {
            responseDispatcher.sendEndMissingSeq(
                m_context->agentId, m_context->sessionId, m_context->moduleName, m_gapSet->ranges());
        }
    }

    /**
     * @brief Checks whether the session has timed out based on last activity.
     * @param timeout The allowed inactivity duration.
     * @return true if the session has been idle for longer than the timeout.
     */
    bool isAlive(const std::chrono::seconds timeout) const
    {
        return m_gapSet->lastUpdate() + timeout >= std::chrono::steady_clock::now();
    }
};

using AgentSession = AgentSessionImpl<Utils::RocksDBWrapper, IndexerQueue, ResponseDispatcher>;

#endif // _AGENT_SESSION_HPP
