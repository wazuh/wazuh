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

#ifndef _INVENTORY_SYNC_FACADE_HPP
#define _INVENTORY_SYNC_FACADE_HPP

#include "agentSession.hpp"
#include "flatbuffers/buffer.h"
#include "flatbuffers/include/inventorySync_generated.h"
#include "loggerHelper.h"
#include "routerSubscriber.hpp"
#include "singleton.hpp"
#include <asyncValueDispatcher.hpp>
#include <filesystem>
#include <functional>
#include <indexerConnector.hpp>
#include <json.hpp>
#include <memory>
#include <random>
#include <rocksdb/slice.h>
#include <shared_mutex>
#include <string>
#include <utility>

constexpr int SINGLE_THREAD_COUNT = 1;
constexpr auto INVENTORY_SYNC_PATH {"inventory_sync"};
constexpr auto INVENTORY_SYNC_TOPIC {"inventory-states"};
constexpr auto INVENTORY_SYNC_SUBSCRIBER_ID {"inventory-sync-module"};

using WorkersQueue = Utils::AsyncValueDispatcher<std::vector<char>, std::function<void(const std::vector<char>&)>>;
using IndexerQueue = Utils::AsyncValueDispatcher<Response, std::function<void(const Response&)>>;

class InventorySyncException : public std::exception
{
public:
    explicit InventorySyncException(std::string message)
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
 * @brief InventorySyncFacade class.
 *
 */
template<typename TAgentSession,
         typename TResponseDispatcher,
         typename TRouterSubscriber,
         typename TIndexerConnector,
         typename TRocksDBWrapper>
class InventorySyncFacadeImpl final
    : public Singleton<InventorySyncFacadeImpl<TAgentSession,
                                               TResponseDispatcher,
                                               TRouterSubscriber,
                                               TIndexerConnector,
                                               TRocksDBWrapper>>
{
    friend class Singleton<InventorySyncFacadeImpl<TAgentSession,
                                                   TResponseDispatcher,
                                                   TRouterSubscriber,
                                                   TIndexerConnector,
                                                   TRocksDBWrapper>>;
    static constexpr int m_threadCount = 1;
    static constexpr int m_bulkDataSize = 10 * 1024 * 1024;

    void run(const std::vector<char>& dataRaw)
    {
        auto message = Wazuh::SyncSchema::GetMessage(dataRaw.data());
        if (message->content_type() == Wazuh::SyncSchema::MessageType_Data)
        {
            const auto data = message->content_as<Wazuh::SyncSchema::Data>();
            if (!data)
            {
                throw InventorySyncException("Invalid data message");
            }

            // Check if session exists.
            std::shared_lock lock(m_agentSessionsMutex);
            auto it = m_agentSessions.find(data->session());
            if (it == m_agentSessions.end())
            {
                throw InventorySyncException("Session not found");
            }

            // Handle data.
            it->second.handleData(data, dataRaw);
        }
        else if (message->content_type() == Wazuh::SyncSchema::MessageType_Start)
        {
            // Generate random number for session ID.
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<uint64_t> dis(0, UINT64_MAX);
            const auto sessionId = dis(gen);
            {
                std::unique_lock lock(m_agentSessionsMutex);
                // Check if session already exists.
                if (m_agentSessions.contains(sessionId))
                {
                    throw InventorySyncException("Session already exists");
                }

                m_agentSessions.try_emplace(sessionId,
                                            sessionId,
                                            message->content_as<Wazuh::SyncSchema::Start>(),
                                            *m_dataStore,
                                            *m_indexerQueue,
                                            *m_responseDispatcher);
            }
        }
        else if (message->content_type() == Wazuh::SyncSchema::MessageType_End)
        {
            const auto end = message->content_as<Wazuh::SyncSchema::End>();
            if (!end)
            {
                throw InventorySyncException("Invalid end message");
            }
            // Check if session exists.
            std::shared_lock lock(m_agentSessionsMutex);
            auto it = m_agentSessions.find(end->session());
            if (it == m_agentSessions.end())
            {
                throw InventorySyncException("Session not found");
            }

            // Handle end.
            logDebug2(LOGGER_INV_SYNC_TAG, "Handling end for session '%d'", end->session());
            it->second.handleEnd(*m_responseDispatcher);
        }
    }

public:
    /**
     * @brief Starts facade.
     *
     * @param logFunction Log function.
     * @param configuration Facade configuration.
     */
    void start(const std::function<void(const int,
                                        const std::string&,
                                        const std::string&,
                                        const int,
                                        const std::string&,
                                        const std::string&,
                                        va_list)>& logFunction,
               const nlohmann::json& /*configuration*/)
    {
        std::filesystem::remove_all(INVENTORY_SYNC_PATH);
        m_dataStore = std::make_unique<TRocksDBWrapper>(INVENTORY_SYNC_PATH);
        m_responseDispatcher = std::make_unique<TResponseDispatcher>();
        m_indexerConnector = std::make_unique<TIndexerConnector>(
            nlohmann::json::parse(R"({"hosts": ["localhost:9200"], "ssl": {"certificate_authorities": []}})"),
            logFunction);

        m_workersQueue = std::make_unique<WorkersQueue>(
            [this](const std::vector<char>& dataRaw)
            {
                try
                {
                    logDebug2(LOGGER_INV_SYNC_TAG, "Processing message %s", dataRaw.data());
                    flatbuffers::Verifier verifier(reinterpret_cast<const uint8_t*>(dataRaw.data()), dataRaw.size());
                    if (Wazuh::SyncSchema::VerifyMessageBuffer(verifier))
                    {
                        run(dataRaw);
                    }
                    else
                    {
                        throw InventorySyncException("Invalid message buffer");
                    }
                }
                catch (const std::exception& e)
                {
                    logError(LOGGER_INV_SYNC_TAG, "Failed to process message %s. Reason: %s", dataRaw.data(), e.what());
                }
            },
            std::thread::hardware_concurrency(),
            UNLIMITED_QUEUE_SIZE);

        m_inventorySubscription =
            std::make_unique<TRouterSubscriber>(INVENTORY_SYNC_TOPIC, INVENTORY_SYNC_SUBSCRIBER_ID);
        m_inventorySubscription->subscribe(
            // coverity[copy_constructor_call]
            [queue = m_workersQueue.get()](const std::vector<char>& message)
            {
                // TODO we need to add move capacity to the router module.
                auto copy = message;
                queue->push(std::move(copy));
            });

        const auto postIndexerAction = []()
        {
            std::cout << "post-indexer action...\n";
        };

        m_indexerQueue = std::make_unique<IndexerQueue>(
            [this, &postIndexerAction](const Response& res)
            {
                if (auto sessionIt = m_agentSessions.find(res.context->sessionId); sessionIt == m_agentSessions.end())
                {
                    logWarn(LOGGER_INV_SYNC_TAG,
                            "Unable to handle indexer message. Session number: '%d' not found",
                            res.context->sessionId);
                    return;
                }

                try
                {
                    // VD ?
                    postIndexerAction();

                    // Send delete by query to indexer if mode is full.
                    if (res.context->mode == Wazuh::SyncSchema::Mode_Full)
                    {
                        logDebug2(LOGGER_INV_SYNC_TAG,
                                  "Processing full sync for module '%s' on agent '%d' (Session '%d')",
                                  res.context->moduleName.c_str(),
                                  res.context->agentId,
                                  res.context->sessionId);
                        m_indexerConnector->deleteByQuery(res.context->moduleName,
                                                          std::to_string(res.context->agentId));
                    }

                    const auto prefix = std::to_string(res.context->sessionId) + "_";

                    // Lock indexer connector to avoid process with the timeout mechanism.
                    std::scoped_lock lock(m_indexerConnector->scopeLock());

                    // Send bulk query (with handling of 413 error).
                    for (const auto& [key, value] : m_dataStore->seek(prefix))
                    {
                        flatbuffers::Verifier verifier(reinterpret_cast<const uint8_t*>(value.data()), value.size());
                        if (Wazuh::SyncSchema::VerifyMessageBuffer(verifier))
                        {
                            auto message = Wazuh::SyncSchema::GetMessage(value.data());
                            auto data = message->content_as_Data();
                            if (data->operation() == Wazuh::SyncSchema::Operation_Upsert)
                            {
                                logDebug2(LOGGER_INV_SYNC_TAG,
                                          "Processing upsert sync for module '%s' on agent '%d' (Session '%d')",
                                          data->index()->string_view(),
                                          data->id()->string_view(),
                                          res.context->sessionId);
                                m_indexerConnector->bulkIndex(
                                    data->id()->string_view(),
                                    data->index()->string_view(),
                                    std::string_view((const char*)data->data()->data(), data->data()->size()));
                            }
                            else if (data->operation() == Wazuh::SyncSchema::Operation_Delete)
                            {
                                logDebug2(LOGGER_INV_SYNC_TAG,
                                          "Processing delete sync for module '%s' on agent '%d' (Session '%d')",
                                          data->index()->string_view(),
                                          data->id()->string_view(),
                                          res.context->sessionId);
                                m_indexerConnector->bulkDelete(data->index()->string_view(), data->id()->string_view());
                            }
                            else
                            {
                                throw InventorySyncException("Invalid operation");
                            }
                        }
                        else
                        {
                            throw InventorySyncException("Invalid message type");
                        }
                    }

                    // Register notify to be called when the indexer is flushed.
                    m_indexerConnector->registerNotify(
                        [this, ctx = res.context]()
                        {
                            // Send ACK to agent.
                            m_responseDispatcher->sendEndAck(Wazuh::SyncSchema::Status_Ok, ctx);
                            logDebug2(
                                LOGGER_INV_SYNC_TAG, "Successfully processed end for session '%d'", ctx->sessionId);
                            // Delete data from database.
                            m_dataStore->deleteByPrefix(std::to_string(ctx->sessionId));
                            // Delete Session.
                            if (m_agentSessions.erase(ctx->sessionId) == 0)
                            {
                                logWarn(LOGGER_INV_SYNC_TAG,
                                        "Unable to delete session in notify call. Session '%d' not found",
                                        ctx->sessionId);
                            }
                        });
                }
                catch (const InventorySyncException& e)
                {
                    logError(LOGGER_INV_SYNC_TAG,
                             "Unable to handle indexer instance due inventory error. Reason: %s",
                             e.what());
                    // Send ACK to agent.
                    m_responseDispatcher->sendEndAck(Wazuh::SyncSchema::Status_Error, res.context);
                    // Delete data from database.
                    m_dataStore->deleteByPrefix(std::to_string(res.context->sessionId));
                    // Delete Session.
                    if (m_agentSessions.erase(res.context->sessionId) == 0)
                    {
                        logWarn(LOGGER_INV_SYNC_TAG,
                                "Unable to delete session in inventory exception. Session '%d' not found",
                                res.context->sessionId);
                    }
                }
                catch (const std::exception& e)
                {
                    logError(LOGGER_INV_SYNC_TAG, "Unable to handle indexer message: %s", e.what());
                    // Send ACK to agent.
                    m_responseDispatcher->sendEndAck(Wazuh::SyncSchema::Status_Error, res.context);
                    // Delete data from database.
                    m_dataStore->deleteByPrefix(std::to_string(res.context->sessionId));
                    // Delete Session.
                    if (m_agentSessions.erase(res.context->sessionId) == 0)
                    {
                        logWarn(LOGGER_INV_SYNC_TAG,
                                "Unable to delete session in generic exception. Session '%d' not found",
                                res.context->sessionId);
                    }
                }
            },
            m_threadCount,
            UNLIMITED_QUEUE_SIZE);

        m_sessionTimeoutThread = std::thread(
            [this]()
            {
                std::unique_lock lock(m_sessionTimeoutMutex);
                while (!m_stopping.load())
                {
                    m_sessionTimeoutCv.wait(lock, [this]() { return m_stopping.load(); });

                    if (m_stopping.load())
                    {
                        break;
                    }

                    for (auto& [sessionId, session] : m_agentSessions)
                    {
                        if (!session.isAlive(std::chrono::seconds(10)))
                        {
                            logDebug2(LOGGER_INV_SYNC_TAG, "Session %d has timed out", sessionId);
                            m_agentSessions.erase(sessionId);
                        }
                    }
                }
            });

        logInfo(LOGGER_INV_SYNC_TAG, "InventorySyncFacade started.");
    }

    /**
     * @brief Stops facade.
     *
     */
    void stop()
    {
        logInfo(LOGGER_INV_SYNC_TAG, "Stopping InventorySync module");
        {
            std::lock_guard lock(m_sessionTimeoutMutex);
            m_stopping = true;
            m_sessionTimeoutCv.notify_all();
        }

        m_inventorySubscription.reset();
        m_workersQueue.reset();
        m_indexerQueue.reset();
        m_indexerConnector.reset();
        m_dataStore.reset();
    }

private:
    InventorySyncFacadeImpl() = default;
    std::shared_mutex m_agentSessionsMutex;
    std::mutex m_sessionTimeoutMutex;
    std::condition_variable m_sessionTimeoutCv;
    std::atomic<bool> m_stopping {false};
    std::unique_ptr<TRocksDBWrapper> m_dataStore;
    std::unique_ptr<TIndexerConnector> m_indexerConnector;
    std::unique_ptr<IndexerQueue> m_indexerQueue;
    std::unique_ptr<TResponseDispatcher> m_responseDispatcher;
    std::unique_ptr<WorkersQueue> m_workersQueue;
    std::unique_ptr<TRouterSubscriber> m_inventorySubscription;
    std::map<uint64_t, TAgentSession, std::less<>> m_agentSessions;
    std::thread m_sessionTimeoutThread;
};

using InventorySyncFacade = InventorySyncFacadeImpl<AgentSession,
                                                    ResponseDispatcher,
                                                    RouterSubscriber,
                                                    IndexerConnectorSync,
                                                    Utils::RocksDBWrapper>;

#endif // _INVENTORY_SYNC_FACADE_HPP
