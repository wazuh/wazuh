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

#ifndef _INVENTORY_SYNC_FACADE_HPP
#define _INVENTORY_SYNC_FACADE_HPP

#include "agentSession.hpp"
#include "flatbuffers/include/inventorySync_generated.h"
#include "inventorySyncQueryBuilder.hpp"
#include "keyStore.hpp"
#include "loggerHelper.h"
#include "routerSubscriber.hpp"
#include "singleton.hpp"
#include "socketServer.hpp"
#include "stringHelper.h"
#include <asyncValueDispatcher.hpp>
#include <filesystem>
#include <format>
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
constexpr int DEFAULT_TIME {60 * 10}; // 10 minutes
constexpr auto INVENTORY_SYNC_PATH {"inventory_sync"};
constexpr auto INVENTORY_SYNC_TOPIC {"inventory-states"};
constexpr auto INVENTORY_SYNC_SUBSCRIBER_ID {"inventory-sync-module"};
constexpr auto SOCKET_KEYSTORE_PATH {"/var/ossec/queue/sockets/keystore"};

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
        auto syncMessage = Wazuh::SyncSchema::GetMessage(dataRaw.data());

        if (syncMessage->content_type() == Wazuh::SyncSchema::MessageType_DataValue)
        {
            const auto data = syncMessage->content_as<Wazuh::SyncSchema::DataValue>();
            if (!data)
            {
                throw InventorySyncException("Invalid data message");
            }

            // Check if session exists.
            std::shared_lock lock(m_agentSessionsMutex);
            if (auto it = m_agentSessions.find(data->session()); it == m_agentSessions.end())
            {
                logDebug2(LOGGER_DEFAULT_TAG,
                          "InventorySyncFacade::start: Session not found, sessionId: %llu",
                          data->session());
            }
            else
            {
                // Handle data - pass the raw flatbuffer bytes directly
                it->second.handleData(data, reinterpret_cast<const uint8_t*>(dataRaw.data()), dataRaw.size());
                logDebug2(
                    LOGGER_DEFAULT_TAG, "InventorySyncFacade::start: Data handled for session %llu", data->session());
            }
        }
        else if (syncMessage->content_type() == Wazuh::SyncSchema::MessageType_Start)
        {
            const auto startMsg = syncMessage->content_as<Wazuh::SyncSchema::Start>();
            if (!startMsg)
            {
                throw InventorySyncException("Invalid start message");
            }

            // Extract agent ID and module name from Start message
            auto agentId = startMsg->agentid() ? startMsg->agentid()->string_view() : std::string_view();
            auto moduleName = startMsg->module_() ? startMsg->module_()->string_view() : std::string_view();

            if (!m_indexerConnector->isAvailable())
            {
                logDebug2(LOGGER_DEFAULT_TAG, "InventorySyncFacade::start: No available server");
                m_responseDispatcher->sendStartAck(Wazuh::SyncSchema::Status_Offline, agentId, -1, moduleName);
            }
            else
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

                    // AgentSession will extract all info (including module) from Start message
                    m_agentSessions.try_emplace(
                        sessionId, sessionId, startMsg, *m_dataStore, *m_indexerQueue, *m_responseDispatcher);
                    logDebug2(LOGGER_DEFAULT_TAG, "InventorySyncFacade::start: Session created %llu", sessionId);
                }
            }
        }
        else if (syncMessage->content_type() == Wazuh::SyncSchema::MessageType_End)
        {
            const auto end = syncMessage->content_as<Wazuh::SyncSchema::End>();
            if (!end)
            {
                throw InventorySyncException("Invalid end message");
            }

            // Check if session exists.
            std::shared_lock lock(m_agentSessionsMutex);
            if (auto it = m_agentSessions.find(end->session()); it == m_agentSessions.end())
            {
                logDebug2(LOGGER_DEFAULT_TAG,
                          "InventorySyncFacade::start: Session not found, sessionId: %llu",
                          end->session());
            }
            else
            {
                // Handle end.
                it->second.handleEnd(*m_responseDispatcher);
                logDebug2(
                    LOGGER_DEFAULT_TAG, "InventorySyncFacade::start: End handled for session %llu", end->session());
            }
        }
        else
        {
            throw InventorySyncException("Invalid message type");
        }
    }

    void initializeKeystoreSocket()
    {
        m_keystoreSocketServer = std::make_unique<SocketServer<Socket<OSPrimitives, SizeHeaderProtocol>, EpollWrapper>>(
            SOCKET_KEYSTORE_PATH);

        m_keystoreSocketServer->listen(
            [keystoreServer = m_keystoreSocketServer.get()](
                const int fd, const char* body, const uint32_t bodySize, const char*, const uint32_t)
            {
                std::string_view queryView(body, bodySize);
                nlohmann::json result;

                try
                {
                    size_t pos1 = queryView.find('|');
                    size_t pos2 = queryView.find('|', pos1 + 1);
                    size_t pos3 = queryView.find('|', pos2 + 1);

                    if (pos1 == std::string_view::npos || pos2 == std::string_view::npos)
                    {
                        throw std::runtime_error("Invalid query format");
                    }

                    auto queryOp = queryView.substr(0, pos1);
                    auto queryCf = queryView.substr(pos1 + 1, pos2 - pos1 - 1);
                    auto key = (pos3 == std::string_view::npos) ? queryView.substr(pos2 + 1)
                                                                : queryView.substr(pos2 + 1, pos3 - pos2 - 1);
                    auto val = (pos3 == std::string_view::npos) ? std::string_view() : queryView.substr(pos3 + 1);

                    if (queryOp == "GET")
                    {
                        std::string value;
                        Keystore::get(std::string(queryCf), std::string(key), value);
                        result["status"] = "ok";
                        result["operation"] = "get";
                        result["columnFamily"] = queryCf;
                        result["key"] = key;
                        result["value"] = value;
                    }
                    else if (queryOp == "PUT")
                    {
                        Keystore::put(std::string(queryCf), std::string(key), std::string(val));
                        result["status"] = "ok";
                        result["operation"] = "put";
                        result["columnFamily"] = queryCf;
                        result["key"] = key;
                    }
                    else if (queryOp == "DELETE")
                    {
                        Keystore::put(std::string(queryCf), std::string(key), "");
                        result["status"] = "ok";
                        result["operation"] = "delete";
                        result["columnFamily"] = queryCf;
                        result["key"] = key;
                    }
                    else
                    {
                        result["status"] = "error";
                        result["message"] = "Unknown operation";
                    }
                }
                catch (const std::exception& e)
                {
                    result["status"] = "error";
                    result["message"] = e.what();
                }

                auto response = result.dump();
                keystoreServer->send(fd, response.c_str(), response.size());
            });
    }

public:
    /**
     * @brief Starts facade.
     *
     * @param logFunction Log function.
     * @param configuration Facade configuration.
     */
    void
    start(const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
              logFunction,
          const nlohmann::json& configuration)
    {
        Log::assignLogFunction(logFunction);

        std::error_code errorCodeFS;
        std::filesystem::remove_all(INVENTORY_SYNC_PATH, errorCodeFS);
        if (errorCodeFS)
        {
            logWarn(LOGGER_DEFAULT_TAG, "Error removing inventory_sync directory: %s", errorCodeFS.message().c_str());
        }
        m_dataStore = std::make_unique<TRocksDBWrapper>(INVENTORY_SYNC_PATH);
        m_responseDispatcher = std::make_unique<TResponseDispatcher>();

        logDebug2(LOGGER_DEFAULT_TAG, "Configuration: %s", configuration.dump().c_str());
        m_indexerConnector = std::make_unique<TIndexerConnector>(configuration.at("indexer"), logFunction);

        if (!configuration.contains("clusterName"))
        {
            throw InventorySyncException("clusterName not found in configuration");
        }

        m_clusterName = Utils::toLowerCase(configuration.at("clusterName").get_ref<const std::string&>());

        logDebug2(LOGGER_DEFAULT_TAG, "Cluster name to be used in indexer: %s", m_clusterName.c_str());

        m_workersQueue = std::make_unique<WorkersQueue>(
            [this](const std::vector<char>& dataRaw)
            {
                try
                {
                    flatbuffers::Verifier verifier(reinterpret_cast<const uint8_t*>(dataRaw.data()), dataRaw.size());
                    if (Wazuh::SyncSchema::VerifyMessageBuffer(verifier))
                    {
                        logDebug2(LOGGER_DEFAULT_TAG, "InventorySyncFacade::start: Processing message...");
                        run(dataRaw);
                    }
                    else
                    {
                        throw InventorySyncException("Invalid message buffer");
                    }
                }
                catch (const std::exception& e)
                {
                    logError(LOGGER_DEFAULT_TAG, "InventorySyncFacade::start: %s", e.what());
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
                logDebug2(LOGGER_DEFAULT_TAG, "InventorySyncFacade::start: Received message from router");
                // TODO: Temporal allocation, we need to use move semantics in router module.
                queue->push(std::move(const_cast<std::vector<char>&>(message)));
            });

        const auto preIndexerAction = []()
        {
            logDebug2(LOGGER_DEFAULT_TAG, "Pre-indexer action...");
        };

        m_indexerQueue = std::make_unique<IndexerQueue>(
            [this, &preIndexerAction](const Response& res)
            {
                logDebug2(LOGGER_DEFAULT_TAG, "Indexer queue action...");
                if (auto sessionIt = m_agentSessions.find(res.context->sessionId); sessionIt == m_agentSessions.end())
                {
                    logError(LOGGER_DEFAULT_TAG,
                             "InventorySyncFacade::start: Session not found, sessionId: %llu",
                             res.context->sessionId);
                    return;
                }

                try
                {
                    // VD ?
                    preIndexerAction();

                    // CRITICAL: Flush any pending bulk operations BEFORE metadata/groups updates
                    // to ensure we don't insert documents with old data after the update
                    if (res.context->mode == Wazuh::SyncSchema::Mode_MetadataDelta ||
                        res.context->mode == Wazuh::SyncSchema::Mode_GroupDelta)
                    {
                        m_indexerConnector->flush();
                    }

                    // Lock indexer connector to avoid process with the timeout mechanism.
                    auto lock = m_indexerConnector->scopeLock();

                    if (res.context->mode == Wazuh::SyncSchema::Mode_MetadataDelta)
                    {
                        logDebug2(LOGGER_DEFAULT_TAG,
                                  "InventorySyncFacade::start: Updating agent metadata for agent %s...",
                                  res.context->agentId.c_str());

                        // Register notify callback BEFORE starting async operation to avoid race condition
                        m_indexerConnector->registerNotify(
                            [this, ctx = res.context]()
                            {
                                // Send ACK to agent.
                                m_responseDispatcher->sendEndAck(
                                    Wazuh::SyncSchema::Status_Ok, ctx->agentId, ctx->sessionId, ctx->moduleName);
                                // Delete data from database.
                                m_dataStore->deleteByPrefix(std::to_string(ctx->sessionId));
                                // Delete Session.
                                if (m_agentSessions.erase(ctx->sessionId) == 0)
                                {
                                    logDebug2(LOGGER_DEFAULT_TAG,
                                              "InventorySyncFacade::start: Session not found, sessionId: %llu",
                                              ctx->sessionId);
                                }
                            });

                        // Build the metadata update query using domain logic
                        auto metadataQuery =
                            InventorySyncQueryBuilder::buildMetadataUpdateQuery(res.context->agentId,
                                                                                res.context->agentName,
                                                                                res.context->agentVersion,
                                                                                res.context->architecture,
                                                                                res.context->hostname,
                                                                                res.context->osname,
                                                                                res.context->osplatform,
                                                                                res.context->ostype,
                                                                                res.context->osversion,
                                                                                res.context->globalVersion);

                        // Execute the update using generic infrastructure method
                        m_indexerConnector->executeUpdateByQuery(res.context->indices, metadataQuery);
                    }
                    else if (res.context->mode == Wazuh::SyncSchema::Mode_GroupDelta)
                    {
                        logDebug2(LOGGER_DEFAULT_TAG,
                                  "InventorySyncFacade::start: Updating agent groups for agent %s...",
                                  res.context->agentId.c_str());

                        // Register notify callback BEFORE starting async operation to avoid race condition
                        m_indexerConnector->registerNotify(
                            [this, ctx = res.context]()
                            {
                                // Send ACK to agent.
                                m_responseDispatcher->sendEndAck(
                                    Wazuh::SyncSchema::Status_Ok, ctx->agentId, ctx->sessionId, ctx->moduleName);
                                // Delete data from database.
                                m_dataStore->deleteByPrefix(std::to_string(ctx->sessionId));
                                // Delete Session.
                                if (m_agentSessions.erase(ctx->sessionId) == 0)
                                {
                                    logDebug2(LOGGER_DEFAULT_TAG,
                                              "InventorySyncFacade::start: Session not found, sessionId: %llu",
                                              ctx->sessionId);
                                }
                            });

                        // Build the groups update query using domain logic
                        auto groupsQuery = InventorySyncQueryBuilder::buildGroupsUpdateQuery(
                            res.context->agentId, res.context->groups, res.context->globalVersion);

                        // Execute the update using generic infrastructure method
                        m_indexerConnector->executeUpdateByQuery(res.context->indices, groupsQuery);
                    }
                    else
                    {
                        // Send delete by query to indexer if mode is full.
                        if (res.context->mode == Wazuh::SyncSchema::Mode_ModuleFull)
                        {
                            logDebug2(LOGGER_DEFAULT_TAG,
                                      "InventorySyncFacade::start: Deleting by query for %zu indices...",
                                      res.context->indices.size());
                            // Delete from all indices specified in the Start message
                            for (const auto& index : res.context->indices)
                            {
                                m_indexerConnector->deleteByQuery(index, res.context->agentId);
                            }
                        }

                        const auto prefix = std::format("{}_", res.context->sessionId);

                        // Send bulk query (with handling of 413 error).
                        for (const auto& [key, value] : m_dataStore->seek(prefix))
                        {
                            logDebug2(LOGGER_DEFAULT_TAG, "InventorySyncFacade::start: Processing data...");
                            flatbuffers::Verifier verifier(reinterpret_cast<const uint8_t*>(value.data()),
                                                           value.size());
                            if (Wazuh::SyncSchema::VerifyMessageBuffer(verifier))
                            {
                                auto message = Wazuh::SyncSchema::GetMessage(value.data());
                                auto data = message->content_as_DataValue();
                                if (!data)
                                {
                                    throw InventorySyncException("Invalid data message");
                                }

                                thread_local std::string elementId;
                                elementId.clear();

                                elementId.append(m_clusterName);
                                elementId.append("_");
                                elementId.append(res.context->agentId);
                                elementId.append("_");
                                elementId.append(data->id()->string_view());

                                if (data->operation() == Wazuh::SyncSchema::Operation_Upsert)
                                {
                                    logDebug2(LOGGER_DEFAULT_TAG, "InventorySyncFacade::start: Upserting data...");
                                    thread_local std::string dataString;
                                    dataString.clear();
                                    dataString.append(R"({"agent":{"id":")");
                                    dataString.append(res.context->agentId);
                                    dataString.append(R"(","name":")");
                                    dataString.append(res.context->agentName);
                                    dataString.append(R"(","version":")");
                                    dataString.append(res.context->agentVersion);
                                    dataString.append(R"(","groups":[)");
                                    bool firstGroup = true;
                                    for (const auto& group : res.context->groups)
                                    {
                                        if (!firstGroup)
                                        {
                                            dataString.append(",");
                                        }
                                        dataString.append(R"(")");
                                        dataString.append(group);
                                        dataString.append(R"(")");
                                        firstGroup = false;
                                    }
                                    dataString.append(R"(],"host":{"architecture":")");
                                    dataString.append(res.context->architecture);
                                    dataString.append(R"(","hostname":")");
                                    dataString.append(res.context->hostname);
                                    dataString.append(R"(","os":{"name":")");
                                    dataString.append(res.context->osname);
                                    dataString.append(R"(","platform":")");
                                    dataString.append(res.context->osplatform);
                                    dataString.append(R"(","type":")");
                                    dataString.append(res.context->ostype);
                                    dataString.append(R"(","version":")");
                                    dataString.append(res.context->osversion);
                                    dataString.append(R"("}}},"wazuh":{"cluster":{"name":")");
                                    dataString.append(m_clusterName);
                                    dataString.append(R"("}},)");
                                    dataString.append(std::string_view((const char*)data->data()->data() + 1,
                                                                       data->data()->size() - 1));
                                    const auto version = data->version();
                                    const auto indexName = data->index()->string_view();
                                    if (version && version > 0)
                                    {
                                        m_indexerConnector->bulkIndex(
                                            elementId, indexName, dataString, std::to_string(version));
                                    }
                                    else
                                    {
                                        m_indexerConnector->bulkIndex(elementId, indexName, dataString);
                                    }
                                }
                                else if (data->operation() == Wazuh::SyncSchema::Operation_Delete)
                                {
                                    logDebug2(LOGGER_DEFAULT_TAG, "InventorySyncFacade::start: Deleting data...");
                                    m_indexerConnector->bulkDelete(elementId, data->index()->string_view());
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

                        // Register notify callback for bulk operations (after accumulating all data)
                        m_indexerConnector->registerNotify(
                            [this, ctx = res.context]()
                            {
                                // Send ACK to agent.
                                m_responseDispatcher->sendEndAck(
                                    Wazuh::SyncSchema::Status_Ok, ctx->agentId, ctx->sessionId, ctx->moduleName);
                                // Delete data from database.
                                m_dataStore->deleteByPrefix(std::to_string(ctx->sessionId));
                                // Delete Session.
                                if (m_agentSessions.erase(ctx->sessionId) == 0)
                                {
                                    logDebug2(LOGGER_DEFAULT_TAG,
                                              "InventorySyncFacade::start: Session not found, sessionId: %llu",
                                              ctx->sessionId);
                                }
                            });
                    } // End of else block for non-MetadataDelta/GroupDelta modes
                }
                catch (const InventorySyncException& e)
                {
                    logError(LOGGER_DEFAULT_TAG, "InventorySyncFacade::start: %s", e.what());
                    // Send ACK to agent.
                    m_responseDispatcher->sendEndAck(Wazuh::SyncSchema::Status_Error,
                                                     res.context->agentId,
                                                     res.context->sessionId,
                                                     res.context->moduleName);
                    // Delete data from database.
                    m_dataStore->deleteByPrefix(std::to_string(res.context->sessionId));
                    // Delete Session.
                    if (m_agentSessions.erase(res.context->sessionId) == 0)
                    {
                        logDebug2(LOGGER_DEFAULT_TAG,
                                  "InventorySyncFacade::start: Session not found, sessionId: %llu",
                                  res.context->sessionId);
                    }
                }
                catch (const std::exception& e)
                {
                    logError(LOGGER_DEFAULT_TAG, "InventorySyncFacade::start: %s", e.what());
                    // Send ACK to agent.
                    m_responseDispatcher->sendEndAck(Wazuh::SyncSchema::Status_Error,
                                                     res.context->agentId,
                                                     res.context->sessionId,
                                                     res.context->moduleName);
                    // Delete data from database.
                    m_dataStore->deleteByPrefix(std::to_string(res.context->sessionId));
                    // Delete Session.
                    if (m_agentSessions.erase(res.context->sessionId) == 0)
                    {
                        logDebug2(LOGGER_DEFAULT_TAG,
                                  "InventorySyncFacade::start: Session not found, sessionId: %llu",
                                  res.context->sessionId);
                    }
                }
            },
            m_threadCount,
            UNLIMITED_QUEUE_SIZE);

        m_sessionTimeoutThread = std::thread(
            [this]()
            {
                while (!m_stopping.load())
                {
                    std::unique_lock lock(m_sessionTimeoutMutex);
                    m_sessionTimeoutCv.wait_for(
                        lock, std::chrono::seconds(DEFAULT_TIME), [this]() { return m_stopping.load(); });

                    if (m_stopping.load())
                    {
                        break;
                    }

                    std::erase_if(m_agentSessions,
                                  [](const auto& pair)
                                  {
                                      if (!pair.second.isAlive(std::chrono::seconds(DEFAULT_TIME * 2)))
                                      {
                                          logDebug2(LOGGER_DEFAULT_TAG, "Session %llu has timed out", pair.first);
                                          return true;
                                      }
                                      return false;
                                  });
                }
            });

        // Init the socket server to attend keystore requests
        initializeKeystoreSocket();

        logInfo(LOGGER_DEFAULT_TAG, "InventorySyncFacade started.");
    }

    /**
     * @brief Stops facade.
     *
     */
    void stop()
    {
        logInfo(LOGGER_DEFAULT_TAG, "Stopping InventorySync module");
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
        m_keystoreSocketServer.reset();
    }

private:
    InventorySyncFacadeImpl() = default;
    std::string m_clusterName;
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
    std::unique_ptr<SocketServer<Socket<OSPrimitives, SizeHeaderProtocol>, EpollWrapper>> m_keystoreSocketServer;
};

using InventorySyncFacade = InventorySyncFacadeImpl<AgentSession,
                                                    ResponseDispatcher,
                                                    RouterSubscriber,
                                                    IndexerConnectorSync,
                                                    Utils::RocksDBWrapper>;

#endif // _INVENTORY_SYNC_FACADE_HPP
