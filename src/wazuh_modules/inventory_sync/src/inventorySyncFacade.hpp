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

            // Check if agent is locked
            std::string agentIdStr(agentId.data(), agentId.size());
            if (isAgentLocked(agentIdStr))
            {
                logDebug2(LOGGER_DEFAULT_TAG,
                          "InventorySyncFacade::start: Agent %s is locked, rejecting new session",
                          agentIdStr.c_str());
                m_responseDispatcher->sendStartAck(Wazuh::SyncSchema::Status_Error, agentId, -1, moduleName);
            }
            else if (!m_indexerConnector->isAvailable())
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

                    // CRITICAL: For metadata/groups operations, lock agent and wait for active sessions
                    // to prevent race conditions with concurrent inventory data
                    if (res.context->mode == Wazuh::SyncSchema::Mode_MetadataDelta ||
                        res.context->mode == Wazuh::SyncSchema::Mode_MetadataCheck ||
                        res.context->mode == Wazuh::SyncSchema::Mode_GroupDelta ||
                        res.context->mode == Wazuh::SyncSchema::Mode_GroupCheck)
                    {
                        // Lock the agent to reject new sessions during metadata/groups updates
                        lockAgent(res.context->agentId, "Metadata/groups update in progress");
                        res.context->ownsAgentLock = true;

                        // Flush any pending bulk operations FIRST to complete inventory sessions
                        // This processes accumulated bulk data and invokes callbacks, allowing sessions to complete
                        m_indexerConnector->flush();

                        // Wait for all OTHER active sessions of this agent to complete (max 60s)
                        // Note: We exclude the current session from the count since we're processing it
                        size_t remainingSessions = waitForAgentSessions(
                            res.context->agentId, std::chrono::seconds(60), res.context->sessionId);

                        if (remainingSessions > 0)
                        {
                            // Timeout: cannot proceed with metadata/groups update safely - agent will retry later
                            res.context->ownsAgentLock = false;
                            unlockAgent(res.context->agentId);

                            logDebug1(LOGGER_DEFAULT_TAG,
                                      "Metadata/groups update failed for agent %s: %zu session(s) still active after "
                                      "timeout. "
                                      "Agent will retry later.",
                                      res.context->agentId.c_str(),
                                      remainingSessions);

                            // Notify agent of failure and cleanup session
                            m_responseDispatcher->sendEndAck(Wazuh::SyncSchema::Status_Error,
                                                             res.context->agentId,
                                                             res.context->sessionId,
                                                             res.context->moduleName);

                            m_agentSessions.erase(res.context->sessionId);
                            return;
                        }

                        // All sessions completed - safe to proceed with metadata/groups update
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
                                // Unlock agent to allow new sessions after metadata update completes
                                ctx->ownsAgentLock = false;
                                unlockAgent(ctx->agentId);

                                // Send ACK to agent.
                                m_responseDispatcher->sendEndAck(
                                    Wazuh::SyncSchema::Status_Ok, ctx->agentId, ctx->sessionId, ctx->moduleName);
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
                                // Unlock agent to allow new sessions after groups update completes
                                ctx->ownsAgentLock = false;
                                unlockAgent(ctx->agentId);

                                // Send ACK to agent.
                                m_responseDispatcher->sendEndAck(
                                    Wazuh::SyncSchema::Status_Ok, ctx->agentId, ctx->sessionId, ctx->moduleName);
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
                    else if (res.context->mode == Wazuh::SyncSchema::Mode_MetadataCheck)
                    {
                        logDebug2(LOGGER_DEFAULT_TAG,
                                  "InventorySyncFacade::start: Disaster recovery - checking metadata for agent %s...",
                                  res.context->agentId.c_str());

                        // Register notify callback BEFORE starting async operation to avoid race condition
                        m_indexerConnector->registerNotify(
                            [this, ctx = res.context]()
                            {
                                // Unlock agent to allow new sessions after metadata check completes
                                ctx->ownsAgentLock = false;
                                unlockAgent(ctx->agentId);

                                // Send ACK to agent.
                                m_responseDispatcher->sendEndAck(
                                    Wazuh::SyncSchema::Status_Ok, ctx->agentId, ctx->sessionId, ctx->moduleName);
                                // Delete Session.
                                if (m_agentSessions.erase(ctx->sessionId) == 0)
                                {
                                    logDebug2(LOGGER_DEFAULT_TAG,
                                              "InventorySyncFacade::start: Session not found, sessionId: %llu",
                                              ctx->sessionId);
                                }
                            });

                        // Build the metadata check query - compares fields and only updates mismatches
                        auto metadataCheckQuery =
                            InventorySyncQueryBuilder::buildMetadataCheckQuery(res.context->agentId,
                                                                               res.context->agentName,
                                                                               res.context->agentVersion,
                                                                               res.context->architecture,
                                                                               res.context->hostname,
                                                                               res.context->osname,
                                                                               res.context->osplatform,
                                                                               res.context->ostype,
                                                                               res.context->osversion);

                        logInfo(LOGGER_DEFAULT_TAG,
                                "Disaster recovery: Checking and recovering metadata inconsistencies for agent %s "
                                "across %zu indices",
                                res.context->agentId.c_str(),
                                res.context->indices.size());

                        // Execute the metadata check update
                        m_indexerConnector->executeUpdateByQuery(res.context->indices, metadataCheckQuery);
                    }
                    else if (res.context->mode == Wazuh::SyncSchema::Mode_GroupCheck)
                    {
                        logDebug2(LOGGER_DEFAULT_TAG,
                                  "InventorySyncFacade::start: Disaster recovery - checking groups for agent %s...",
                                  res.context->agentId.c_str());

                        // Register notify callback BEFORE starting async operation to avoid race condition
                        m_indexerConnector->registerNotify(
                            [this, ctx = res.context]()
                            {
                                // Unlock agent to allow new sessions after groups check completes
                                ctx->ownsAgentLock = false;
                                unlockAgent(ctx->agentId);

                                // Send ACK to agent.
                                m_responseDispatcher->sendEndAck(
                                    Wazuh::SyncSchema::Status_Ok, ctx->agentId, ctx->sessionId, ctx->moduleName);
                                // Delete Session.
                                if (m_agentSessions.erase(ctx->sessionId) == 0)
                                {
                                    logDebug2(LOGGER_DEFAULT_TAG,
                                              "InventorySyncFacade::start: Session not found, sessionId: %llu",
                                              ctx->sessionId);
                                }
                            });

                        // Build the groups check query - compares groups and only updates mismatches
                        auto groupsCheckQuery =
                            InventorySyncQueryBuilder::buildGroupsCheckQuery(res.context->agentId, res.context->groups);

                        logInfo(LOGGER_DEFAULT_TAG,
                                "Disaster recovery: Checking and recovering groups inconsistencies for agent %s across "
                                "%zu indices",
                                res.context->agentId.c_str(),
                                res.context->indices.size());

                        // Execute the groups check update
                        m_indexerConnector->executeUpdateByQuery(res.context->indices, groupsCheckQuery);
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

                    // Unlock agent if this session owns the lock
                    if (res.context->ownsAgentLock)
                    {
                        res.context->ownsAgentLock = false;
                        unlockAgent(res.context->agentId);
                    }

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

                    // Unlock agent if this session owns the lock
                    if (res.context->ownsAgentLock)
                    {
                        res.context->ownsAgentLock = false;
                        unlockAgent(res.context->agentId);
                    }

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
                                  [this](const auto& pair)
                                  {
                                      if (!pair.second.isAlive(std::chrono::seconds(DEFAULT_TIME * 2)))
                                      {
                                          logDebug2(LOGGER_DEFAULT_TAG, "Session %llu has timed out", pair.first);

                                          // Unlock agent if this session owns the lock
                                          const auto& context = pair.second.getContext();
                                          if (context->ownsAgentLock)
                                          {
                                              unlockAgent(context->agentId);
                                              logDebug1(LOGGER_DEFAULT_TAG,
                                                        "Session %llu for agent %s timed out - agent unlocked",
                                                        pair.first,
                                                        context->agentId.c_str());
                                          }

                                          // Delete data from database.
                                          m_dataStore->deleteByPrefix(std::to_string(pair.first));
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
     * @brief Lock an agent to prevent new sessions from being created
     * @param agentId Agent ID to lock, or empty string to lock ALL agents
     * @param reason Reason for locking (for logging purposes)
     * @return true if locked successfully, false if already locked
     */
    bool lockAgent(const std::string& agentId, const std::string& reason = "")
    {
        std::unique_lock lock(m_blockedAgentsMutex);

        if (agentId.empty())
        {
            if (m_allAgentsLocked.load())
            {
                logDebug2(LOGGER_DEFAULT_TAG, "All agents already locked");
                return false;
            }
            m_allAgentsLocked.store(true);
            logInfo(LOGGER_DEFAULT_TAG,
                    "Locked ALL agents from creating new sessions%s%s",
                    reason.empty() ? "" : " - Reason: ",
                    reason.c_str());
            return true;
        }
        else
        {
            auto [it, inserted] = m_blockedAgents.insert(agentId);
            if (inserted)
            {
                logInfo(LOGGER_DEFAULT_TAG,
                        "Locked agent %s from creating new sessions%s%s",
                        agentId.c_str(),
                        reason.empty() ? "" : " - Reason: ",
                        reason.c_str());
            }
            else
            {
                logDebug2(LOGGER_DEFAULT_TAG, "Agent %s already locked", agentId.c_str());
            }
            return inserted;
        }
    }

    /**
     * @brief Unlock an agent to allow new sessions
     * @param agentId Agent ID to unlock, or empty string to unlock ALL agents
     */
    void unlockAgent(const std::string& agentId)
    {
        std::unique_lock lock(m_blockedAgentsMutex);

        if (agentId.empty())
        {
            m_allAgentsLocked.store(false);
            logInfo(LOGGER_DEFAULT_TAG, "Unlocked ALL agents for new sessions");
        }
        else
        {
            size_t erased = m_blockedAgents.erase(agentId);
            if (erased > 0)
            {
                logInfo(LOGGER_DEFAULT_TAG, "Unlocked agent %s for new sessions", agentId.c_str());
            }
            else
            {
                logDebug2(LOGGER_DEFAULT_TAG, "Agent %s was not locked", agentId.c_str());
            }
        }
    }

    /**
     * @brief Check if an agent is locked
     * @param agentId Agent ID to check
     * @return true if agent is locked (or all agents are locked)
     */
    bool isAgentLocked(const std::string& agentId) const
    {
        std::shared_lock lock(m_blockedAgentsMutex);
        return m_allAgentsLocked.load() || m_blockedAgents.contains(agentId);
    }

    /**
     * @brief Get count of active sessions for an agent
     * @param agentId Agent ID, or empty string for ALL agents
     * @param excludeSessionId Session ID to exclude from count (useful when counting other sessions)
     * @return Number of active sessions
     */
    size_t getActiveSessionCount(const std::string& agentId = "", uint64_t excludeSessionId = 0) const
    {
        std::shared_lock lock(m_agentSessionsMutex);

        if (agentId.empty())
        {
            return excludeSessionId == 0
                       ? m_agentSessions.size()
                       : m_agentSessions.size() - (m_agentSessions.contains(excludeSessionId) ? 1 : 0);
        }

        size_t count = 0;
        for (const auto& [sessionId, session] : m_agentSessions)
        {
            if (session.getContext()->agentId == agentId && sessionId != excludeSessionId)
            {
                ++count;
            }
        }
        return count;
    }

    /**
     * @brief Wait for all active sessions of an agent to complete
     * @param agentId Agent ID to wait for, or empty string for ALL agents
     * @param timeout Maximum time to wait
     * @param excludeSessionId Session ID to exclude from wait (e.g., the current session)
     * @return Number of sessions still active after wait (0 = success, >0 = timeout/failure)
     */
    size_t waitForAgentSessions(const std::string& agentId = "",
                                std::chrono::seconds timeout = std::chrono::seconds(60),
                                uint64_t excludeSessionId = 0)
    {
        const auto startTime = std::chrono::steady_clock::now();
        size_t initialCount = getActiveSessionCount(agentId, excludeSessionId);

        if (initialCount == 0)
        {
            logDebug2(LOGGER_DEFAULT_TAG, "No active sessions for agent %s", agentId.empty() ? "ALL" : agentId.c_str());
            return 0;
        }

        logInfo(LOGGER_DEFAULT_TAG,
                "Waiting for %zu active session(s) of agent %s to complete (timeout: %llds)",
                initialCount,
                agentId.empty() ? "ALL" : agentId.c_str(),
                timeout.count());

        while (true)
        {
            size_t currentCount = getActiveSessionCount(agentId, excludeSessionId);

            if (currentCount == 0)
            {
                auto elapsed =
                    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startTime);
                logInfo(LOGGER_DEFAULT_TAG,
                        "All %zu session(s) of agent %s completed after %lldms",
                        initialCount,
                        agentId.empty() ? "ALL" : agentId.c_str(),
                        elapsed.count());
                return 0; // Success - no sessions remaining
            }

            auto elapsed = std::chrono::steady_clock::now() - startTime;
            if (elapsed >= timeout)
            {
                logDebug1(LOGGER_DEFAULT_TAG,
                          "Timeout waiting for agent %s sessions to complete. %zu session(s) still active",
                          agentId.empty() ? "ALL" : agentId.c_str(),
                          currentCount);
                return currentCount; // Timeout - return number of remaining sessions
            }

            // Poll every 100ms
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    /**
     * @brief Stops facade.
     *
     */
    void stop()
    {
        logInfo(LOGGER_DEFAULT_TAG, "Stopping InventorySync module");

        // Lock all agents to reject new sessions during shutdown (don't wait for existing sessions)
        lockAgent("", "Module shutdown");

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
    mutable std::shared_mutex m_agentSessionsMutex;
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

    // Agent locking mechanism for metadata/groups updates
    std::unordered_set<std::string> m_blockedAgents; ///< Set of locked agent IDs
    mutable std::shared_mutex m_blockedAgentsMutex;  ///< Mutex for blocked agents set
    std::atomic<bool> m_allAgentsLocked {false};     ///< Global lock for all agents
};

using InventorySyncFacade = InventorySyncFacadeImpl<AgentSession,
                                                    ResponseDispatcher,
                                                    RouterSubscriber,
                                                    IndexerConnectorSync,
                                                    Utils::RocksDBWrapper>;

#endif // _INVENTORY_SYNC_FACADE_HPP
