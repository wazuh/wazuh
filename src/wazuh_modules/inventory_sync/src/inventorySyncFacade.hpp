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
#include "hashHelper.h"
#include "inventorySyncQueryBuilder.hpp"
#include "keyStore.hpp"
#include "loggerHelper.h"
#include "routerSubscriber.hpp"
#include "singleton.hpp"
#include "socketServer.hpp"
#include "stringHelper.h"
#include "vulnerabilityScannerFacade.hpp"
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
constexpr auto INVENTORY_SYNC_PATH {"queue/inventory_sync"};
constexpr auto INVENTORY_SYNC_TOPIC {"inventory-states"};
constexpr auto INVENTORY_SYNC_SUBSCRIBER_ID {"inventory-sync-module"};
constexpr auto WAZUH_STATES_INDEX_PATTERN {"wazuh-states-*"};
constexpr auto SOCKET_KEYSTORE_PATH {"queue/sockets/keystore"};

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
        // Check if message is JSON (starts with '{')
        if (!dataRaw.empty() && dataRaw[0] == '{')
        {
            try
            {
                std::string jsonStr(dataRaw.data(), dataRaw.size());
                auto jsonMsg = nlohmann::json::parse(jsonStr);

                if (jsonMsg.contains("command") && jsonMsg["command"] == "delete_agent")
                {
                    if (jsonMsg.contains("agent_id") && jsonMsg["agent_id"].is_string())
                    {
                        std::string agentId = jsonMsg["agent_id"];
                        deleteAgent(agentId);
                    }
                    else
                    {
                        logError(LOGGER_DEFAULT_TAG, "Invalid delete_agent message: missing agent_id");
                    }
                    return;
                }
            }
            catch (const std::exception& e)
            {
                logError(LOGGER_DEFAULT_TAG, "Failed to parse JSON message: %s", e.what());
                return;
            }
        }

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
        else if (syncMessage->content_type() == Wazuh::SyncSchema::MessageType_DataClean)
        {
            const auto dataClean = syncMessage->content_as<Wazuh::SyncSchema::DataClean>();
            if (!dataClean)
            {
                throw InventorySyncException("Invalid data clean message");
            }

            // Check if session exists.
            std::shared_lock lock(m_agentSessionsMutex);
            if (auto it = m_agentSessions.find(dataClean->session()); it == m_agentSessions.end())
            {
                logDebug2(LOGGER_DEFAULT_TAG,
                          "InventorySyncFacade::start: Session not found for DataClean, sessionId: %llu",
                          dataClean->session());
            }
            else
            {
                // Handle DataClean - stores index and tracks seq number
                it->second.handleDataClean(dataClean);
                logDebug2(LOGGER_DEFAULT_TAG,
                          "InventorySyncFacade::start: DataClean handled for session %llu",
                          dataClean->session());
            }
        }
        else if (syncMessage->content_type() == Wazuh::SyncSchema::MessageType_DataContext)
        {
            const auto dataContext = syncMessage->content_as<Wazuh::SyncSchema::DataContext>();
            if (!dataContext)
            {
                throw InventorySyncException("Invalid data context message");
            }

            // Check if session exists.
            std::shared_lock lock(m_agentSessionsMutex);
            if (auto it = m_agentSessions.find(dataContext->session()); it == m_agentSessions.end())
            {
                logDebug2(LOGGER_DEFAULT_TAG,
                          "InventorySyncFacade::start: Session not found for DataContext, sessionId: %llu",
                          dataContext->session());
            }
            else
            {
                // Handle DataContext - stores context in RocksDB and tracks seq number
                it->second.handleDataContext(
                    dataContext, reinterpret_cast<const uint8_t*>(dataRaw.data()), dataRaw.size());
                logDebug2(LOGGER_DEFAULT_TAG,
                          "InventorySyncFacade::start: DataContext handled for session %llu",
                          dataContext->session());
            }
        }
        else if (syncMessage->content_type() == Wazuh::SyncSchema::MessageType_DataBatch)
        {
            const auto dataBatch = syncMessage->content_as<Wazuh::SyncSchema::DataBatch>();
            if (!dataBatch || !dataBatch->values())
            {
                throw InventorySyncException("Invalid data batch message");
            }

            logDebug2(LOGGER_DEFAULT_TAG,
                      "InventorySyncFacade::start: Received DataBatch with %zu DataValues.",
                      dataBatch->values()->size());

            std::shared_lock lock(m_agentSessionsMutex);
            for (const auto* dataValue : *dataBatch->values())
            {
                if (!dataValue)
                {
                    continue;
                }

                if (auto it = m_agentSessions.find(dataValue->session()); it == m_agentSessions.end())
                {
                    logDebug2(LOGGER_DEFAULT_TAG,
                              "InventorySyncFacade::start: Session not found, sessionId: %llu",
                              dataValue->session());
                }
                else
                {
                    try
                    {
                        // Re-serialize each DataValue as a standalone Message{DataValue} FlatBuffer.
                        // RocksDB consumers (indexer) expect individual DataValue messages per key.
                        flatbuffers::FlatBufferBuilder dvBuilder;
                        const auto* idRaw = dataValue->id();
                        const auto* idxRaw = dataValue->index();
                        const auto* dataRaw = dataValue->data();
                        auto idStr = dvBuilder.CreateString(idRaw ? idRaw->string_view() : std::string_view {});
                        auto idxStr = dvBuilder.CreateString(idxRaw ? idxRaw->string_view() : std::string_view {});
                        auto dataVec = dataRaw ? dvBuilder.CreateVector(dataRaw->data(), dataRaw->size())
                                               : dvBuilder.CreateVector<int8_t>({});

                        Wazuh::SyncSchema::DataValueBuilder dataValueBuilder(dvBuilder);
                        dataValueBuilder.add_seq(dataValue->seq());
                        dataValueBuilder.add_session(dataValue->session());
                        dataValueBuilder.add_id(idStr);
                        dataValueBuilder.add_index(idxStr);
                        dataValueBuilder.add_version(dataValue->version());
                        dataValueBuilder.add_operation(dataValue->operation());
                        dataValueBuilder.add_data(dataVec);
                        auto dvOffset = dataValueBuilder.Finish();

                        auto msgOffset = Wazuh::SyncSchema::CreateMessage(
                            dvBuilder, Wazuh::SyncSchema::MessageType_DataValue, dvOffset.Union());
                        dvBuilder.Finish(msgOffset);

                        it->second.handleData(dataValue, dvBuilder.GetBufferPointer(), dvBuilder.GetSize());
                        logDebug2(LOGGER_DEFAULT_TAG,
                                  "InventorySyncFacade::start: DataBatch item handled for session %llu",
                                  dataValue->session());
                    }
                    catch (const std::exception& e)
                    {
                        logError(LOGGER_DEFAULT_TAG,
                                 "InventorySyncFacade::start: DataBatch item failed for session %llu, seq %llu: %s",
                                 dataValue->session(),
                                 dataValue->seq(),
                                 e.what());
                    }
                }
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

            // Check if agent is locked.
            // syscollector_vd sessions (VDFirst/VDSync) are exempt from the feed-update lock:
            // they read package data from their RocksDB session store, not from the OpenSearch
            // package index, so they cannot produce dirty reads during a feed-update full scan.
            // Per-agent serialisation with the feed-update scan is handled by the wait in
            // hasActiveSessionForModule instead.
            std::string agentIdStr(agentId.data(), agentId.size());
            const std::string moduleNameStr(moduleName.data(), moduleName.size());
            const bool isVDModule = (moduleNameStr == "syscollector_vd");
            if (!isVDModule && isAgentLocked(agentIdStr))
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
                // Check session limit before creating new session
                std::unique_lock lock(m_agentSessionsMutex);

                // Clean up any stale session for this agent+module combination
                // This handles agent restart or modulesd restart scenarios
                cleanupStaleSessionForAgentModule(std::string(agentId), std::string(moduleName));

                if (m_agentSessions.size() >= static_cast<size_t>(m_maxSessions))
                {
                    logWarn(LOGGER_DEFAULT_TAG,
                            "InventorySyncFacade::start: Session limit reached (%zu/%d active sessions). "
                            "Rejecting new session for agent %s - agent will retry later",
                            m_agentSessions.size(),
                            m_maxSessions,
                            std::string(agentId).c_str());
                    m_responseDispatcher->sendStartAck(Wazuh::SyncSchema::Status_Offline, agentId, -1, moduleName);
                }
                else
                {
                    // Generate random number for session ID.
                    std::random_device rd;
                    std::mt19937 gen(rd());
                    std::uniform_int_distribution<uint64_t> dis(0, UINT64_MAX);
                    const auto sessionId = dis(gen);

                    // Check if session already exists.
                    if (m_agentSessions.contains(sessionId))
                    {
                        throw InventorySyncException("Session already exists");
                    }

                    // AgentSession will extract all info (including module) from Start message
                    m_agentSessions.try_emplace(
                        sessionId, sessionId, startMsg, *m_dataStore, *m_indexerQueue, *m_responseDispatcher);
                    logDebug2(LOGGER_DEFAULT_TAG, "InventorySyncFacade::start: Session created %llu", sessionId);

                    if (startMsg->option() == Wazuh::SyncSchema::Option_VDSync ||
                        startMsg->option() == Wazuh::SyncSchema::Option_VDFirst)
                    {
                        const char* optStr =
                            startMsg->option() == Wazuh::SyncSchema::Option_VDSync ? "VDSync" : "VDFirst";
                        const char* modeStr = [&]() -> const char*
                        {
                            switch (startMsg->mode())
                            {
                                case Wazuh::SyncSchema::Mode_ModuleFull:  return "ModuleFull";
                                case Wazuh::SyncSchema::Mode_ModuleDelta: return "ModuleDelta";
                                default:                                   return "Other";
                            }
                        }();
                        logWarn(LOGGER_DEFAULT_TAG,
                                "[VDSYNC] Session CREATED: agent=%s module=%s option=%s mode=%s "
                                "size=%llu sessionId=%llu — Start ACK (Status_Ok) sent to agent.",
                                agentIdStr.c_str(),
                                moduleNameStr.c_str(),
                                optStr,
                                modeStr,
                                static_cast<unsigned long long>(startMsg->size()),
                                sessionId);
                    }
                }
            }
        }
        else if (syncMessage->content_type() == Wazuh::SyncSchema::MessageType_ChecksumModule)
        {
            const auto checksumModule = syncMessage->content_as<Wazuh::SyncSchema::ChecksumModule>();
            if (!checksumModule)
            {
                throw InventorySyncException("Invalid checksum module message");
            }

            // Check if session exists.
            std::shared_lock lock(m_agentSessionsMutex);
            if (auto it = m_agentSessions.find(checksumModule->session()); it == m_agentSessions.end())
            {
                logDebug2(LOGGER_DEFAULT_TAG,
                          "InventorySyncFacade::start: Session not found, sessionId: %llu",
                          checksumModule->session());
            }
            else
            {
                // Handle checksum module.
                it->second.handleChecksumModule(checksumModule);
                logDebug2(LOGGER_DEFAULT_TAG,
                          "InventorySyncFacade::start: ChecksumModule handled for session %llu",
                          checksumModule->session());
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
                const auto& ctx = it->second.getContext();
                if (ctx->option == Wazuh::SyncSchema::Option_VDSync ||
                    ctx->option == Wazuh::SyncSchema::Option_VDFirst)
                {
                    logWarn(LOGGER_DEFAULT_TAG,
                            "[VDSYNC] End message RECEIVED: agent=%s sessionId=%llu option=%s — "
                            "agent finished sending all packages; session queued for indexing "
                            "(Status_Processing sent to agent).",
                            ctx->agentId.c_str(),
                            ctx->sessionId,
                            ctx->option == Wazuh::SyncSchema::Option_VDSync ? "VDSync" : "VDFirst");
                }
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

    std::string calculateChecksumOfChecksums(const std::string& index, const std::string& agentId)
    {
        std::string concatenatedChecksums;
        std::string searchAfter;
        constexpr size_t BATCH_SIZE = 1000;
        size_t totalDocs = 0;

        logDebug2(
            LOGGER_DEFAULT_TAG, "Querying indexer for checksums: agent=%s, index=%s", agentId.c_str(), index.c_str());

        while (true)
        {
            nlohmann::json searchQuery;
            searchQuery["query"]["term"]["wazuh.agent.id"] = agentId;
            searchQuery["_source"] = nlohmann::json::array({"checksum.hash.sha1"});
            searchQuery["sort"] = nlohmann::json::array({nlohmann::json::object({{"checksum.hash.sha1", "asc"}})});
            searchQuery["size"] = BATCH_SIZE;

            if (!searchAfter.empty())
            {
                searchQuery["search_after"] = nlohmann::json::array({searchAfter});
            }

            logDebug2(LOGGER_DEFAULT_TAG, "Search query: %s", searchQuery.dump().c_str());

            auto searchResult = m_indexerConnector->executeSearchQuery(index, searchQuery);

            logDebug2(LOGGER_DEFAULT_TAG, "Search result: %s", searchResult.dump().c_str());

            if (!searchResult.contains("hits") || !searchResult["hits"].contains("hits") ||
                searchResult["hits"]["hits"].empty())
            {
                logDebug2(LOGGER_DEFAULT_TAG, "No more results, breaking pagination loop");
                break;
            }

            const auto& hits = searchResult["hits"]["hits"];
            for (const auto& hit : hits)
            {
                if (hit.contains("_source") && hit["_source"].contains("checksum") &&
                    hit["_source"]["checksum"].contains("hash") && hit["_source"]["checksum"]["hash"].contains("sha1"))
                {
                    concatenatedChecksums += hit["_source"]["checksum"]["hash"]["sha1"].template get<std::string>();
                }

                if (hit.contains("sort") && !hit["sort"].empty())
                {
                    searchAfter = hit["sort"][0].template get<std::string>();
                }
            }

            totalDocs += hits.size();

            if (hits.size() < BATCH_SIZE)
            {
                break;
            }
        }

        logDebug2(LOGGER_DEFAULT_TAG, "Retrieved %zu documents for checksum calculation", totalDocs);

        Utils::HashData hash(Utils::HashType::Sha1);
        hash.update(concatenatedChecksums.c_str(), concatenatedChecksums.length());
        const std::vector<unsigned char> hashResult = hash.hash();
        std::string finalChecksum = Utils::asciiToHex(hashResult);

        logDebug2(LOGGER_DEFAULT_TAG, "Calculated checksum of checksums: %s", finalChecksum.c_str());

        return finalChecksum;
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
                        if (!value.empty())
                        {
                            result["value"] = value;
                        }
                        else
                        {
                            result["value"] = "admin";
                        }
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

        // Get max sessions from configuration, default to 1000 if not specified
        if (configuration.contains("maxSessions"))
        {
            m_maxSessions = configuration.at("maxSessions").get<int>();
        }
        logDebug1(LOGGER_DEFAULT_TAG, "InventorySync session limit: %d", m_maxSessions);

        logDebug2(LOGGER_DEFAULT_TAG, "Cluster name to be used in indexer: %s", m_clusterName.c_str());

        m_workersQueue = std::make_unique<WorkersQueue>(
            [this](const std::vector<char>& dataRaw)
            {
                try
                {
                    // Check if it's a JSON message (starts with '{')
                    if (!dataRaw.empty() && dataRaw[0] == '{')
                    {
                        logDebug2(LOGGER_DEFAULT_TAG, "InventorySyncFacade::start: Processing JSON message...");
                        run(dataRaw);
                    }
                    else
                    {
                        // FlatBuffer message - verify before processing
                        flatbuffers::Verifier verifier(reinterpret_cast<const uint8_t*>(dataRaw.data()),
                                                       dataRaw.size());
                        if (Wazuh::SyncSchema::VerifyMessageBuffer(verifier))
                        {
                            logDebug2(LOGGER_DEFAULT_TAG,
                                      "InventorySyncFacade::start: Processing FlatBuffer message...");
                            run(dataRaw);
                        }
                        else
                        {
                            throw InventorySyncException("Invalid message buffer");
                        }
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
            std::make_unique<TRouterSubscriber>(INVENTORY_SYNC_TOPIC, INVENTORY_SYNC_SUBSCRIBER_ID, false);
        m_inventorySubscription->subscribe(
            // coverity[copy_constructor_call]
            [queue = m_workersQueue.get()](const std::vector<char>& message)
            {
                logDebug2(LOGGER_DEFAULT_TAG, "InventorySyncFacade::start: Received message from router");
                // TODO: Temporal allocation, we need to use move semantics in router module.
                queue->push(std::move(const_cast<std::vector<char>&>(message)));
            });

        m_indexerQueue = std::make_unique<IndexerQueue>(
            [this](const Response& res)
            {
                logDebug2(LOGGER_DEFAULT_TAG, "Indexer queue action...");
                if (res.context->option == Wazuh::SyncSchema::Option_VDSync ||
                    res.context->option == Wazuh::SyncSchema::Option_VDFirst)
                {
                    const char* modeStr = [&]() -> const char*
                    {
                        switch (res.context->mode)
                        {
                            case Wazuh::SyncSchema::Mode_ModuleFull:  return "ModuleFull";
                            case Wazuh::SyncSchema::Mode_ModuleDelta: return "ModuleDelta";
                            default:                                   return "Other";
                        }
                    }();
                    logWarn(LOGGER_DEFAULT_TAG,
                            "[VDSYNC] IndexerQueue PROCESSING: agent=%s sessionId=%llu option=%s mode=%s — "
                            "all packages received; starting bulk indexing to OpenSearch.",
                            res.context->agentId.c_str(),
                            res.context->sessionId,
                            res.context->option == Wazuh::SyncSchema::Option_VDSync ? "VDSync" : "VDFirst",
                            modeStr);
                }
                if (auto sessionIt = m_agentSessions.find(res.context->sessionId); sessionIt == m_agentSessions.end())
                {
                    logError(LOGGER_DEFAULT_TAG,
                             "InventorySyncFacade::start: Session not found, sessionId: %llu",
                             res.context->sessionId);
                    return;
                }

                try
                {
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
                            // Timeout: sessions still active after 60s
                            // These are zombie sessions - agent already validated no active syncs on its side
                            // Manager-side validation failed because of orphaned sessions
                            logWarn(
                                LOGGER_DEFAULT_TAG,
                                "Metadata/groups update for agent %s: %zu session(s) still active after 60s timeout. "
                                "Detecting as zombie sessions (agent already validated no active syncs). "
                                "Cleaning up zombie sessions automatically.",
                                res.context->agentId.c_str(),
                                remainingSessions);

                            // Clean up zombie sessions
                            size_t cleanedCount = cleanupZombieSessions(res.context->agentId, res.context->sessionId);

                            logInfo(LOGGER_DEFAULT_TAG,
                                    "Cleaned up %zu zombie session(s) for agent %s - proceeding with metadata/groups "
                                    "update",
                                    cleanedCount,
                                    res.context->agentId.c_str());
                        }

                        // All sessions completed (or zombies cleaned) - safe to proceed with metadata/groups update
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
                    else if (res.context->mode == Wazuh::SyncSchema::Mode_ModuleCheck)
                    {
                        logDebug2(LOGGER_DEFAULT_TAG,
                                  "InventorySyncFacade::start: Processing ModuleCheck for agent %s, module %s",
                                  res.context->agentId.c_str(),
                                  res.context->moduleName.c_str());

                        try
                        {
                            if (res.context->checksumIndex.empty())
                            {
                                logError(LOGGER_DEFAULT_TAG,
                                         "ModuleCheck: No index specified for agent %s",
                                         res.context->agentId.c_str());
                                m_responseDispatcher->sendEndAck(Wazuh::SyncSchema::Status_Error,
                                                                 res.context->agentId,
                                                                 res.context->sessionId,
                                                                 res.context->moduleName);
                            }
                            else
                            {
                                // Retry logic: attempt checksum validation with delays between retries
                                // This handles cases where recent delta syncs haven't been indexed yet
                                constexpr int MAX_RETRIES = 5;
                                constexpr int RETRY_DELAY_SEC = 10;
                                bool checksumMatch = false;
                                std::string managerChecksum;

                                for (int attempt = 0; attempt < MAX_RETRIES; ++attempt)
                                {
                                    if (attempt > 0)
                                    {
                                        logDebug2(LOGGER_DEFAULT_TAG,
                                                  "ModuleCheck: Retry attempt %d for agent %s after %ds delay",
                                                  attempt,
                                                  res.context->agentId.c_str(),
                                                  RETRY_DELAY_SEC);
                                        std::this_thread::sleep_for(std::chrono::seconds(RETRY_DELAY_SEC));
                                    }

                                    managerChecksum =
                                        calculateChecksumOfChecksums(res.context->checksumIndex, res.context->agentId);

                                    logInfo(LOGGER_DEFAULT_TAG,
                                            "ModuleCheck (attempt %d/%d): agent=%s, module=%s, index=%s, "
                                            "agent_checksum=%s, manager_checksum=%s",
                                            attempt + 1,
                                            MAX_RETRIES,
                                            res.context->agentId.c_str(),
                                            res.context->moduleName.c_str(),
                                            res.context->checksumIndex.c_str(),
                                            res.context->checksum.c_str(),
                                            managerChecksum.c_str());

                                    if (managerChecksum == res.context->checksum)
                                    {
                                        checksumMatch = true;
                                        break; // Success - exit retry loop
                                    }
                                }

                                if (checksumMatch)
                                {
                                    logInfo(LOGGER_DEFAULT_TAG,
                                            "ModuleCheck: Checksums match for agent %s - no full resync needed",
                                            res.context->agentId.c_str());
                                    m_responseDispatcher->sendEndAck(Wazuh::SyncSchema::Status_Ok,
                                                                     res.context->agentId,
                                                                     res.context->sessionId,
                                                                     res.context->moduleName);
                                }
                                else
                                {
                                    logInfo(LOGGER_DEFAULT_TAG,
                                            "ModuleCheck: Checksums DO NOT match for agent %s after %d attempts - "
                                            "full resync required",
                                            res.context->agentId.c_str(),
                                            MAX_RETRIES);
                                    m_responseDispatcher->sendEndAck(Wazuh::SyncSchema::Status_ChecksumMismatch,
                                                                     res.context->agentId,
                                                                     res.context->sessionId,
                                                                     res.context->moduleName);
                                }
                            }
                        }
                        catch (const std::exception& e)
                        {
                            logError(LOGGER_DEFAULT_TAG,
                                     "ModuleCheck failed for agent %s: %s",
                                     res.context->agentId.c_str(),
                                     e.what());
                            m_responseDispatcher->sendEndAck(Wazuh::SyncSchema::Status_Error,
                                                             res.context->agentId,
                                                             res.context->sessionId,
                                                             res.context->moduleName);
                        }

                        if (m_agentSessions.erase(res.context->sessionId) == 0)
                        {
                            logDebug2(LOGGER_DEFAULT_TAG,
                                      "InventorySyncFacade::start: Session not found, sessionId: %llu",
                                      res.context->sessionId);
                        }
                    }
                    else
                    {
                        // Execute DataClean deletions if any were received during the session
                        if (!res.context->dataCleanIndices.empty())
                        {
                            logDebug2(LOGGER_DEFAULT_TAG,
                                      "InventorySyncFacade::start: Processing DataClean for %zu indices...",
                                      res.context->dataCleanIndices.size());
                            // Delete from each index specified in DataClean messages
                            for (const auto& index : res.context->dataCleanIndices)
                            {
                                logDebug2(LOGGER_DEFAULT_TAG,
                                          "InventorySyncFacade::start: Deleting data from index '%s' for agent %s",
                                          index.c_str(),
                                          res.context->agentId.c_str());
                                m_indexerConnector->deleteByQuery(index, res.context->agentId);
                            }
                        }

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

                        // Track if we have any bulk data to send to indexer
                        bool hasBulkData = false;

                        // Send bulk query (with handling of 413 error).
                        for (const auto& [key, value] : m_dataStore->seek(prefix))
                        {
                            // Skip DataContext entries - they are stored with "_context" suffix and not sent to indexer
                            if (key.ends_with("_context"))
                            {
                                logDebug2(LOGGER_DEFAULT_TAG,
                                          "InventorySyncFacade::start: Skipping DataContext entry: %s",
                                          key.c_str());
                                continue;
                            }

                            hasBulkData = true;
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

                                elementId.append(!res.context->clusterName.empty() ? res.context->clusterName
                                                                                   : m_clusterName);
                                elementId.append("_");
                                elementId.append(res.context->agentId);
                                elementId.append("_");
                                elementId.append(data->id()->string_view());

                                if (data->operation() == Wazuh::SyncSchema::Operation_Upsert)
                                {
                                    logDebug2(LOGGER_DEFAULT_TAG, "InventorySyncFacade::start: Upserting data...");

                                    // Build metadata using nlohmann::json for automatic escaping
                                    nlohmann::json metadata;
                                    metadata["wazuh"]["agent"]["id"] = res.context->agentId;
                                    metadata["wazuh"]["agent"]["name"] = res.context->agentName;
                                    metadata["wazuh"]["agent"]["version"] = res.context->agentVersion;
                                    metadata["wazuh"]["agent"]["groups"] = res.context->groups;
                                    metadata["wazuh"]["agent"]["host"]["architecture"] = res.context->architecture;
                                    metadata["wazuh"]["agent"]["host"]["hostname"] = res.context->hostname;
                                    metadata["wazuh"]["agent"]["host"]["os"]["name"] = res.context->osname;
                                    metadata["wazuh"]["agent"]["host"]["os"]["platform"] = res.context->osplatform;
                                    metadata["wazuh"]["agent"]["host"]["os"]["type"] = res.context->ostype;
                                    metadata["wazuh"]["agent"]["host"]["os"]["version"] = res.context->osversion;
                                    metadata["wazuh"]["cluster"]["name"] =
                                        !res.context->clusterName.empty() ? res.context->clusterName : m_clusterName;

                                    // Serialize metadata to string and append FlatBuffer inventory data
                                    thread_local std::string dataString;
                                    dataString = metadata.dump();
                                    // Remove closing brace to append inventory data
                                    dataString.pop_back();
                                    dataString.append(",");
                                    // Append inventory data (skip opening brace from FlatBuffer data)
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

                        if (res.context->option == Wazuh::SyncSchema::Option_VDFirst ||
                            res.context->option == Wazuh::SyncSchema::Option_VDSync)
                        {
                            logWarn(LOGGER_DEFAULT_TAG,
                                    "[VDSYNC] Packages INDEXED: agent=%s sessionId=%llu option=%s "
                                    "hasBulkData=%s — packages queued for bulk send to OpenSearch "
                                    "(notify-callback will fire when OpenSearch ACKs the bulk).",
                                    res.context->agentId.c_str(),
                                    res.context->sessionId,
                                    res.context->option == Wazuh::SyncSchema::Option_VDSync ? "VDSync" : "VDFirst",
                                    hasBulkData ? "true" : "false");

                            if (VulnerabilityScannerFacade::instance().isInitialized())
                            {
                                // If the CVE feed initial load is still in progress, block this
                                // session thread until it completes (or the scanner is stopped).
                                // The agent stays in Status_Processing — already sent at End-message
                                // time — so it will not mark its VDFirst flag prematurely.
                                bool waitedForFeed = false;
                                const bool feedReadyNow = VulnerabilityScannerFacade::instance().isFeedReady();
                                logWarn(LOGGER_DEFAULT_TAG,
                                        "[VDSYNC] Feed check: agent=%s sessionId=%llu option=%s "
                                        "isFeedReady=%s — %s.",
                                        res.context->agentId.c_str(),
                                        res.context->sessionId,
                                        res.context->option == Wazuh::SyncSchema::Option_VDSync ? "VDSync" : "VDFirst",
                                        feedReadyNow ? "true" : "false",
                                        feedReadyNow ? "proceeding directly to scan decision"
                                                     : "CVE feed not ready, this thread will block");
                                if (!feedReadyNow)
                                {
                                    waitedForFeed = true;
                                    logWarn(LOGGER_DEFAULT_TAG,
                                            "[VDSYNC] Wait START: agent=%s sessionId=%llu option=%s — "
                                            "blocking IndexerQueue thread until CVE feed is ready.",
                                            res.context->agentId.c_str(),
                                            res.context->sessionId,
                                            res.context->option == Wazuh::SyncSchema::Option_VDSync ? "VDSync"
                                                                                                   : "VDFirst");
                                    VulnerabilityScannerFacade::instance().waitForFeedReady();
                                    logWarn(LOGGER_DEFAULT_TAG,
                                            "[VDSYNC] Wait END: agent=%s sessionId=%llu option=%s — "
                                            "CVE feed ready, resuming.",
                                            res.context->agentId.c_str(),
                                            res.context->sessionId,
                                            res.context->option == Wazuh::SyncSchema::Option_VDSync ? "VDSync"
                                                                                                   : "VDFirst");
                                }

                                // Run scan only if the scanner was not stopped during the wait.
                                if (VulnerabilityScannerFacade::instance().isFeedReady())
                                {
                                    // Skip VDSync delta scan when a feed-update full scan is already
                                    // covering all packages — either because this session waited for the
                                    // initial feed load (the feed-update scan fires right after) or
                                    // because a feed-update full scan is currently in progress.
                                    const bool feedUpdateInProgress =
                                        VulnerabilityScannerFacade::instance().isFeedUpdateScanInProgress();
                                    const bool skipScan =
                                        (waitedForFeed || feedUpdateInProgress) &&
                                        res.context->option == Wazuh::SyncSchema::Option_VDSync;

                                    logWarn(LOGGER_DEFAULT_TAG,
                                            "[VDSYNC] Scan decision: agent=%s sessionId=%llu option=%s "
                                            "waitedForFeed=%s feedUpdateInProgress=%s skipScan=%s — %s.",
                                            res.context->agentId.c_str(),
                                            res.context->sessionId,
                                            res.context->option == Wazuh::SyncSchema::Option_VDSync ? "VDSync"
                                                                                                   : "VDFirst",
                                            waitedForFeed ? "true" : "false",
                                            feedUpdateInProgress ? "true" : "false",
                                            skipScan ? "true" : "false",
                                            skipScan
                                                ? (waitedForFeed
                                                       ? "SKIPPED — waited for feed, feed-update full scan covers all packages"
                                                       : "SKIPPED — feed-update full scan in progress, covers all packages")
                                                : "RUN — executing delta vulnerability scan now");

                                    if (skipScan)
                                    {
                                        logInfo(LOGGER_DEFAULT_TAG,
                                                "InventorySyncFacade: Skipping VDSync scan for agent %s — "
                                                "%s.",
                                                res.context->agentId.c_str(),
                                                waitedForFeed
                                                    ? "feed-update full scan will cover all packages"
                                                    : "feed-update full scan in progress, covers all packages");
                                    }
                                    else
                                    {
                                        logWarn(LOGGER_DEFAULT_TAG,
                                                "[VDSYNC] Scan RUN START: agent=%s sessionId=%llu option=%s — "
                                                "calling runScanner() with RocksDB delta packages.",
                                                res.context->agentId.c_str(),
                                                res.context->sessionId,
                                                res.context->option == Wazuh::SyncSchema::Option_VDSync ? "VDSync"
                                                                                                       : "VDFirst");
                                        try
                                        {
                                            VulnerabilityScannerFacade::instance().runScanner(
                                                *m_dataStore, *res.context);
                                            logWarn(LOGGER_DEFAULT_TAG,
                                                    "[VDSYNC] Scan RUN END: agent=%s sessionId=%llu option=%s — "
                                                    "runScanner() completed successfully.",
                                                    res.context->agentId.c_str(),
                                                    res.context->sessionId,
                                                    res.context->option == Wazuh::SyncSchema::Option_VDSync ? "VDSync"
                                                                                                           : "VDFirst");
                                        }
                                        catch (const std::exception& e)
                                        {
                                            logError(LOGGER_DEFAULT_TAG,
                                                     "InventorySyncFacade: Vulnerability scanner exception for "
                                                     "agent %s: %s",
                                                     res.context->agentId.c_str(),
                                                     e.what());
                                            m_responseDispatcher->sendEndAck(Wazuh::SyncSchema::Status_Error,
                                                                             res.context->agentId,
                                                                             res.context->sessionId,
                                                                             res.context->moduleName);
                                            m_dataStore->deleteByPrefix(std::to_string(res.context->sessionId));
                                            m_agentSessions.erase(res.context->sessionId);
                                            logWarn(LOGGER_DEFAULT_TAG,
                                                    "[VDSYNC] Session END (scanner-exception): agent=%s "
                                                    "sessionId=%llu option=%s reason=%s",
                                                    res.context->agentId.c_str(),
                                                    res.context->sessionId,
                                                    res.context->option == Wazuh::SyncSchema::Option_VDSync
                                                        ? "VDSync"
                                                        : "VDFirst",
                                                    e.what());
                                            m_sessionCompletedCV.notify_all();
                                        }
                                    }
                                }
                                else
                                {
                                    logDebug1(LOGGER_DEFAULT_TAG,
                                              "InventorySyncFacade: Scanner stopped while waiting for CVE feed — "
                                              "skipping scan for agent %s.",
                                              res.context->agentId.c_str());
                                }
                            }
                            else
                            {
                                logDebug1(LOGGER_DEFAULT_TAG,
                                          "InventorySyncFacade: Vulnerability scanner disabled — "
                                          "skipping scan for agent %s.",
                                          res.context->agentId.c_str());
                            }
                        }

                        // Only register notify callback if there's bulk data or deleteByQuery operations
                        if (hasBulkData || !res.context->dataCleanIndices.empty() ||
                            res.context->mode == Wazuh::SyncSchema::Mode_ModuleFull)
                        {
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
                                    if (ctx->option == Wazuh::SyncSchema::Option_VDSync ||
                                        ctx->option == Wazuh::SyncSchema::Option_VDFirst)
                                    {
                                        logWarn(LOGGER_DEFAULT_TAG,
                                                "[VDSYNC] Session END (notify-callback): agent=%s sessionId=%llu "
                                                "option=%s — OpenSearch ACKed the bulk; Status_Ok sent to agent; "
                                                "RocksDB data deleted.",
                                                ctx->agentId.c_str(),
                                                ctx->sessionId,
                                                ctx->option == Wazuh::SyncSchema::Option_VDSync ? "VDSync" : "VDFirst");
                                    }
                                    m_sessionCompletedCV.notify_all();
                                });
                        }
                        else
                        {
                            // No bulk data and no deleteByQuery - send immediate response (e.g., DataContext-only
                            // session)
                            logDebug2(LOGGER_DEFAULT_TAG,
                                      "InventorySyncFacade::start: No bulk data or deleteByQuery, sending immediate "
                                      "response for session %llu",
                                      res.context->sessionId);
                            m_responseDispatcher->sendEndAck(Wazuh::SyncSchema::Status_Ok,
                                                             res.context->agentId,
                                                             res.context->sessionId,
                                                             res.context->moduleName);
                            m_dataStore->deleteByPrefix(std::to_string(res.context->sessionId));
                            if (m_agentSessions.erase(res.context->sessionId) == 0)
                            {
                                logDebug2(LOGGER_DEFAULT_TAG,
                                          "InventorySyncFacade::start: Session not found, sessionId: %llu",
                                          res.context->sessionId);
                            }
                            if (res.context->option == Wazuh::SyncSchema::Option_VDSync ||
                                res.context->option == Wazuh::SyncSchema::Option_VDFirst)
                            {
                                logWarn(LOGGER_DEFAULT_TAG,
                                        "[VDSYNC] Session END (immediate-response): agent=%s sessionId=%llu "
                                        "option=%s — no bulk data; Status_Ok sent to agent immediately.",
                                        res.context->agentId.c_str(),
                                        res.context->sessionId,
                                        res.context->option == Wazuh::SyncSchema::Option_VDSync ? "VDSync" : "VDFirst");
                            }
                            m_sessionCompletedCV.notify_all();
                        }
                    } // End of else block for non-MetadataDelta/GroupDelta modes

                    // Invoke pending callbacks from executeUpdateByQuery operations (if any)
                    // This must be done after releasing scopeLock to avoid deadlock
                    lock.unlock();
                    m_indexerConnector->invokePendingCallbacks();
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
                    if (res.context->option == Wazuh::SyncSchema::Option_VDSync ||
                        res.context->option == Wazuh::SyncSchema::Option_VDFirst)
                    {
                        logWarn(LOGGER_DEFAULT_TAG,
                                "[VDSYNC] Session END (InventorySyncException): agent=%s sessionId=%llu "
                                "option=%s reason=%s",
                                res.context->agentId.c_str(),
                                res.context->sessionId,
                                res.context->option == Wazuh::SyncSchema::Option_VDSync ? "VDSync" : "VDFirst",
                                e.what());
                    }
                    m_sessionCompletedCV.notify_all();

                    m_indexerConnector->invokePendingCallbacks();
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
                    if (res.context->option == Wazuh::SyncSchema::Option_VDSync ||
                        res.context->option == Wazuh::SyncSchema::Option_VDFirst)
                    {
                        logWarn(LOGGER_DEFAULT_TAG,
                                "[VDSYNC] Session END (exception): agent=%s sessionId=%llu "
                                "option=%s reason=%s",
                                res.context->agentId.c_str(),
                                res.context->sessionId,
                                res.context->option == Wazuh::SyncSchema::Option_VDSync ? "VDSync" : "VDFirst",
                                e.what());
                    }
                    m_sessionCompletedCV.notify_all();

                    m_indexerConnector->invokePendingCallbacks();
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

                    // Release condition-variable mutex before acquiring the sessions mutex
                    // to match the canonical lock order (m_agentSessionsMutex → m_blockedAgentsMutex)
                    // and avoid a data race with worker threads that hold m_agentSessionsMutex.
                    lock.unlock();

                    std::unique_lock agentSessionsLock(m_agentSessionsMutex);
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
                    m_sessionCompletedCV.notify_all();
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
     * @brief Wait until all active VDSync sessions across all agents have completed.
     *
     * Called by the feed-update callback BEFORE it acquires m_internalMutex, avoiding
     * the deadlock where feedUpdate holds that mutex while waiting for a VDSync session
     * that is itself blocked trying to acquire the same mutex.
     *
     * Because VulnerabilityScannerFacade::m_feedUpdateScanInProgress is set before
     * this is called, VDSync sessions in their scan-decision phase will skip their scan
     * and end quickly, so each hasActiveSessionForModule call below returns fast.
     *
     * @param timeout    Maximum wait time per attempt (forwarded to hasActiveSessionForModule).
     * @param maxRetries Retry count (forwarded to hasActiveSessionForModule).
     */
    void waitForAllVDSyncSessions(std::chrono::seconds timeout, uint32_t maxRetries) const
    {
        while (true)
        {
            std::vector<std::string> vdSyncAgents;
            {
                std::shared_lock lock(m_agentSessionsMutex);
                for (const auto& [id, session] : m_agentSessions)
                {
                    const auto& ctx = session.getContext();
                    if (ctx->moduleName == "syscollector_vd" &&
                        ctx->option == Wazuh::SyncSchema::Option_VDSync)
                    {
                        vdSyncAgents.push_back(ctx->agentId);
                    }
                }
            }

            if (vdSyncAgents.empty())
            {
                break;
            }

            for (const auto& agentId : vdSyncAgents)
            {
                hasActiveSessionForModule(agentId, "syscollector_vd", timeout, maxRetries);
            }
        }
    }

    /**
     * @brief Check if a specific agent has an active session for a specific module.
     *
     * When called from a feed-update scan context (timeout > 0):
     *   - VDFirst session: returns true immediately so the caller can skip the redundant
     *     feed-update scan (the first-scan itself will cover the updated feed).
     *   - VDSync session:  blocks until the session ends or the timeout expires, then
     *     returns false so the caller proceeds with the feed-update scan.
     *     If the session does not finish within the timeout, the wait is retried up to
     *     maxRetries additional times before giving up.
     *
     * When called without a timeout (default): behaves as a plain existence check and
     * returns true if any session matches, regardless of the session option.
     *
     * @param agentId    Agent ID to check
     * @param moduleName Module name to check (e.g., "syscollector_vd")
     * @param timeout    How long to wait per attempt for a VDSync session to finish (0 = no wait)
     * @param maxRetries Maximum number of extra wait attempts after the first timeout (0 = no retry)
     * @return true if a VDFirst session is active (caller should skip the scan);
     *         false in all other cases (no session, or VDSync finished/timed out)
     */
    bool hasActiveSessionForModule(const std::string& agentId,
                                   const std::string& moduleName,
                                   std::chrono::seconds timeout,
                                   uint32_t maxRetries) const
    {
        std::shared_lock lock(m_agentSessionsMutex);

        for (const auto& [sessionId, session] : m_agentSessions)
        {
            const auto& context = session.getContext();
            if (context->agentId == agentId && context->moduleName == moduleName)
            {
                if (context->option == Wazuh::SyncSchema::Option_VDFirst)
                {
                    return true; // VDFirst: caller should skip
                }

                if (timeout > std::chrono::seconds(0))
                {
                    // VDSync: wait for the session to finish before the feed-update scan reads
                    // the indexer, so all packages are in a consistent state.
                    logInfo(LOGGER_DEFAULT_TAG,
                            "Feed update scan waiting for VDSync session to complete for agent %s "
                            "(timeout: %lds, max retries: %u).",
                            agentId.c_str(),
                            static_cast<long>(timeout.count()),
                            maxRetries);

                    const auto isSessionGone = [&]()
                    {
                        for (const auto& [sId, s] : m_agentSessions)
                        {
                            if (s.getContext()->agentId == agentId && s.getContext()->moduleName == moduleName)
                            {
                                return false; // still active
                            }
                        }
                        return true; // session gone
                    };

                    uint32_t attemptsLeft = maxRetries + 1;
                    while (attemptsLeft > 0)
                    {
                        --attemptsLeft;
                        const bool completed = m_sessionCompletedCV.wait_for(lock, timeout, isSessionGone);

                        if (completed)
                        {
                            break;
                        }

                        if (attemptsLeft > 0)
                        {
                            logWarn(LOGGER_DEFAULT_TAG,
                                    "Feed update scan timeout waiting for VDSync session for agent %s (%lds). "
                                    "Retrying (%u retries left).",
                                    agentId.c_str(),
                                    static_cast<long>(timeout.count()),
                                    attemptsLeft);
                        }
                        else
                        {
                            logWarn(LOGGER_DEFAULT_TAG,
                                    "Feed update scan timeout waiting for VDSync session for agent %s (%lds). "
                                    "Proceeding with current indexer data.",
                                    agentId.c_str(),
                                    static_cast<long>(timeout.count()));
                        }
                    }
                }

                return false; // VDSync: proceed with the scan (waited or no-wait requested)
            }
        }

        return false; // no session
    }

    /**
     * @brief Clean up zombie sessions for an agent
     * @param agentId Agent ID to clean up sessions for
     * @param excludeSessionId Session ID to exclude from cleanup (e.g., the current session)
     * @return Number of zombie sessions cleaned up
     */
    size_t cleanupZombieSessions(const std::string& agentId, uint64_t excludeSessionId = 0)
    {
        std::unique_lock lock(m_agentSessionsMutex);
        size_t cleanedCount = 0;

        std::vector<uint64_t> sessionsToRemove;

        // Collect zombie sessions for this agent
        for (const auto& [sessionId, session] : m_agentSessions)
        {
            if (sessionId == excludeSessionId)
            {
                continue;
            }

            const auto& context = session.getContext();
            if (agentId.empty() || context->agentId == agentId)
            {
                sessionsToRemove.push_back(sessionId);
            }
        }

        // Remove zombie sessions
        for (const auto& sessionId : sessionsToRemove)
        {
            auto it = m_agentSessions.find(sessionId);
            if (it != m_agentSessions.end())
            {
                const auto& context = it->second.getContext();

                logWarn(LOGGER_DEFAULT_TAG,
                        "Cleaning up zombie session %llu for agent %s (module: %s)",
                        sessionId,
                        context->agentId.c_str(),
                        context->moduleName.c_str());

                // Delete data from database
                m_dataStore->deleteByPrefix(std::to_string(sessionId));

                // Remove session
                m_agentSessions.erase(it);
                cleanedCount++;
            }
        }

        if (cleanedCount > 0)
        {
            m_sessionCompletedCV.notify_all();
            logInfo(LOGGER_DEFAULT_TAG,
                    "Cleaned up %zu zombie session(s) for agent %s",
                    cleanedCount,
                    agentId.empty() ? "ALL" : agentId.c_str());
        }

        return cleanedCount;
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

        if (m_sessionTimeoutThread.joinable())
        {
            m_sessionTimeoutThread.join();
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

    void deleteAgent(const std::string& agentId)
    {
        if (agentId.empty())
        {
            logWarn(LOGGER_DEFAULT_TAG, "InventorySyncFacade::deleteAgent: Empty agent ID");
            return;
        }

        if (!m_indexerConnector)
        {
            logError(LOGGER_DEFAULT_TAG, "InventorySyncFacade::deleteAgent: Indexer connector not initialized");
            return;
        }

        if (!m_indexerConnector->isAvailable())
        {
            logWarn(LOGGER_DEFAULT_TAG,
                    "InventorySyncFacade::deleteAgent: Indexer not available, skipping deletion for agent '%s'",
                    agentId.c_str());
            return;
        }

        logInfo(LOGGER_DEFAULT_TAG,
                "InventorySyncFacade::deleteAgent: Deleting data for agent '%s' from %s indexes",
                agentId.c_str(),
                WAZUH_STATES_INDEX_PATTERN);

        try
        {
            // Delete all agent data from wazuh-states-* indexes using wildcard pattern
            auto lock = m_indexerConnector->scopeLock();
            m_indexerConnector->deleteByQuery(WAZUH_STATES_INDEX_PATTERN, agentId);

            logInfo(LOGGER_DEFAULT_TAG,
                    "InventorySyncFacade::deleteAgent: Successfully deleted data for agent '%s'",
                    agentId.c_str());
        }
        catch (const std::exception& e)
        {
            logError(LOGGER_DEFAULT_TAG,
                     "InventorySyncFacade::deleteAgent: Failed to delete data for agent '%s': %s",
                     agentId.c_str(),
                     e.what());
        }
    }

    /**
     * @brief Clean up stale session for agent+module if one exists
     * @param agentId Agent ID
     * @param moduleName Module name
     *
     * This handles cases where agent or modulesd restarts, leaving orphaned sessions.
     * When a new Start message arrives, we check if there's already a session for the
     * same agent+module combination, and if so, clean it up before creating the new one.
     *
     * Note: Caller must hold m_agentSessionsMutex write lock
     */
    void cleanupStaleSessionForAgentModule(const std::string& agentId, const std::string& moduleName)
    {
        std::vector<uint64_t> staleSessionsToRemove;

        // Find existing sessions for this agent+module combination
        for (const auto& [existingSessionId, existingSession] : m_agentSessions)
        {
            const auto& existingContext = existingSession.getContext();
            if (existingContext->agentId == agentId && existingContext->moduleName == moduleName)
            {
                logInfo(LOGGER_DEFAULT_TAG,
                        "Found existing session %llu for agent %s module %s - "
                        "cleaning up stale session",
                        existingSessionId,
                        agentId.c_str(),
                        moduleName.c_str());
                staleSessionsToRemove.push_back(existingSessionId);
            }
        }

        // Clean up stale sessions
        for (const auto& staleSessionId : staleSessionsToRemove)
        {
            auto it = m_agentSessions.find(staleSessionId);
            if (it != m_agentSessions.end())
            {
                const auto& context = it->second.getContext();

                // Unlock agent if this session owns the lock
                if (context->ownsAgentLock)
                {
                    unlockAgent(agentId);
                    logInfo(LOGGER_DEFAULT_TAG,
                            "Stale session %llu owned agent lock - unlocked agent %s",
                            staleSessionId,
                            agentId.c_str());
                }

                // Delete data from database
                m_dataStore->deleteByPrefix(std::to_string(staleSessionId));

                // Remove session from map
                m_agentSessions.erase(it);
                m_sessionCompletedCV.notify_all();
            }
        }
    }

    std::string m_clusterName;
    int m_maxSessions {1000}; // Maximum concurrent sessions (configured from internal_options)
    mutable std::shared_mutex m_agentSessionsMutex;
    mutable std::condition_variable_any m_sessionCompletedCV; ///< Notified whenever a session is removed
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

    // Agent locking mechanism for metadata/groups updates
    std::unordered_set<std::string> m_blockedAgents; ///< Set of locked agent IDs
    mutable std::shared_mutex m_blockedAgentsMutex;  ///< Mutex for blocked agents set
    std::atomic<bool> m_allAgentsLocked {false};     ///< Global lock for all agents
    std::unique_ptr<SocketServer<Socket<OSPrimitives, SizeHeaderProtocol>, EpollWrapper>> m_keystoreSocketServer;
};

using InventorySyncFacade = InventorySyncFacadeImpl<AgentSession,
                                                    ResponseDispatcher,
                                                    RouterSubscriber,
                                                    IndexerConnectorSync,
                                                    Utils::RocksDBWrapper>;

#endif // _INVENTORY_SYNC_FACADE_HPP
