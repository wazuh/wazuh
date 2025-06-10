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
#include "routerSubscriber.hpp"
#include "singleton.hpp"
#include <functional>
#include <indexerConnector.hpp>
#include <json.hpp>
#include <memory>
#include <random>
#include <rocksdb/slice.h>
#include <shared_mutex>
#include <string>
#include <threadDispatcher.h>
#include <utility>

constexpr int SINGLE_THREAD_COUNT = 1;

using WorkersQueue = Utils::AsyncDispatcher<std::vector<char>, std::function<void(const std::vector<char>&)>>;
using IndexerQueue = Utils::AsyncDispatcher<Response, std::function<void(const Response&)>>;

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
            if (auto it = m_agentSessions.find(data->session()); it == m_agentSessions.end())
            {
                throw InventorySyncException("Session not found");
            }
            else
            {
                // Handle data.
                it->second.handleData(data, dataRaw);
            }
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
                if (m_agentSessions.find(sessionId) != m_agentSessions.end())
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
            if (auto it = m_agentSessions.find(end->session()); it == m_agentSessions.end())
            {
                throw InventorySyncException("Session not found");
            }
            else
            {
                // Handle end.
                std::cout << "Handling end for session: " << end->session() << std::endl;
                it->second.handleEnd(*m_responseDispatcher);
            }
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
        std::cout << "Starting InventorySyncFacade..." << std::endl;

        // TODO This database should be ephemeral and not persistent.
        m_dataStore = std::make_unique<TRocksDBWrapper>("inventory_sync");
        m_responseDispatcher = std::make_unique<TResponseDispatcher>();
        m_indexerConnector = std::make_unique<TIndexerConnector>(
            nlohmann::json::parse(R"({"hosts": ["localhost:9200"], "ssl": {"certificate_authorities": []}})"),
            logFunction);

        m_workersQueue = std::make_unique<WorkersQueue>(
            [this](const std::vector<char>& dataRaw)
            {
                try
                {
                    // std::cout << "InventorySyncFacade::start: Processing message..." << std::endl;
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
                    std::cerr << "InventorySyncFacade::start: " << e.what() << std::endl;
                }
            },
            std::thread::hardware_concurrency(),
            UNLIMITED_QUEUE_SIZE);

        m_inventorySubscription = std::make_unique<TRouterSubscriber>("inventory-states", "inventory-sync-module");
        m_inventorySubscription->subscribe(
            // coverity[copy_constructor_call]
            [queue = m_workersQueue.get()](const std::vector<char>& message) { queue->push(message); });

        const auto preIndexerAction = []()
        {
            std::cout << "Pre-indexer action...\n";
        };

        m_indexerQueue = std::make_unique<IndexerQueue>(
            [this, &preIndexerAction](const Response& res)
            {
                std::cout << "Indexer queue action...\n";
                try
                {
                    auto sessionIt = m_agentSessions.find(res.context->sessionId);
                    if (sessionIt == m_agentSessions.end())
                    {
                        throw InventorySyncException("Session not found");
                    }

                    preIndexerAction();

                    // Send delete by query to indexer if mode is full.
                    if (res.context->mode == Wazuh::SyncSchema::Mode_Full)
                    {
                        nlohmann::json bulkData;
                        IndexerConnector::Builder::deleteByQuery(bulkData, std::to_string(res.context->agentId));
                        m_indexerConnector->deleteByQuery(bulkData.dump(), std::to_string(res.context->agentId));
                    }

                    std::string bulkData;
                    std::string prefix = std::to_string(res.context->sessionId) + "_";
                    // Send bulk query (with handling of 429 error).
                    for (const auto& [key, value] : m_dataStore->seek(prefix))
                    {
                        flatbuffers::Verifier verifier(reinterpret_cast<const uint8_t*>(value.data()), value.size());
                        if (Wazuh::SyncSchema::VerifyMessageBuffer(verifier))
                        {
                            auto message = Wazuh::SyncSchema::GetMessage(value.data());
                            auto data = message->content_as_Data();
                            if (data->operation() == Wazuh::SyncSchema::Operation_Upsert)
                            {
                                IndexerConnector::Builder::bulkIndex(
                                    bulkData,
                                    data->id()->string_view(),
                                    data->index()->string_view(),
                                    std::string_view((const char*)data->data()->data(), data->data()->size()));
                            }
                            else if (data->operation() == Wazuh::SyncSchema::Operation_Delete)
                            {
                                IndexerConnector::Builder::bulkDelete(
                                    bulkData, data->index()->str(), data->id()->str());
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
                    std::cout << "Bulk data: " << bulkData << std::endl;
                    m_indexerConnector->bulk(bulkData);

                    // Send ACK to agent.
                    m_responseDispatcher->sendEndAck(Wazuh::SyncSchema::Status_Ok, res.context);
                    // Delete data from database.
                    m_dataStore->deleteByPrefix(std::to_string(res.context->sessionId));
                    // Delete Session.
                    m_agentSessions.erase(sessionIt);
                }
                catch (const InventorySyncException& e)
                {
                    std::cerr << "InventorySyncFacade::start: " << e.what() << std::endl;
                }
                catch (const std::exception& e)
                {
                    std::cerr << "InventorySyncFacade::start: " << e.what() << std::endl;
                }
            },
            std::thread::hardware_concurrency(),
            UNLIMITED_QUEUE_SIZE);

        std::cout << "InventorySyncFacade started." << std::endl;
    }

    /**
     * @brief Stops facade.
     *
     */
    void stop()
    {
        std::cout << "Stopping InventorySyncFacade..." << std::endl;
        m_inventorySubscription.reset();
        m_workersQueue.reset();
        m_indexerQueue.reset();
        m_indexerConnector.reset();
        m_dataStore.reset();
    }

private:
    InventorySyncFacadeImpl() = default;
    std::unique_ptr<TRocksDBWrapper> m_dataStore;
    std::unique_ptr<TIndexerConnector> m_indexerConnector;
    std::unique_ptr<IndexerQueue> m_indexerQueue;
    std::unique_ptr<TResponseDispatcher> m_responseDispatcher;
    std::unique_ptr<WorkersQueue> m_workersQueue;
    std::unique_ptr<TRouterSubscriber> m_inventorySubscription;
    std::map<uint64_t, TAgentSession, std::less<>> m_agentSessions;
    std::shared_mutex m_agentSessionsMutex;
};

using InventorySyncFacade = InventorySyncFacadeImpl<AgentSession,
                                                    ResponseDispatcher,
                                                    RouterSubscriber,
                                                    IndexerConnector,
                                                    Utils::RocksDBWrapper>;

#endif // _INVENTORY_SYNC_FACADE_HPP
