/*
 * Wazuh - Indexer connector.
 * Copyright (C) 2015, Wazuh Inc.
 * June 2, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INDEXER_CONNECTOR_HPP
#define _INDEXER_CONNECTOR_HPP

#include "rocksDBWrapper.hpp"
#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

static constexpr auto DEFAULT_INTERVAL = 60u;

class ServerSelector;
class SecureCommunication;
#include "threadDispatcher.h"
#include "threadEventDispatcher.hpp"
#include <json.hpp>
#include <string>

using ThreadDispatchQueue = ThreadEventDispatcher<std::string, std::function<void(std::queue<std::string>&)>>;
using ThreadSyncQueue = Utils::AsyncDispatcher<std::string, std::function<void(const std::string&)>>;

/**
 * @brief IndexerConnector class.
 *
 */
class EXPORTED IndexerConnector final
{
    /**
     * @brief Initialized status.
     *
     */
    std::atomic<bool> m_initialized {false};
    std::thread m_initializeThread;
    std::condition_variable m_cv;
    std::mutex m_mutex;
    std::atomic<bool> m_stopping {false};
    std::unique_ptr<Utils::RocksDBWrapper> m_db;
    std::unique_ptr<ThreadSyncQueue> m_syncQueue;
    std::string m_indexName;
    std::mutex m_syncMutex;
    std::unique_ptr<ThreadDispatchQueue> m_dispatcher;
    std::unordered_map<std::string, std::chrono::system_clock::time_point> m_lastSync;
    uint32_t m_successCount {0};
    bool m_error413FirstTime {false};

    /**
     * @brief Intialize method used to load template data and initialize the index.
     *
     * @param templateData Template data.
     * @param indexName Index name.
     * @param selector Server selector.
     * @param secureCommunication Secure communication.
     */
    void initialize(const nlohmann::json& templateData,
                    const std::shared_ptr<ServerSelector>& selector,
                    const SecureCommunication& secureCommunication);

    /**
     * @brief This method is used to calculate the diff between the inventory database and the indexer.
     * @param responseJson Response JSON.
     * @param agentId Agent ID.
     * @param secureCommunication Secure communication.
     * @param selector Server selector.
     */
    void diff(const nlohmann::json& responseJson,
              const std::string& agentId,
              const SecureCommunication& secureCommunication,
              const std::shared_ptr<ServerSelector>& selector);

    /**
     * @brief Get agent ids of documents from the indexer.
     * @param url Indexer URL.
     * @param agentId Agent ID.
     * @param secureCommunication Secure communication.
     * @return Agent documents.
     */
    nlohmann::json getAgentDocumentsIds(const std::string& url,
                                        const std::string& agentId,
                                        const SecureCommunication& secureCommunication) const;

    /**
     * @brief Abuse control.
     * @param agentId Agent ID.
     * @return True if the agent is abusing the indexer, false otherwise.
     */
    bool abuseControl(const std::string& agentId);

    /**
     * @brief Send bulk reactive, this method is used to send a bulk request to the indexer.
     * @param actions Actions to be sent.
     * @param url Indexer URL.
     * @param secureCommunication Secure communication.
     */
    void sendBulkReactive(const std::vector<std::pair<std::string, bool>>& actions,
                          const std::string& url,
                          const SecureCommunication& secureCommunication);

public:
    /**
     * @brief Class constructor that initializes the publisher.
     *
     * @param config Indexer configuration, including database_path and servers.
     * @param templatePath Path to the template file.
     * @param logFunction Callback function to be called when trying to log a message.
     * @param timeout Server selector time interval.
     */
    explicit IndexerConnector(const nlohmann::json& config,
                              const std::string& templatePath,
                              const std::function<void(const int,
                                                       const std::string&,
                                                       const std::string&,
                                                       const int,
                                                       const std::string&,
                                                       const std::string&,
                                                       va_list)>& logFunction = {},
                              const uint32_t& timeout = DEFAULT_INTERVAL);

    ~IndexerConnector();

    /**
     * @brief Publish a message into the queue map.
     *
     * @param message Message to be published.
     */
    void publish(const std::string& message);

    /**
     * @brief Sync the inventory database with the indexer.
     * This method is used to synchronize the inventory database to the indexer.
     *
     * @param agentId Agent ID.
     */
    void sync(const std::string& agentId);
};

#endif // _INDEXER_CONNECTOR_HPP
