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

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>

#include <nlohmann/json.hpp>

#include <base/utils/threadEventDispatcher.hpp>

#include <indexerConnector/iindexerconnector.hpp>

#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

static constexpr auto DEFAULT_INTERVAL = 60u;

class ServerSelector;
class SecureCommunication;

using ThreadDispatchQueue = ThreadEventDispatcher<std::string, std::function<void(std::queue<std::string>&)>>;

/**
 * @brief IndexerConnector class.
 *
 */
class EXPORTED IndexerConnector final : public IIndexerConnector
{
    /**
     * @brief Initialized status.
     *
     */
    std::condition_variable m_cv;
    std::atomic<bool> m_stopping {false};
    std::string m_indexName;
    std::mutex m_syncMutex;
    std::unique_ptr<ThreadDispatchQueue> m_dispatcher;

public:
    /**
     * @brief Class constructor
     *
     * @note Does the following:
     * 1. Initializes credential management based on the configurations.
     * 2. Selects the server to be used through a round-robin algorithm among the available servers (servers are
     * health-checked using the API endpoint (/_cat/health)
     * 3. Sets up the dispatcher to process messages asynchronously using a persistent queue. Messages are dispatched in
     * bulk either when the maximum bulk size or the time interval is reached. The bulk size is 1000 messages and the
     * interval is 5 seconds.
     *
     * @param config Indexer configuration, including the index name, server list, ssl configuration and user and
     * password.
     * @param timeout Interval for monitoring the server health.
     * @param workingThreads Number of working threads used by the dispatcher. More than one results in an unordered
     * processing.
     * @note Example of the configuration:
     *  {
     *      "name": "wazuh-alerts-5.x",
     *      "host": ["localhost:9200"],
     *      "user": "admin",
     *      "password": "admin",
     *      "ssl": {
     *          "certificate_authorities": "/etc/ssl/certs/ca.pem",
     *          "certificate": "/etc/ssl/certs/cert.pem",
     *          "key": "/etc/ssl/certs/key.pem"
     *      }
     *  }
     */
    explicit IndexerConnector(const nlohmann::json& config,
                              const uint32_t& timeout = DEFAULT_INTERVAL,
                              uint8_t workingThreads = 1);

    /**
     * @brief Class destructor.
     * @note It will stop the dispatcher and wait for the threads to finish gracefully.
     */
    ~IndexerConnector() override;

    /**
     * @copydoc IIndexerConnector::publish
     */
    void publish(const std::string& message) override;
};

#endif // _INDEXER_CONNECTOR_HPP
