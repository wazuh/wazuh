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

#include <base/utils/threadEventDispatcher.hpp>

#include <indexerConnector/iindexerconnector.hpp>

#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

/**
 * @brief Options for the secure communication.
 *
 */
struct SslOptions
{
    std::vector<std::string> cacert;
    std::string cert;
    std::string key;
};

/**
 * @brief Options for the IndexerConnector.
 *
 */
struct IndexerConnectorOptions
{
    std::string name;
    std::vector<std::string> hosts;
    std::string username;
    std::string password;
    SslOptions sslOptions;
    uint32_t timeout = 60000u;
    uint8_t workingThreads = 1;
    std::string databasePath;
};

template<typename TMonitoring = void>
class TServerSelector;
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
    IndexerConnectorOptions m_indexerConnectorOptions;

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
     * @param config Indexer configuration includes:
     *  - Index name .
     *  - Server list .
     *  - Ssl configuration (cacert, cert, and key).
     *  - Authentication (username and password).
     *  - Timeout (Interval for monitoring the server health).
     *  - Working threads number (Number of working threads used by the dispatcher. More than one results in an
    unordered
     * processing).
     */
    explicit IndexerConnector(const IndexerConnectorOptions& config);

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
