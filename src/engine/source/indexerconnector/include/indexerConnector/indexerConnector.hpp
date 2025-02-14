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
 * @brief Configuration options for the Indexer Connector.
 *
 */
struct IndexerConnectorOptions
{
    std::string name;               ///< The name of the index to push the data.
    std::vector<std::string> hosts; ///< The list of hosts to connect to. i.e. ["https://localhost:9200"]
    std::string username;           ///< The username to authenticate with OpenSearch.
    std::string password;           ///< The password to authenticate with OpenSearch.
    struct
    {
        std::vector<std::string> cacert; ///< The list of CA certificates to trust.
        std::string cert;                ///< The certificate to connect to OpenSearch.
        std::string key;                 ///< The key to connect to OpenSearch.
        bool skipVerifyPeer;             ///< Skip peer verification. (insecure mode)
        std::string mergedCaPath;        ///< The path to the merged CA certificate.
    } sslOptions;                        ///< The SSL options to connect to OpenSearch.

    uint32_t timeout = 60000u;  ///< The timeout in milliseconds to connect to OpenSearch.
    uint8_t workingThreads = 1; ///< The number of threads to dequeue and send the data.
    std::string databasePath;   ///< The path to the database file.
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
     * 4. In each bulk query, the index name "$(date)" placeholder will be replaced by the current date.
     *
     * @param config Indexer connector configuration
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
