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
class EXPORTED IndexerConnector : public IIndexerConnector
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
     * @brief Class constructor that initializes the publisher.
     *
     * @param config Indexer configuration, including database_path and servers.
     * @param timeout Server selector time interval.
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

    ~IndexerConnector();

    /**
     * @copydoc IIndexerConnector::publish
     */
    void publish(const std::string& message);
};

#endif // _INDEXER_CONNECTOR_HPP
