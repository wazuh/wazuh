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

#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

static constexpr auto DEFAULT_INTERVAL = 60u;

class ServerSelector;
class SecureCommunication;

#include "threadEventDispatcher.hpp"
#include <json.hpp>
#include <string>

using ThreadDispatchQueue = ThreadEventDispatcher<std::string, std::function<void(std::queue<std::string>&)>>;

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
     * @param logFunction Callback function to be called when trying to log a message.
     * @param timeout Server selector time interval.
     * @param workingThreads Number of working threads used by the dispatcher. More than one results in an unordered
     * processing.
     */
    explicit IndexerConnector(const nlohmann::json& config,
                              const std::function<void(const int,
                                                       const std::string&,
                                                       const std::string&,
                                                       const int,
                                                       const std::string&,
                                                       const std::string&,
                                                       va_list)>& logFunction = {},
                              const uint32_t& timeout = DEFAULT_INTERVAL,
                              const uint8_t workingThreads = 1);

    ~IndexerConnector();

    /**
     * @brief Publish a message into the queue map.
     *
     * @param message Message to be published.
     */
    void publish(const std::string& message);
};

#endif // _INDEXER_CONNECTOR_HPP
