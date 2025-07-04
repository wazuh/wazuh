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

#include "secureCommunication.hpp"
#include <atomic>
#include <condition_variable>
#include <json.hpp>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>

#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

class ServerSelector;
static constexpr auto DEFAULT_INTERVAL = 60u;
static constexpr auto IC_NAME {"indexer-connector"};

class IndexerConnectorException : public std::runtime_error
{
public:
    explicit IndexerConnectorException(const std::string& what)
        : std::runtime_error(what)
    {
    }
};

/**
 * @brief IndexerConnector class.
 *
 */
class EXPORTED IndexerConnectorSync final
{
    /**
     * @brief Initialized status.
     *
     */
    SecureCommunication m_secureCommunication;
    std::unique_ptr<ServerSelector> m_selector;
    std::string m_bulkData;
    std::map<std::string, nlohmann::json> m_deleteByQuery;
    std::vector<std::function<void()>> m_notify;
    std::chrono::steady_clock::time_point m_lastBulkTime;
    std::condition_variable m_cv;
    std::mutex m_mutex;
    std::thread m_bulkThread;
    std::atomic<bool> m_stopping;
    std::vector<size_t> m_boundaries;

    void processBulk();
    void splitAndProcessBulk();
    void processBulkChunk(std::string_view data, std::span<const size_t> boundaries);

public:
    /**
     * @brief Class constructor that initializes the publisher.
     *
     * @param config Indexer configuration, including database_path and servers.
     * @param logFunction Callback function to be called when trying to log a message.
     * @param timeout Server selector time interval.
     */
    explicit IndexerConnectorSync(const nlohmann::json& config,
                                  const std::function<void(const int,
                                                           const std::string&,
                                                           const std::string&,
                                                           const int,
                                                           const std::string&,
                                                           const std::string&,
                                                           va_list)>& logFunction = {});

    ~IndexerConnectorSync();

    // /**
    //  * @brief Publish a message into the queue map with 413 error handling.
    //  *
    //  * @param message Message to be published.
    //  * @param initialOperationCount Initial number of operations in the message.
    //  */
    // void bulk(const std::string& message, size_t initialOperationCount);

    /**
     * @brief Publish a message into the queue map.
     *
     * @param message Message to be published.
     * @param index Index name.
     */
    void deleteByQuery(const std::string& index, const std::string& agentId);

    /**
     * @brief Bulk delete.
     *
     * @param id ID.
     * @param index Index name.
     */
    void bulkDelete(std::string_view id, std::string_view index);

    /**
     * @brief Bulk index.
     *
     * @param id ID.
     * @param index Index name.
     * @param data Data.
     */
    void bulkIndex(std::string_view id, std::string_view index, std::string_view data);
};

/**
 * @brief IndexerConnectorAsync class.
 *
 */
class IndexerConnectorAsync final
{
    SecureCommunication m_secureCommunication;
    std::unique_ptr<ServerSelector> m_selector;

public:
    /**
     * @brief Class constructor that initializes the publisher.
     *
     * @param config Indexer configuration, including database_path and servers.
     * @param logFunction Callback function to be called when trying to log a message.
     * @param timeout Server selector time interval.
     */
    explicit IndexerConnectorAsync(const nlohmann::json& config,
                                   const std::function<void(const int,
                                                            const std::string&,
                                                            const std::string&,
                                                            const int,
                                                            const std::string&,
                                                            const std::string&,
                                                            va_list)>& logFunction = {});

    ~IndexerConnectorAsync();

    /**
     * @brief Publish a message into the queue map.
     *
     * @param message Message to be published.
     */
    void publish(const char* message, size_t size);
};

#endif // _INDEXER_CONNECTOR_HPP
