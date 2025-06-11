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
#include <json.hpp>
#include <memory>
#include <stdexcept>
#include <string>

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

public:
    struct Builder final
    {
        static void bulkDelete(std::string& bulkData, std::string_view id, std::string_view index)
        {
            bulkData.append(R"({"delete":{"_index":")");
            bulkData.append(index);
            bulkData.append(R"(","_id":")");
            bulkData.append(id);
            bulkData.append(R"("}})");
            bulkData.append("\n");
        }

        static void deleteByQuery(nlohmann::json& bulkData, const std::string& agentId)
        {
            bulkData["query"]["bool"]["filter"]["terms"]["agent.id"].push_back(agentId);
        }

        static void bulkIndex(std::string& bulkData, std::string_view id, std::string_view index, std::string_view data)
        {
            bulkData.append(R"({"index":{"_index":")");
            bulkData.append(index);
            bulkData.append(R"(","_id":")");
            bulkData.append(id);
            bulkData.append(R"("}})");
            bulkData.append("\n");
            bulkData.append(data);
            bulkData.append("\n");
        }
    };
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

    /**
     * @brief Publish a message into the queue map.
     *
     * @param message Message to be published.
     */
    void bulk(const std::string& message);

    /**
     * @brief Publish a message into the queue map.
     *
     * @param message Message to be published.
     * @param index Index name.
     */
    void deleteByQuery(const std::string& message, const std::string& index);
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
