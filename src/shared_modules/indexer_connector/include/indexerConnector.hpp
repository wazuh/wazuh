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

#include "../src/serverSelector.hpp"
#include "HTTPRequest.hpp"
#include "keyStore.hpp"
#include "loggerHelper.h"
#include "secureCommunication.hpp"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <functional>
#include <grp.h>
#include <json.hpp>
#include <map>
#include <memory>
#include <mutex>
#include <pwd.h>
#include <stringHelper.h>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <vector>

#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

/**
 * @brief IndexerConnectorSync class - Facade for IndexerConnectorSyncImpl.
 *
 */
class EXPORTED IndexerConnectorSync final
{
private:
    class Impl;
    std::unique_ptr<Impl> m_impl;

public:
    /**
     * @brief Class constructor that initializes the publisher.
     *
     * @param config Indexer configuration, including database_path and servers.
     * @param logFunction Callback function to be called when trying to log a message.
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

    /**
     * @brief Flush the bulk data.
     */
    void flush();
};

// /**
//  * @brief IndexerConnectorAsync class.
//  *
//  */
// class IndexerConnectorAsync final
// {
//     SecureCommunication m_secureCommunication;
//     std::unique_ptr<ServerSelector> m_selector;

// public:
//     /**
//      * @brief Class constructor that initializes the publisher.
//      *
//      * @param config Indexer configuration, including database_path and servers.
//      * @param logFunction Callback function to be called when trying to log a message.
//      * @param timeout Server selector time interval.
//      */
//     explicit IndexerConnectorAsync(const nlohmann::json& config,
//                                    const std::function<void(const int,
//                                                             const std::string&,
//                                                             const std::string&,
//                                                             const int,
//                                                             const std::string&,
//                                                             const std::string&,
//                                                             va_list)>& logFunction = {});

//     ~IndexerConnectorAsync();

//     /**
//      * @brief Publish a message into the queue map.
//      *
//      * @param message Message to be published.
//      */
//     void publish(const char* message, size_t size);
// };

#endif // _INDEXER_CONNECTOR_HPP
