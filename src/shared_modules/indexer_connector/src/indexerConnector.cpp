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

#include "indexerConnector.hpp"
#include "HTTPRequest.hpp"
#include "keyStore.hpp"
#include "loggerHelper.h"
#include "secureCommunication.hpp"
#include "serverSelector.hpp"
#include <fstream>

constexpr auto NOT_USED {-1};
constexpr auto INDEXER_COLUMN {"indexer"};
constexpr auto USER_KEY {"username"};
constexpr auto PASSWORD_KEY {"password"};
constexpr auto ELEMENTS_PER_BULK {1000};

namespace Log
{
    std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>
        GLOBAL_LOG_FUNCTION;
};
constexpr auto IC_NAME {"indexer-connector"};
constexpr auto MAX_WAIT_TIME {60};
constexpr auto START_TIME {1};
constexpr auto DOUBLE_FACTOR {2};

// Single thread because the events needs to be processed in order.
constexpr auto DATABASE_WORKERS = 1;
constexpr auto DATABASE_BASE_PATH = "queue/indexer/";

// Sync configuration
constexpr auto SYNC_WORKERS = 1;
constexpr auto SYNC_QUEUE_LIMIT = 4096;

// Abuse control
constexpr auto MINIMAL_SYNC_TIME {30}; // In minutes

static void initConfiguration(SecureCommunication& secureCommunication, const nlohmann::json& config)
{
    std::string caRootCertificate;
    std::string sslCertificate;
    std::string sslKey;
    std::string username;
    std::string password;

    if (config.contains("ssl"))
    {
        if (config.at("ssl").contains("certificate_authorities") &&
            !config.at("ssl").at("certificate_authorities").empty())
        {
            caRootCertificate = config.at("ssl").at("certificate_authorities").front().get_ref<const std::string&>();
        }

        if (config.at("ssl").contains("certificate"))
        {
            sslCertificate = config.at("ssl").at("certificate").get_ref<const std::string&>();
        }

        if (config.at("ssl").contains("key"))
        {
            sslKey = config.at("ssl").at("key").get_ref<const std::string&>();
        }
    }

    Keystore::get(INDEXER_COLUMN, USER_KEY, username);
    Keystore::get(INDEXER_COLUMN, PASSWORD_KEY, password);

    if (username.empty() && password.empty())
    {
        username = "admin";
        password = "admin";
        logWarn(IC_NAME, "No username and password found in the keystore, using default values.");
    }

    if (username.empty())
    {
        username = "admin";
        logWarn(IC_NAME, "No username found in the keystore, using default value.");
    }

    secureCommunication.basicAuth(username + ":" + password)
        .sslCertificate(sslCertificate)
        .sslKey(sslKey)
        .caRootCertificate(caRootCertificate);
}

static void builderBulkDelete(std::string& bulkData, std::string_view id, std::string_view index)
{
    bulkData.append(R"({"delete":{"_index":")");
    bulkData.append(index);
    bulkData.append(R"(","_id":")");
    bulkData.append(id);
    bulkData.append(R"("}})");
    bulkData.append("\n");
}

static void builderBulkIndex(std::string& bulkData, std::string_view id, std::string_view index, std::string_view data)
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

bool IndexerConnector::abuseControl(const std::string& agentId)
{
    const auto currentTime = std::chrono::system_clock::now();
    // If the agent is in the map, check if the last sync was less than MINIMAL_SYNC_TIME minutes ago.
    if (const auto lastSync = m_lastSync.find(agentId); lastSync != m_lastSync.end())
    {
        const auto diff = std::chrono::duration_cast<std::chrono::minutes>(currentTime - lastSync->second);
        // If the last sync was less than MINIMAL_SYNC_TIME minutes ago, return true.
        if (diff.count() < MINIMAL_SYNC_TIME)
        {
            logDebug2(IC_NAME, "Agent '%s' sync omitted due to abuse control.", agentId.c_str());
            return true;
        }
    }
    // If the agent is not in the map, add it to the map with the current time.
    m_lastSync[agentId] = currentTime;
    return false;
}

nlohmann::json IndexerConnector::getAgentDocumentsIds(const std::string& url,
                                                      const std::string& agentId,
                                                      const SecureCommunication& secureCommunication) const
{
    nlohmann::json postData;
    nlohmann::json responseJson;
    constexpr auto ELEMENTS_PER_QUERY {10000}; // The max value for queries is 10000 in the wazuh-indexer.

    postData["query"]["match"]["agent.id"] = agentId;
    postData["size"] = ELEMENTS_PER_QUERY;
    postData["_source"] = nlohmann::json::array({"_id"});

    HTTPRequest::instance().post(
        HttpURL(url + "/" + m_indexName + "/_search?scroll=1m"),
        postData.dump(),
        [&responseJson](const std::string& response) { responseJson = nlohmann::json::parse(response); },
        [](const std::string& error, const long) { throw std::runtime_error(error); },
        "",
        DEFAULT_HEADERS,
        secureCommunication);

    // If the response have more than ELEMENTS_PER_QUERY elements, we need to scroll.
    if (responseJson.at("hits").at("total").at("value").get<int>() > ELEMENTS_PER_QUERY)
    {
        const auto& scrollId = responseJson.at("_scroll_id").get_ref<const std::string&>();
        const auto scrollUrl = url + "/_search/scroll";
        const auto scrollData = R"({"scroll":"1m","scroll_id":")" + scrollId + "\"}";

        while (responseJson.at("hits").at("hits").size() < responseJson.at("hits").at("total").at("value").get<int>())
        {
            HTTPRequest::instance().post(
                HttpURL(scrollUrl),
                scrollData,
                [&responseJson](const std::string& response)
                {
                    auto newResponse = nlohmann::json::parse(response);
                    for (const auto& hit : newResponse.at("hits").at("hits"))
                    {
                        responseJson.at("hits").at("hits").push_back(hit);
                    }
                },
                [](const std::string& error, const long) { throw std::runtime_error(error); },
                "",
                DEFAULT_HEADERS,
                secureCommunication);
        }
    }

    return responseJson;
}

void IndexerConnector::diff(const nlohmann::json& responseJson,
                            const std::string& agentId,
                            const SecureCommunication& secureCommunication,
                            const std::shared_ptr<ServerSelector>& selector)
{
    std::vector<std::pair<std::string, bool>> status;
    std::vector<std::pair<std::string, bool>> actions;

    // Move elements to vector.
    for (const auto& hit : responseJson.at("hits").at("hits"))
    {
        if (hit.contains("_id"))
        {
            status.emplace_back(hit.at("_id").get_ref<const std::string&>(), false);
        }
    }

    // Iterate over the database and check if the element is in the status vector.
    for (const auto& [key, value] : m_db->seek(agentId))
    {
        bool found {false};
        for (auto& [id, data] : status)
        {
            // If the element is found, mark it as found.
            if (key.compare(id) == 0)
            {
                data = true;
                found = true;
                break;
            }
        }

        // If the element is not found, add it to the actions vector. This element will be added to the indexer.
        if (!found)
        {
            actions.emplace_back(key, false);
        }
    }

    // Iterate over the status vector and check if the element is marked as not found.
    // This means that the element is in the indexer but not in the database. To solve this, the element will be deleted
    for (const auto& [id, data] : status)
    {
        if (!data)
        {
            actions.emplace_back(id, true);
        }
    }

    auto url = selector->getNext();
    url.append("/_bulk?refresh=wait_for");

    std::string bulkData;
    // Iterate over the actions vector and build the bulk data.
    // If the element is marked as deleted, the element will be deleted from the indexer.
    // If the element is not marked as deleted, the element will be added to the indexer.
    for (const auto& [id, deleted] : actions)
    {
        if (deleted)
        {
            builderBulkDelete(bulkData, id, m_indexName);
        }
        else
        {
            std::string data;
            if (!m_db->get(id, data))
            {
                throw std::runtime_error("Failed to get data from the database.");
            }
            builderBulkIndex(bulkData, id, m_indexName, data);
        }
    }

    if (!bulkData.empty())
    {
        HTTPRequest::instance().post(
            HttpURL(url),
            bulkData,
            [](const std::string& response) { logDebug2(IC_NAME, "Response: %s", response.c_str()); },
            [](const std::string& error, const long statusCode) { throw std::runtime_error(error); },
            "",
            DEFAULT_HEADERS,
            secureCommunication);
    }
}

IndexerConnector::IndexerConnector(
    const nlohmann::json& config,
    const std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>&
        logFunction,
    const uint32_t& timeout)
{
    if (logFunction)
    {
        Log::assignLogFunction(logFunction);
    }

    // Get index name.
    m_indexName = config.at("name").get_ref<const std::string&>();

    if (Utils::haveUpperCaseCharacters(m_indexName))
    {
        throw std::runtime_error("Index name must be lowercase.");
    }

    m_db = std::make_unique<Utils::RocksDBWrapper>(std::string(DATABASE_BASE_PATH) + "db/" + m_indexName);

    auto secureCommunication = SecureCommunication::builder();
    initConfiguration(secureCommunication, config);

    // Initialize publisher.
    auto selector {std::make_shared<ServerSelector>(config.at("hosts"), timeout, secureCommunication)};

    m_dispatcher = std::make_unique<ThreadDispatchQueue>(
        [this, selector, secureCommunication](std::queue<std::string>& dataQueue)
        {
            std::scoped_lock lock(m_syncMutex);

            if (!m_initialized && m_initializeThread.joinable())
            {
                logDebug2(IC_NAME, "Waiting for initialization thread to process events.");
                m_initializeThread.join();
            }

            if (m_stopping.load())
            {
                logDebug2(IC_NAME, "IndexerConnector is stopping, event processing will be skipped.");
                throw std::runtime_error("IndexerConnector is stopping, event processing will be skipped.");
            }

            auto url = selector->getNext();
            std::string bulkData;
            url.append("/_bulk?refresh=wait_for");

            while (!dataQueue.empty())
            {
                auto data = dataQueue.front();
                dataQueue.pop();
                auto parsedData = nlohmann::json::parse(data);
                const auto& id = parsedData.at("id").get_ref<const std::string&>();
                // If the element should not be indexed, only delete it from the sync database.
                const bool noIndex = parsedData.contains("no-index") ? parsedData.at("no-index").get<bool>() : false;

                if (parsedData.at("operation").get_ref<const std::string&>().compare("DELETED") == 0)
                {
                    if (!noIndex)
                    {
                        builderBulkDelete(bulkData, id, m_indexName);
                    }
                    m_db->delete_(id);
                }
                else
                {
                    const auto dataString = parsedData.at("data").dump();
                    if (!noIndex)
                    {
                        builderBulkIndex(bulkData, id, m_indexName, dataString);
                    }
                    m_db->put(id, dataString);
                }
            }

            if (!bulkData.empty())
            {
                // Process data.
                HTTPRequest::instance().post(
                    HttpURL(url),
                    bulkData,
                    [](const std::string& response) { logDebug2(IC_NAME, "Response: %s", response.c_str()); },
                    [](const std::string& error, const long statusCode)
                    {
                        logError(IC_NAME, "%s, status code: %ld.", error.c_str(), statusCode);
                        throw std::runtime_error(error);
                    },
                    "",
                    DEFAULT_HEADERS,
                    secureCommunication);
            }
        },
        DATABASE_BASE_PATH + m_indexName,
        ELEMENTS_PER_BULK);

    m_syncQueue = std::make_unique<ThreadSyncQueue>(
        // coverity[missing_lock]
        [this, selector, secureCommunication](const std::string& agentId)
        {
            try
            {
                std::scoped_lock lock(m_syncMutex);
                if (!abuseControl(agentId))
                {
                    logDebug2(IC_NAME, "Syncing agent '%s' with the indexer.", agentId.c_str());
                    diff(getAgentDocumentsIds(selector->getNext(), agentId, secureCommunication),
                         agentId,
                         secureCommunication,
                         selector);
                }
            }
            catch (const std::exception& e)
            {
                logWarn(IC_NAME, "Failed to sync agent '%s' with the indexer.", agentId.c_str());
                logDebug1(IC_NAME, "Error: %s", e.what());
            }
        },
        SYNC_WORKERS,
        SYNC_QUEUE_LIMIT);
}

IndexerConnector::~IndexerConnector()
{
    m_stopping.store(true);
    m_cv.notify_all();

    m_dispatcher->cancel();

    if (m_initializeThread.joinable())
    {
        m_initializeThread.join();
    }
}

void IndexerConnector::publish(const std::string& message)
{
    m_dispatcher->push(message);
}

void IndexerConnector::sync(const std::string& agentId)
{
    m_syncQueue->push(agentId);
}
