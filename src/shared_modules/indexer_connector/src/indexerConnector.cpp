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
constexpr auto ELEMENTS_PER_BULK {50};

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
constexpr auto SYNC_WORKERS = 1;
constexpr auto SYNC_QUEUE_LIMIT = 4096;

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

void IndexerConnector::saveDocuments(const std::vector<Document>& documents)
{
    for (const auto& document : documents)
    {
        if (document.deleted)
        {
            m_db->delete_(document.id);
        }
        else
        {
            m_db->put(document.id, document.data);
        }
    }
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

IndexerConnector::IndexerConnector(
    const nlohmann::json& config,
    const std::string& templatePath,
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

    m_db = std::make_unique<Utils::RocksDBWrapper>(std::string(DATABASE_BASE_PATH) + "db/" + m_indexName);

    auto secureCommunication = SecureCommunication::builder();
    initConfiguration(secureCommunication, config);

    // Read template file.
    std::ifstream templateFile(templatePath);
    if (!templateFile.is_open())
    {
        throw std::runtime_error("Could not open template file: " + templatePath);
    }
    nlohmann::json templateData = nlohmann::json::parse(templateFile);

    // Initialize publisher.
    auto selector {std::make_shared<ServerSelector>(config.at("hosts"), timeout, secureCommunication)};

    m_dispatcher = std::make_unique<ThreadDispatchQueue>(
        [=](std::queue<std::string>& dataQueue)
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

            std::vector<Document> documents;
            while (!dataQueue.empty())
            {
                auto data = dataQueue.front();
                dataQueue.pop();
                auto parsedData = nlohmann::json::parse(data);
                const auto& id = parsedData.at("id").get_ref<const std::string&>();

                if (parsedData.at("operation").get_ref<const std::string&>().compare("DELETED") == 0)
                {
                    builderBulkDelete(bulkData, id, m_indexName);
                    documents.push_back({id, data, true});
                }
                else
                {
                    const auto dataString = parsedData.at("data").dump();
                    builderBulkIndex(bulkData, id, m_indexName, dataString);
                    documents.push_back({id, dataString, false});
                }
            }
            // Process data.
            HTTPRequest::instance().post(
                HttpURL(url),
                bulkData,
                [](const std::string& response) { logDebug2(IC_NAME, "Response: %s", response.c_str()); },
                [](const std::string& error, const long statusCode)
                {
                    logError(IC_NAME, "%s, status code: %ld", error.c_str(), statusCode);
                    throw std::runtime_error(error);
                },
                "",
                DEFAULT_HEADERS,
                secureCommunication);

            // Save documents to the database.
            saveDocuments(documents);
        },
        DATABASE_BASE_PATH + m_indexName,
        ELEMENTS_PER_BULK);

    m_syncQueue = std::make_unique<ThreadSyncQueue>(
        [=](const std::string& agentId)
        {
            try
            {
                std::scoped_lock lock(m_syncMutex);
                nlohmann::json responseJson;
                auto url = selector->getNext().append("/").append(m_indexName).append("/_search");

                nlohmann::json postData;

                // TODO: Add scroll support.
                postData["query"]["match"]["agent.id"] = agentId;
                postData["size"] = 10000;
                postData["_source"] = nlohmann::json::array({"_id"});

                logDebug2(IC_NAME, "Payload: %s", postData.dump().c_str());

                HTTPRequest::instance().post(
                    HttpURL(url),
                    postData.dump(),
                    [&responseJson](const std::string& response) { responseJson = nlohmann::json::parse(response); },
                    [](const std::string& error, const long) { throw std::runtime_error(error); },
                    "",
                    DEFAULT_HEADERS,
                    secureCommunication);
                logDebug2(IC_NAME, "Response: %s", responseJson.dump().c_str());
                diff(responseJson, agentId, secureCommunication, selector);
            }
            catch (const std::exception& e)
            {
                logError(IC_NAME, "Failed to sync agent '%s' with the indexer.", agentId.c_str());
                logDebug1(IC_NAME, "Error: %s", e.what());
            }
        },
        SYNC_WORKERS,
        SYNC_QUEUE_LIMIT);

    m_initializeThread = std::thread(
        // coverity[copy_constructor_call]
        [=]()
        {
            auto sleepTime = std::chrono::seconds(START_TIME);
            std::unique_lock lock(m_mutex);
            auto warningPrinted {false};
            do
            {
                try
                {
                    sleepTime *= DOUBLE_FACTOR;
                    if (sleepTime.count() > MAX_WAIT_TIME)
                    {
                        sleepTime = std::chrono::seconds(MAX_WAIT_TIME);
                    }

                    initialize(templateData, selector, secureCommunication);
                }
                catch (const std::exception& e)
                {
                    logDebug1(IC_NAME,
                              "Unable to initialize IndexerConnector for index '%s': %s. Retrying in %ld "
                              "seconds.",
                              m_indexName.c_str(),
                              e.what(),
                              sleepTime.count());
                    if (!warningPrinted)
                    {
                        logWarn(IC_NAME,
                                "IndexerConnector initialization failed for index '%s', retrying until the connection "
                                "is successful.",
                                m_indexName.c_str());
                        warningPrinted = true;
                    }
                }
            } while (!m_initialized && !m_cv.wait_for(lock, sleepTime, [this]() { return m_stopping.load(); }));
        });
}

IndexerConnector::~IndexerConnector()
{
    m_stopping.store(true);
    m_cv.notify_all();

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

void IndexerConnector::diff(nlohmann::json& responseJson,
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

    for (const auto& [key, value] : m_db->seek(agentId))
    {
        bool found {false};
        for (auto& [id, data] : status)
        {
            if (key.compare(id) == 0)
            {
                data = true;
                found = true;
                break;
            }
        }

        if (!found)
        {
            actions.emplace_back(key, false);
        }
    }

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
        logDebug2(IC_NAME, "Payload: %s", bulkData.c_str());
        HTTPRequest::instance().post(
            HttpURL(url),
            bulkData,
            [](const std::string& response) { logDebug2(IC_NAME, "Response: %s", response.c_str()); },
            [](const std::string& error, const long statusCode)
            {
                logError(IC_NAME, "%s, status code: %ld", error.c_str(), statusCode);
                throw std::runtime_error(error);
            },
            "",
            DEFAULT_HEADERS,
            secureCommunication);
    }
}

void IndexerConnector::initialize(const nlohmann::json& templateData,
                                  const std::shared_ptr<ServerSelector>& selector,
                                  const SecureCommunication& secureCommunication)
{
    // Define the error callback
    auto onError = [](const std::string& error, const long statusCode)
    {
        if (statusCode != 400) // Assuming 400 is for bad requests which we expect to handle differently
        {
            std::string errorMessage = error;
            if (statusCode != NOT_USED)
            {
                errorMessage += " (Status code: " + std::to_string(statusCode) + ")";
            }

            throw std::runtime_error(errorMessage);
        }
    };

    // Define the success callback
    auto onSuccess = [](const std::string&)
    {
        // Not used
    };

    // Initialize template.
    HTTPRequest::instance().put(HttpURL(selector->getNext() + "/_index_template/" + m_indexName + "_template"),
                                templateData,
                                onSuccess,
                                onError,
                                "",
                                DEFAULT_HEADERS,
                                secureCommunication);

    // Initialize Index.
    HTTPRequest::instance().put(HttpURL(selector->getNext() + "/" + m_indexName),
                                templateData.at("template"),
                                onSuccess,
                                onError,
                                "",
                                DEFAULT_HEADERS,
                                secureCommunication);

    m_initialized = true;
    logInfo(IC_NAME, "IndexerConnector initialized successfully for index: %s.", m_indexName.c_str());
}
