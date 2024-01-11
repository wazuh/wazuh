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
#include "loggerHelper.h"
#include "secureCommunication.hpp"
#include "serverSelector.hpp"
#include <fstream>

constexpr auto NOT_USED {-1};

namespace Log
{
    std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>
        GLOBAL_LOG_FUNCTION;
};
constexpr auto IC_NAME {"indexer-connector"};
constexpr auto MAX_WAIT_TIME {60};

std::unordered_map<IndexerConnector*, std::unique_ptr<ThreadDispatchQueue>> QUEUE_MAP;

// Single thread because the events needs to be processed in order.
constexpr auto DATABASE_WORKERS = 1;
constexpr auto DATABASE_BASE_PATH = "queue/indexer/";

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
    auto indexName {config.at("name").get_ref<const std::string&>()};

    std::string caRootCertificate;
    std::string sslCertificate;
    std::string sslKey;
    std::string username;
    std::string password;

    auto secureCommunication = SecureCommunication::builder();

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

    if (config.contains("username") && config.contains("password"))
    {
        username = config.at("username").get_ref<const std::string&>();
        password = config.at("password").get_ref<const std::string&>();
    }

    secureCommunication.basicAuth(username + ":" + password)
        .sslCertificate(sslCertificate)
        .sslKey(sslKey)
        .caRootCertificate(caRootCertificate);

    // Read template file.
    std::ifstream templateFile(templatePath);
    if (!templateFile.is_open())
    {
        throw std::runtime_error("Could not open template file: " + templatePath);
    }
    nlohmann::json templateData = nlohmann::json::parse(templateFile);

    // Initialize publisher.
    auto selector {std::make_shared<ServerSelector>(config.at("hosts"), timeout, secureCommunication)};

    QUEUE_MAP[this] = std::make_unique<ThreadDispatchQueue>(
        [=](std::queue<std::string>& dataQueue)
        {
            try
            {
                if (!m_initialized && m_initializeThread.joinable())
                {
                    logDebug2(IC_NAME, "Waiting for initialization thread to process events.");
                    m_initializeThread.join();
                }

                if (m_stopping.load())
                {
                    logDebug2(IC_NAME, "IndexerConnector is stopping, event processing will be skipped.");
                    return;
                }

                auto url = selector->getNext();
                std::string bulkData;
                url.append("/_bulk");

                while (!dataQueue.empty())
                {
                    auto data = dataQueue.front();
                    dataQueue.pop();
                    auto parsedData = nlohmann::json::parse(data);
                    const auto& id = parsedData.at("id").get_ref<const std::string&>();

                    if (parsedData.at("operation").get_ref<const std::string&>().compare("DELETED") == 0)
                    {
                        bulkData.append(R"({"delete":{"_index":")");
                        bulkData.append(indexName);
                        bulkData.append(R"(","_id":")");
                        bulkData.append(id);
                        bulkData.append(R"("}})");
                        bulkData.append("\n");
                    }
                    else
                    {
                        bulkData.append(R"({"index":{"_index":")");
                        bulkData.append(indexName);
                        bulkData.append(R"(","_id":")");
                        bulkData.append(id);
                        bulkData.append(R"("}})");
                        bulkData.append("\n");
                        bulkData.append(parsedData.at("data").dump());
                        bulkData.append("\n");
                    }
                }
                // Process data.
                HTTPRequest::instance().post(
                    HttpURL(url),
                    bulkData,
                    [&](const std::string& response) { logDebug2(IC_NAME, "Response: %s", response.c_str()); },
                    [&](const std::string& error, const long statusCode)
                    {
                        // TODO: Need to handle the case when the index is not created yet, to avoid losing data.
                        logError(IC_NAME, "%s, status code: %ld", error.c_str(), statusCode);
                    },
                    "",
                    DEFAULT_HEADERS,
                    secureCommunication);
            }
            catch (const std::exception& e)
            {
                logError(IC_NAME, "%s", e.what());
            }
        },
        DATABASE_BASE_PATH + indexName,
        ELEMENTS_PER_BULK,
        DATABASE_WORKERS);

    m_initializeThread = std::thread(
        [=]()
        {
            auto sleepTime = std::chrono::seconds(1);
            std::unique_lock<std::mutex> lock(m_mutex);
            do
            {
                try
                {
                    sleepTime *= 2;
                    if (sleepTime.count() > MAX_WAIT_TIME)
                    {
                        sleepTime = std::chrono::seconds(MAX_WAIT_TIME);
                    }

                    initialize(templateData, indexName, selector, secureCommunication);
                }
                catch (const std::exception& e)
                {
                    logWarn(IC_NAME,
                            "Error initializing IndexerConnector: %s, we will try again after %ld seconds.",
                            e.what(),
                            sleepTime.count());
                }
            } while (!m_initialized && !m_cv.wait_for(lock, sleepTime, [&]() { return m_stopping.load(); }));
        });
}

IndexerConnector::~IndexerConnector()
{
    m_stopping.store(true);
    m_cv.notify_all();

    QUEUE_MAP.erase(this);

    if (m_initializeThread.joinable())
    {
        m_initializeThread.join();
    }
}

void IndexerConnector::publish(const std::string& message)
{
    QUEUE_MAP[this]->push(message);
}

void IndexerConnector::initialize(const nlohmann::json& templateData,
                                  const std::string& indexName,
                                  const std::shared_ptr<ServerSelector>& selector,
                                  const SecureCommunication& secureCommunication)
{
    // Initialize template.
    HTTPRequest::instance().put(
        HttpURL(selector->getNext() + "/_index_template/" + indexName + "_template"),
        templateData,
        [&](const std::string& response) {},
        [&](const std::string& error, const long statusCode)
        {
            if (statusCode != 400)
            {
                throw std::runtime_error(statusCode != NOT_USED ? error + ": " + std::to_string(statusCode) : error);
            }
        },
        "",
        DEFAULT_HEADERS,
        secureCommunication);

    // Initialize Index.
    HTTPRequest::instance().put(
        HttpURL(selector->getNext() + "/" + indexName),
        templateData.at("template"),
        [&](const std::string& response) {},
        [&](const std::string& error, const long statusCode)
        {
            if (statusCode != 400)
            {
                throw std::runtime_error(statusCode != NOT_USED ? error + ": " + std::to_string(statusCode) : error);
            }
        },
        "",
        DEFAULT_HEADERS,
        secureCommunication);

    m_initialized = true;
    logInfo(IC_NAME, "IndexerConnector initialized.");
}
