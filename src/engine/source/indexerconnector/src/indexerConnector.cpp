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

#include "indexerConnector/indexerConnector.hpp"
#include "HTTPRequest.hpp"
#include "base/logging.hpp"
#include "secureCommunication.hpp"
#include "serverSelector.hpp"
#include <fstream>

constexpr auto INDEXER_COLUMN {"indexer"};
constexpr auto USER_KEY {"username"};
constexpr auto PASSWORD_KEY {"password"};
constexpr auto ELEMENTS_PER_BULK {1000};

// Single thread in case the events needs to be processed in order.
constexpr auto SINGLE_ORDERED_DISPATCHING = 1;
constexpr auto DATABASE_BASE_PATH = "queue/indexer/";

static void initConfiguration(SecureCommunication& secureCommunication, const nlohmann::json& config)
{
    std::string caRootCertificate;
    std::string sslCertificate;
    std::string sslKey;
    std::string username;
    std::string password;

    if (config.contains("ssl"))
    {
        if (config.at("ssl").contains("certificate_authorities")
            && !config.at("ssl").at("certificate_authorities").empty())
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

    if (config.contains("username"))
    {
        username = config.at("username");
    }

    if (config.contains("password"))
    {
        password = config.at("password");
    }

    if (username.empty() && password.empty())
    {
        username = "admin";
        password = "admin";
        LOG_WARNING("No username and password found in the configuration, using default values.");
    }

    if (username.empty())
    {
        username = "admin";
        LOG_WARNING("No username found in the configuration, using default value.");
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

IndexerConnector::IndexerConnector(const nlohmann::json& config, const uint32_t& timeout, const uint8_t workingThreads)
{
    // Get index name.
    m_indexName = config.at("name").get_ref<const std::string&>();

    if (base::utils::string::haveUpperCaseCharacters(m_indexName))
    {
        throw std::invalid_argument("Index name must be lowercase.");
    }

    auto secureCommunication = SecureCommunication::builder();
    initConfiguration(secureCommunication, config);

    // Initialize publisher.
    auto selector {std::make_shared<ServerSelector>(config.at("hosts"), timeout, secureCommunication)};

    // Validate threads number
    if (workingThreads <= 0)
    {
        LOG_DEBUG("Invalid number of working threads, using default value.");
    }

    m_dispatcher = std::make_unique<ThreadDispatchQueue>(
        [this,
         selector,
         secureCommunication,
         getLambdaName = logging::getLambdaName(__FUNCTION__, "processEventQueue")](std::queue<std::string>& dataQueue)
        {
            std::scoped_lock lock(m_syncMutex);

            if (m_stopping.load())
            {
                const auto functionName = getLambdaName.c_str();
                LOG_DEBUG_L(functionName, "IndexerConnector is stopping, event processing will be skipped.");
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

                if (parsedData.at("operation").get_ref<const std::string&>().compare("DELETED") == 0)
                {
                    builderBulkDelete(bulkData, id, m_indexName);
                }
                else
                {
                    const auto dataString = parsedData.at("data").dump();
                    builderBulkIndex(bulkData, id, m_indexName, dataString);
                }
            }

            if (!bulkData.empty())
            {
                // Process data.
                HTTPRequest::instance().post(
                    {HttpURL(url), bulkData, secureCommunication},
                    {[getLambdaName = logging::getLambdaName(__FUNCTION__, "handleSuccessfulPostResponse")](
                         const std::string& response)
                     {
                         const auto functionName = getLambdaName.c_str();
                         LOG_DEBUG_L(functionName, "Response: %s", response.c_str());
                     },
                     [getLambdaName = logging::getLambdaName(__FUNCTION__, "handlePostResponseError")](
                         const std::string& error, const long statusCode)
                     {
                         const auto functionName = getLambdaName.c_str();
                         LOG_ERROR_L(functionName, "%s, status code: %ld.", error.c_str(), statusCode);
                         throw std::runtime_error(error);
                     }});
            }
        },
        DATABASE_BASE_PATH + m_indexName,
        ELEMENTS_PER_BULK,
        workingThreads <= 0 ? SINGLE_ORDERED_DISPATCHING : workingThreads);
}

IndexerConnector::~IndexerConnector()
{
    m_stopping.store(true);
    m_cv.notify_all();

    m_dispatcher->cancel();
}

void IndexerConnector::publish(const std::string& message)
{
    m_dispatcher->push(message);
}
