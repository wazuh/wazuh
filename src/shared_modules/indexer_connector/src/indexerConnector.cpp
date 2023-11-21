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
#include "secureCommunication.hpp"
#include "shared_modules/indexer_connector/src/serverSelector.hpp"
#include <fstream>

// TODO: remove the LCOV flags when the implementation of this class is completed
// LCOV_EXCL_START
std::unordered_map<IndexerConnector*, std::unique_ptr<ThreadDispatchQueue>> QUEUE_MAP;
constexpr auto DATABASE_WORKERS = 1;
constexpr auto DATABASE_BASE_PATH = "queue/indexer/";

IndexerConnector::IndexerConnector(const nlohmann::json& config, const std::string& templatePath)
{
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
        throw std::runtime_error("Could not open template file.");
    }
    nlohmann::json templateData = nlohmann::json::parse(templateFile);

    // Initialize publisher.
    auto selector = std::make_shared<ServerSelector>(config.at("hosts"), INTERVAL, secureCommunication);

    // Initialize index template.
    HTTPRequest::instance().put(
        HttpURL(selector->getNext() + "/_index_template/" + indexName + "_template"),
        templateData,
        [&](const std::string& response) {},
        [&](const std::string& error, const long statusCode)
        { throw std::runtime_error("Status:" + std::to_string(statusCode) + " - Error: " + error); },
        "",
        DEFAULT_HEADERS,
        secureCommunication);

    QUEUE_MAP[this] = std::make_unique<ThreadDispatchQueue>(
        [selector, indexName, secureCommunication](std::queue<std::string>& dataQueue)
        {
            try
            {
                auto url = selector->getNext();
                std::string bulkData;
                url.append("/_bulk");

                while (!dataQueue.empty())
                {
                    auto data = dataQueue.front();
                    dataQueue.pop();
                    auto parsedData = nlohmann::json::parse(data);
                    auto id = parsedData.at("id").get_ref<const std::string&>();

                    if (parsedData.at("operation").get_ref<const std::string&>().compare("DELETED") == 0)
                    {
                        bulkData.append(nlohmann::json({{"delete", {{"_index", indexName}, {"_id", id}}}}).dump());
                    }
                    else
                    {
                        bulkData.append(nlohmann::json({{"index", {{"_index", indexName}, {"_id", id}}}}).dump());
                        bulkData.append("\n");
                        bulkData.append(parsedData.at("data").dump());
                        bulkData.append("\n");
                    }
                }

                // Process data.
                HTTPRequest::instance().post(
                    HttpURL(url),
                    bulkData,
                    [&](const std::string& response) {},
                    [&](const std::string& error, const long statusCode)
                    { std::cout << "Status:" << statusCode << " - Error: " << error << std::endl; },
                    "",
                    DEFAULT_HEADERS,
                    secureCommunication);
            }
            catch (const std::exception& e)
            {
                std::cout << "Error: " << e.what() << std::endl;
            }
        },
        DATABASE_BASE_PATH + indexName,
        DATABASE_WORKERS);
}

IndexerConnector::~IndexerConnector()
{
    QUEUE_MAP.erase(this);
}

void IndexerConnector::publish(const std::string& message)
{
    QUEUE_MAP[this]->push(message);
}
// LCOV_EXCL_STOP
