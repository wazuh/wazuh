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

std::unordered_map<IndexerConnector*, std::unique_ptr<ThreadDispatchQueue>> QUEUE_MAP;
constexpr auto DATABASE_WORKERS = 1;

IndexerConnector::IndexerConnector(const nlohmann::json& config)
{
    // Initialize publisher.
    m_selector = std::make_unique<RoundRobinSelector<std::string>>(config.at("servers"));
    QUEUE_MAP[this] = std::make_unique<ThreadDispatchQueue>(
        [&](std::queue<std::string>& dataQueue)
        {
            try
            {
                auto server = m_selector->getNext();
                auto url = server;
                nlohmann::json bulkData;
                url.append("/_bulk");

                while (!dataQueue.empty())
                {
                    auto data = dataQueue.front();
                    dataQueue.pop();
                    auto parsedData = nlohmann::json::parse(data);
                    auto index = parsedData.at("type");
                    auto id = parsedData.at("id").get_ref<const std::string&>();

                    if (parsedData.at("operation").get_ref<const std::string&>().compare("DELETED") == 0)
                    {
                        bulkData.push_back(nlohmann::json({{"delete", {{"_index", index}, {"_id", id}}}}));
                    }
                    else
                    {
                        bulkData.push_back(nlohmann::json({{"index", {{"_index", index}, {"_id", id}}}}));
                        bulkData.push_back(parsedData.at("data"));
                    }
                }

                // Process data.
                HTTPRequest::instance().post(
                    HttpURL(url),
                    bulkData,
                    [&](const std::string& response) { std::cout << "Response: " << response << std::endl; },
                    [&](const std::string& error) { std::cout << "Error: " << error << std::endl; });
            }
            catch (const std::exception& e)
            {
                std::cout << "Error: " << e.what() << std::endl;
            }
        },
        config.at("databasePath"),
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

