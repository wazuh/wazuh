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

IndexerConnector::IndexerConnector(const nlohmann::json& config)
{
    // Initialize publisher.
    m_selector = std::make_unique<RoundRobinSelector<std::string>>(config.at("servers"));
    QUEUE_MAP[this] = std::make_unique<ThreadDispatchQueue>(
        [&](const std::string& data)
        {
            auto parsedData = nlohmann::json::parse(data);
            auto server = m_selector->getNext();
            auto index = parsedData.at("type");
            auto url = server;
            url.append("/");
            url.append(index);
            url.append("/_doc");

            std::cout << "URL: " << url << std::endl;
            std::cout << "Data: " << parsedData.at("data").dump() << std::endl;
            // Process data.
            HTTPRequest::instance().post(
                HttpURL(url),
                parsedData.at("data"),
                [&](const std::string& response) { std::cout << "Response: " << response << std::endl; },
                [&](const std::string& error) { std::cout << "Error: " << error << std::endl; });
        },
        config.at("database_path"));
}

IndexerConnector::~IndexerConnector()
{
    QUEUE_MAP.erase(this);
}

void IndexerConnector::publish(const std::string& message)
{
    QUEUE_MAP[this]->push(message);
}

