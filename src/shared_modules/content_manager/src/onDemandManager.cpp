/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "onDemandManager.hpp"
#include "../sharedDefs.hpp"
#include "actionOrchestrator.hpp"
#include "contentManager.hpp"
#include "external/nlohmann/json.hpp"
#include <filesystem>
#include <utility>

/**
 * @brief Start the server
 */
void OnDemandManager::startServer()
{
    m_serverThread = std::thread(
        [&]()
        {
            // Capture string by value
            m_server.Get("/ondemand/(.*)",
                         [&](const httplib::Request& req, httplib::Response& res)
                         {
                             std::shared_lock<std::shared_mutex> lock {m_mutex};

                             try
                             {
                                 // Default value. Do not replace current offset
                                 int offset = -1;

                                 if (auto offset_param = req.params.find("offset"); offset_param != req.params.end())
                                 {
                                     offset = std::stoi(offset_param->second);
                                 }

                                 if (offset != -1 && offset != 0)
                                 {
                                     throw std::invalid_argument("Invalid offset value. Use instead:\n"
                                                                 "offset=0 (Start with offset 0)\n"
                                                                 "offset=-1 (Do not replace current offset)");
                                 }

                                 const auto& it {m_endpoints.find(req.matches[1].str())};
                                 if (it != m_endpoints.end())
                                 {
                                     it->second(ActionOrchestrator::UpdateData::createContentUpdateData(offset));
                                     res.status = 200;
                                 }
                                 else
                                 {
                                     res.status = 404;
                                 }
                             }
                             catch (const std::exception& e)
                             {
                                 res.status = 400;
                                 res.body = e.what();
                             }
                         });

            // Capture offset PUT requests. These requests are used to update the offset from the database.
            m_server.Put("/offset",
                         [&](const httplib::Request& req, httplib::Response& res)
                         {
                             std::shared_lock<std::shared_mutex> lock {m_mutex};

                             try
                             {
                                 const auto requestData = nlohmann::json::parse(req.body);
                                 const auto offset {requestData.at("offset").get<int>()};
                                 const auto& topicName {requestData.at("topicName").get_ref<const std::string&>()};

                                 if (0 > offset)
                                 {
                                     throw std::invalid_argument(
                                         "Invalid offset value: Should be greater or equal than zero");
                                 }

                                 if (const auto& it {m_endpoints.find(topicName)}; it != m_endpoints.end())
                                 {
                                     it->second(ActionOrchestrator::UpdateData::createOffsetUpdateData(offset));
                                     res.status = 200;
                                     res.body = "Offset update processed successfully";
                                 }
                                 else
                                 {
                                     res.status = 404;
                                     res.body = "Topic '" + topicName + "' not found";
                                 }
                             }
                             catch (const std::exception& e)
                             {
                                 res.status = 400;
                                 res.body = e.what();
                             }
                         });

            // Capture hash PUT requests. These requests are used to update the file hash from the database.
            m_server.Put("/hash",
                         [&](const httplib::Request& req, httplib::Response& res)
                         {
                             std::shared_lock<std::shared_mutex> lock {m_mutex};

                             try
                             {
                                 const auto requestData = nlohmann::json::parse(req.body);
                                 const auto& fileHash {requestData.at("hash").get_ref<const std::string&>()};
                                 const auto& topicName {requestData.at("topicName").get_ref<const std::string&>()};

                                 if (fileHash.empty())
                                 {
                                     throw std::invalid_argument {"Invalid hash value: The hash is empty"};
                                 }

                                 if (const auto& it {m_endpoints.find(topicName)}; it != m_endpoints.end())
                                 {
                                     it->second(ActionOrchestrator::UpdateData::createHashUpdateData(fileHash));
                                     res.status = 200;
                                     res.body = "File hash update processed successfully";
                                 }
                                 else
                                 {
                                     res.status = 404;
                                     res.body = "Topic '" + topicName + "' not found";
                                 }
                             }
                             catch (const std::exception& e)
                             {
                                 res.status = 400;
                                 res.body = e.what();
                             }
                         });

            m_server.set_address_family(AF_UNIX);

            std::filesystem::remove(ONDEMAND_SOCK);
            std::filesystem::path path {ONDEMAND_SOCK};
            std::filesystem::create_directories(path.parent_path());

            m_runningTrigger = m_server.listen(ONDEMAND_SOCK, true);
        });

    // Spin lock until server is ready
    while (!m_server.is_running() && m_runningTrigger)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

/**
 * @brief Stop the server
 */

void OnDemandManager::stopServer()
{
    m_server.stop();
    if (m_serverThread.joinable())
    {
        m_serverThread.join();
    }
    logDebug1(WM_CONTENTUPDATER, "Server stopped");
}

void OnDemandManager::addEndpoint(const std::string& endpoint, std::function<void(ActionOrchestrator::UpdateData)> func)
{
    std::unique_lock<std::shared_mutex> lock {m_mutex};
    // Check if the endpoint already exists
    if (m_endpoints.find(endpoint) != m_endpoints.end())
    {
        throw std::runtime_error("Endpoint already exists");
    }

    // Start server if it's not running
    if (!m_server.is_running())
    {
        startServer();
    }
    m_endpoints[endpoint] = std::move(func);
}

void OnDemandManager::removeEndpoint(const std::string& endpoint)
{
    std::unique_lock<std::shared_mutex> lock {m_mutex};
    m_endpoints.erase(endpoint);
    // Stop server if there are no more endpoints
    if (m_endpoints.empty())
    {
        stopServer();
    }
}

/**
 * @brief Clear all endpoints and stop the server
 */
void OnDemandManager::clearEndpoints()
{
    std::unique_lock<std::shared_mutex> lock {m_mutex};
    m_endpoints.clear();
    stopServer();
}
