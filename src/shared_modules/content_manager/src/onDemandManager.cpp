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
#include <filesystem>
#include <utility>

constexpr auto SOCKET_PATH {"/tmp/wazuh-ondemand.sock"};

/**
 * @brief Start the server
 */
void OnDemandManager::startServer()
{
    std::atomic<bool> runningTrigger {true};
    m_serverThread = std::thread(
        [&]()
        {
            // Capture string by value
            m_server.Get("/ondemand/(.*)",
                         [&](const httplib::Request& req, httplib::Response& res)
                         {
                             std::shared_lock<std::shared_mutex> lock {m_mutex};
                             const auto& it {m_endpoints.find(req.matches[1].str())};
                             if (it != m_endpoints.end())
                             {
                                 it->second();
                                 res.status = 200;
                             }
                             else
                             {
                                 res.status = 404;
                             }
                         });
            m_server.set_address_family(AF_UNIX);
            std::filesystem::remove(SOCKET_PATH);

            runningTrigger = m_server.listen(SOCKET_PATH, true);
        });

    // Spin lock until server is ready
    while (!m_server.is_running() && runningTrigger)
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
    std::cout << "Server stopped" << std::endl;
}

void OnDemandManager::addEndpoint(const std::string& endpoint, std::function<void()> func)
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
