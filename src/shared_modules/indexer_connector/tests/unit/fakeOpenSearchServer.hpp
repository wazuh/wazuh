/*
 * Wazuh Indexer Connector - Fake OpenSearch Server
 * Copyright (C) 2015, Wazuh Inc.
 * September 08, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FAKE_OPEN_SEARCH_SERVER_HPP
#define _FAKE_OPEN_SEARCH_SERVER_HPP

#include <external/cpp-httplib/httplib.h>
#include <external/nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <thread>
#include <utility>

/**
 * @brief This class is a simple HTTP server that provides a fake OpenSearch server.
 */
class FakeOpenSearchServer
{
private:
    httplib::Server m_server;
    std::thread m_thread;
    std::string m_host;
    std::string m_health;
    int m_port;
    int m_statusCode;
    std::string m_response;
    uint16_t m_forcedDelay;

public:
    /**
     * @brief Class constructor.
     *
     * @param host host of the fake OpenSearch server.
     * @param port port of the fake OpenSearch server
     * @param health health status of the fake OpenSearch server.
     * @param forcedDelay forced delay in milliseconds (default 0). This is used to simulate a slow server.
     * @param code Error code returned by the fake OpenSearch server.
     * @param response Mocked response from server.
     */
    FakeOpenSearchServer(std::string host,
                         int port,
                         std::string health,
                         uint16_t forcedDelay = 0,
                         int code = 200,
                         std::string response = "")
        : m_thread(&FakeOpenSearchServer::run, this)
        , m_host(std::move(host))
        , m_health(std::move(health))
        , m_port(port)
        , m_statusCode(code)
        , m_response(std::move(response))
        , m_forcedDelay(forcedDelay)
    {
        // Wait until server is ready
        while (!m_server.is_running())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    ~FakeOpenSearchServer()
    {
        m_server.stop();
        if (m_thread.joinable())
        {
            m_thread.join();
        }
    }

    /**
     * @brief Starts the server and listens for new connections.
     *
     * Setups a fake OpenSearch endpoint, configures the server and starts listening
     * for new connections.
     *
     */
    void run()
    {
        m_server.Get("/_cat/health",
                     [this](const httplib::Request& /*req*/, httplib::Response& res)
                     {
                         // Simulate a slow server
                         std::this_thread::sleep_for(std::chrono::milliseconds(m_forcedDelay));

                         if (m_response.empty())
                         {
                             const auto response = nlohmann::json::array({{{"epoch", "1726271464"},
                                                                           {"timestamp", "23:51:04"},
                                                                           {"cluster", "wazuh-cluster"},
                                                                           {"status", m_health},
                                                                           {"node.total", "1"},
                                                                           {"node.data", "1"},
                                                                           {"discovered_cluster_manager", "true"},
                                                                           {"shards", "166"},
                                                                           {"pri", "166"},
                                                                           {"relo", "0"},
                                                                           {"init", "0"},
                                                                           {"unassign", "0"},
                                                                           {"pending_tasks", "0"},
                                                                           {"max_task_wait_time", "-"},
                                                                           {"active_shards_percent", "100.0%"}}});

                             std::stringstream ss;
                             ss << response.dump();
                             res.set_content(ss.str(), "application/json");
                         }
                         else
                         {
                             res.set_content(m_response, "application/json");
                         }
                     });
        m_server.set_keep_alive_max_count(1);
        m_server.listen(m_host.c_str(), m_port);
    }
};

#endif // _FAKE_OPEN_SEARCH_SERVER_HPP
