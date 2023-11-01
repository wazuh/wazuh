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

public:
    /**
     * @brief Class constructor.
     *
     * @param host host of the fake OpenSearch server.
     * @param port port of the fake OpenSearch server
     * @param health health status of the fake OpenSearch server.
     */
    FakeOpenSearchServer(std::string host, int port, std::string health)
        : m_thread(&FakeOpenSearchServer::run, this)
        , m_host(std::move(host))
        , m_health(std::move(health))
        , m_port(port)
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
        m_server.Get(
            "/_cat/health",
            [this](const httplib::Request& req, httplib::Response& res)
            {
                std::stringstream ss;
                ss << "epoch      timestamp cluster            status node.total node.data discovered_cluster_manager "
                      "shards pri relo init unassign pending_tasks max_task_wait_time active_shards_percent\n";
                ss << "1694645550 22:52:30 opensearch-cluster " << m_health << " 2 2 true 14 7 0 0 0 0 - 100.0%\n";
                res.set_content(ss.str(), "text/plain");
            });
        m_server.set_keep_alive_max_count(1);
        m_server.listen(m_host.c_str(), m_port);
    }
};

#endif // _FAKE_OPEN_SEARCH_SERVER_HPP
