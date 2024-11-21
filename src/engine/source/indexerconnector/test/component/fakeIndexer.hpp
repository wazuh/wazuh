/*
 * Wazuh Indexer Connector - Component tests
 * Copyright (C) 2015, Wazuh Inc.
 * January 09, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FAKE_INDEXER_HPP
#define _FAKE_INDEXER_HPP

#include <functional>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>
#include <utility>

/**
 * @brief This class is a simple HTTP server that provides a fake OpenSearch server.
 */
class FakeIndexer
{
private:
    httplib::Server m_server;
    std::thread m_thread;
    int m_port;
    std::string m_host;
    std::string m_health;
    std::string m_indexName;
    bool m_indexerInitialized = false;
    std::function<void(const std::string&)> m_initTemplateCallback = {};
    std::function<void(const std::string&)> m_initIndexCallback = {};
    std::function<void(const std::string&, std::string&)> m_publishCallback = {};

public:
    /**
     * @brief Class constructor.
     *
     * @param host Host of the server.
     * @param port Port of the server.
     * @param health Health status of the server.
     * @param indexName Name of the index.
     */
    FakeIndexer(std::string host, int port, std::string health, std::string indexName)
        : m_thread(&FakeIndexer::run, this)
        , m_port(port)
        , m_host(std::move(host))
        , m_health(std::move(health))
        , m_indexName(std::move(indexName))
    {
        // Wait until server is ready.
        while (!m_server.is_running())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    ~FakeIndexer()
    {
        m_server.stop();
        if (m_thread.joinable())
        {
            m_thread.join();
        }
    }

    /**
     * @brief Sets the health of the server.
     *
     * @param health New health value.
     */
    void setHealth(std::string health) { m_health = std::move(health); }

    /**
     * @brief Sets the publish callback.
     *
     * @param callback New callback.
     */
    void setPublishCallback(std::function<void(const std::string&, std::string&)> callback)
    {
        m_publishCallback = std::move(callback);
    }

    /**
     * @brief Returns the indexer initialized flag.
     *
     * @return True if initialized, false otherwise.
     */
    bool initialized() const { return m_indexerInitialized; }

    /**
     * @brief Starts the server and listens for new connections.
     *
     * Setups a fake OpenSearch endpoint, configures the server and starts listening
     * for new connections.
     *
     */
    void run()
    {
        // Endpoint where the health status is returned.
        m_server.Get("/_cat/health",
                     [this](const httplib::Request& req, httplib::Response& res)
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
                     });

        // Endpoint where the publications are made into.
        m_server.Post("/_bulk",
                      [this](const httplib::Request& req, httplib::Response& res)
                      {
                          try
                          {
                              std::string content;
                              if (m_publishCallback)
                              {
                                  m_publishCallback(req.body, content);
                              }
                              res.status = 200;
                              res.set_content(content, "text/plain");
                          }
                          catch (const std::exception& e)
                          {
                              res.status = 500;
                              res.set_content(e.what(), "text/plain");
                          }
                      });

        m_server.set_keep_alive_max_count(1);
        m_server.listen(m_host, m_port);
    }
};

#endif // _FAKE_INDEXER_HPP
