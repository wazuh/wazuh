/*
 * Wazuh Indexer Connector - Component tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _FAKE_INDEXER_HPP
#define _FAKE_INDEXER_HPP

#include "json.hpp"
#include <external/cpp-httplib/httplib.h>
#include <functional>
#include <sstream>
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
    std::atomic<int> m_healthRequests {0};
    std::atomic<bool> m_indexerInitialized = false;
    std::function<void(const std::string&)> m_initTemplateCallback = {};
    std::function<void(const std::string&)> m_initIndexCallback = {};
    std::function<void(const std::string&)> m_publishCallback = {};
    std::function<std::string(const std::string&)> m_searchCallback = {};
    std::function<void(const std::string&)> m_deleteScrollCallback = {};

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
        : m_thread()
        , m_port(port)
        , m_host(std::move(host))
        , m_health(std::move(health))
        , m_indexName(std::move(indexName))
    {
    }

    /**
     * @brief Class destructor.
     */
    ~FakeIndexer()
    {
        m_server.stop();
        if (m_thread.joinable())
        {
            m_thread.join();
        }
    }

    /**
     * @brief Initiates the server.
     *
     */
    void start()
    {
        m_thread = std::thread(&FakeIndexer::run, this);
        // Wait until server is ready.
        while (!m_server.is_running())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    /**
     * @brief Sets the health of the server.
     *
     * @param health New health value.
     */
    void setHealth(std::string health)
    {
        m_health = std::move(health);
    }

    /**
     * @brief Number of health-check requests served since this server started.
     *
     * Counts a request to the index-scoped `GET /_cluster/health/<pattern>` the connector probes
     * with. It is deliberately not keyed to a literal path -- that is what let this counter keep
     * its meaning across the move from the cluster-wide `/_cat/health` -- and what it measures is a
     * health-check ROUND, the observable difference between connectors that each build their own
     * monitor and connectors sharing one IndexerSession.
     *
     * The cluster-wide route is NOT served any more: serving both would let a regression back to
     * `/_cat/health` pass the component suite unnoticed.
     *
     * @return The request count.
     */
    int healthRequests() const
    {
        return m_healthRequests.load();
    }

    /**
     * @brief Sets the publish callback.
     *
     * @param callback New callback.
     */
    void setPublishCallback(std::function<void(const std::string&)> callback)
    {
        m_publishCallback = std::move(callback);
    }

    /**
     * @brief Sets the init index callback.
     *
     * @param callback New callback.
     */
    void setInitIndexCallback(std::function<void(const std::string&)> callback)
    {
        m_initIndexCallback = std::move(callback);
    }

    /**
     * @brief Sets the init template callback.
     *
     * @param callback New callback.
     */
    void setInitTemplateCallback(std::function<void(const std::string&)> callback)
    {
        m_initTemplateCallback = std::move(callback);
    }

    /**
     * @brief Sets the search callback.
     *
     * @param callback New callback.
     */
    void setSearchCallback(std::function<std::string(const std::string&)> callback)
    {
        m_searchCallback = std::move(callback);
    }

    /**
     * @brief Sets the delete scroll callback.
     *
     * @param callback New callback.
     */
    void setDeleteScrollCallback(std::function<void(const std::string&)> callback)
    {
        m_deleteScrollCallback = std::move(callback);
    }

    /**
     * @brief Returns the indexer initialized flag.
     *
     * @return True if initialized, false otherwise.
     */
    bool initialized() const
    {
        return m_indexerInitialized.load();
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
        // Endpoint where the health status of a set of indices is returned.
        //
        // Registered as a regular expression so that ANY index pattern matches, the
        // `wazuh-*,.wazuh-*` the manager asks for included: httplib builds a RegexMatcher for every
        // pattern that carries no `/:` path parameter and runs it over the URL-decoded request path,
        // so the `*` and `,` of the suffix are matched as the literal characters they are.
        m_server.Get(R"(/_cluster/health(/.*)?)",
                     [this](const httplib::Request& req, httplib::Response& res)
                     {
                         ++m_healthRequests;
                         // `_cluster/health` answers with a bare object, unlike the cluster-wide
                         // `_cat/health` this replaced, which answered with an array of one row.
                         // Driven by `m_health`, so setHealth() still governs what the probe sees.
                         const auto response = nlohmann::json::object({{"cluster_name", "wazuh-cluster"},
                                                                       {"status", m_health},
                                                                       {"timed_out", false},
                                                                       {"number_of_nodes", 1},
                                                                       {"number_of_data_nodes", 1},
                                                                       {"discovered_master", true},
                                                                       {"active_primary_shards", 166},
                                                                       {"active_shards", 166},
                                                                       {"relocating_shards", 0},
                                                                       {"initializing_shards", 0},
                                                                       {"unassigned_shards", 0},
                                                                       {"delayed_unassigned_shards", 0},
                                                                       {"number_of_pending_tasks", 0},
                                                                       {"number_of_in_flight_fetch", 0},
                                                                       {"task_max_waiting_in_queue_millis", 0},
                                                                       {"active_shards_percent_as_number", 100.0}});

                         std::stringstream ss;
                         ss << response.dump();
                         res.set_content(ss.str(), "application/json");
                     });

        // Endpoint where the index is initialized.
        m_server.Put("/" + m_indexName,
                     [this](const httplib::Request& req, httplib::Response& res)
                     {
                         try
                         {
                             if (m_initIndexCallback)
                             {
                                 m_initIndexCallback(req.body);
                             }
                             m_indexerInitialized = true;
                             res.status = 200;
                             res.set_content("Index initialized", "text/plain");
                         }
                         catch (const std::exception& e)
                         {
                             res.status = 500;
                             res.set_content(e.what(), "text/plain");
                         }
                     });

        // Endpoint where the template is initialized.
        m_server.Put("/_index_template/" + m_indexName + "_template",
                     [this](const httplib::Request& req, httplib::Response& res)
                     {
                         try
                         {
                             if (m_initTemplateCallback)
                             {
                                 m_initTemplateCallback(req.body);
                             }
                             res.status = 200;
                             res.set_content("Template initialized", "text/plain");
                         }
                         catch (const std::exception& e)
                         {
                             res.status = 500;
                             res.set_content(e.what(), "text/plain");
                         }
                     });

        // Endpoint where the publications are made into.
        m_server.Post("/_bulk",
                      [this](const httplib::Request& req, httplib::Response& res)
                      {
                          try
                          {
                              if (m_publishCallback)
                              {
                                  m_publishCallback(req.body);
                              }
                              res.status = 200;
                              res.set_content(R"({"took":1,"errors":false,"items":[]})", "application/json");
                          }
                          catch (const std::exception& e)
                          {
                              res.status = 500;
                              res.set_content(e.what(), "text/plain");
                          }
                      });

        // Endpoint where the publications are made into.
        m_server.Post("/indexer_connector_test/_delete_by_query",
                      [this](const httplib::Request& req, httplib::Response& res)
                      {
                          try
                          {
                              if (m_publishCallback)
                              {
                                  m_publishCallback(req.body);
                              }
                              res.status = 200;
                              res.set_content(R"({"deleted":1,"failures":[]})", "application/json");
                          }
                          catch (const std::exception& e)
                          {
                              res.status = 500;
                              res.set_content(e.what(), "text/plain");
                          }
                      });

        // Endpoint where the search is made into.
        m_server.Post("/" + m_indexName + "/_search",
                      [this](const httplib::Request& req, httplib::Response& res)
                      {
                          try
                          {
                              if (m_searchCallback)
                              {
                                  res.set_content(m_searchCallback(req.body), "text/plain");
                              }
                              else
                              {
                                  res.set_content("Search made", "text/plain");
                              }
                              res.status = 200;
                          }
                          catch (const std::exception& e)
                          {
                              res.status = 500;
                              res.set_content(e.what(), "text/plain");
                          }
                      });

        m_server.Delete("/_search/scroll/:scroll_id",
                        [this](const httplib::Request& req, httplib::Response& res)
                        {
                            try
                            {
                                if (m_deleteScrollCallback)
                                {
                                    m_deleteScrollCallback(req.path_params.at("scroll_id"));
                                }
                                res.status = 200;
                                res.set_content("Scroll deleted", "text/plain");
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
