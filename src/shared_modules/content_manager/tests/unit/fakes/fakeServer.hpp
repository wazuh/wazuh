/*
 * Wazuh Indexer Connector - Fake Server
 * Copyright (C) 2015, Wazuh Inc.
 * September 19, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FAKE_SERVER_HPP
#define _FAKE_SERVER_HPP

#include "external/cpp-httplib/httplib.h"
#include "external/nlohmann/json.hpp"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <utility>

/**
 * @brief This class is a simple HTTP server that provides a fake server.
 */
class FakeServer
{
private:
    httplib::Server m_server;
    std::thread m_thread;
    std::string m_host;
    int m_port;
    std::queue<unsigned long> m_errorsQueue; ///< Errors queue used to return error codes for some queries.

    /**
     * @brief Pops and returns the last error code from the error queue.
     *
     * @return unsigned long Error code.
     */
    unsigned long popError()
    {
        const auto errorCode {m_errorsQueue.front()};
        m_errorsQueue.pop();
        return errorCode;
    }

public:
    /**
     * @brief Class constructor.
     *
     * @param host Host of the fake server.
     * @param port Port of the fake server
     */
    FakeServer(std::string host, int port)
        : m_thread(&FakeServer::run, this)
        , m_host(std::move(host))
        , m_port(port)
    {
        // Wait until server is ready
        while (!m_server.is_running())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    ~FakeServer()
    {
        m_server.stop();
        if (m_thread.joinable())
        {
            m_thread.join();
        }
    }

    /**
     * @brief Appends an error to the error queue.
     *
     * @param errorCode Error code to push.
     */
    void pushError(const unsigned long& errorCode)
    {
        m_errorsQueue.push(errorCode);
    }

    /**
     * @brief Clears the errors queue.
     *
     */
    void clearErrorsQueue()
    {
        std::queue<unsigned long> emptyQueue;
        std::swap(m_errorsQueue, emptyQueue);
    }

    /**
     * @brief Starts the server and listens for new connections.
     *
     * Setups a fake endpoint, configures the server and starts listening
     * for new connections.
     *
     */
    void run()
    {
        m_server.Get("/raw",
                     [](const httplib::Request& req, httplib::Response& res)
                     {
                         const auto response = R"(
                         {
                             "key": "value"
                         })"_json;
                         res.set_content(response.dump(), "text/plain");
                     });
        m_server.Get("/xz",
                     [](const httplib::Request& req, httplib::Response& res)
                     {
                         const std::filesystem::path inputPath {std::filesystem::current_path() /
                                                                "input_files/sample.xz"};
                         std::ifstream in(inputPath, std::ios::in | std::ios::binary);
                         if (in)
                         {
                             std::ostringstream response;
                             response << in.rdbuf();
                             in.close();
                             res.set_content(response.str(), "application/octet-stream");
                         }
                         else
                         {
                             res.status = 404;
                             res.set_content("File not found", "text/plain");
                         }
                     });
        m_server.Get("/xz/consumers",
                     [this](const httplib::Request& req, httplib::Response& res)
                     {
                         auto response = R"(
                            {
                                "data": 
                                {
                                    "last_offset": 3
                                }
                            }
                         )"_json;
                         response["data"]["last_snapshot_link"] = "127.0.0.1:" + std::to_string(m_port) + "/xz";

                         res.set_content(response.dump(), "text/plain");
                     });
        m_server.Get("/xz/consumers/changes",
                     [this](const httplib::Request& req, httplib::Response& res)
                     {
                         const std::filesystem::path inputPath {std::filesystem::current_path() /
                                                                "input_files/sample.xz"};
                         std::ifstream in(inputPath, std::ios::in | std::ios::binary);
                         if (in)
                         {
                             std::ostringstream response;
                             response << in.rdbuf();
                             in.close();
                             res.set_content(response.str(), "application/octet-stream");
                         }
                         else
                         {
                             res.status = 404;
                             res.set_content("File not found", "text/plain");
                         }
                     });
        m_server.Get("/raw/consumers",
                     [this](const httplib::Request& req, httplib::Response& res)
                     {
                         auto response = R"(
                            {
                                "data": 
                                {
                                    "last_offset": 3
                                }
                            }
                         )"_json;
                         response["data"]["last_snapshot_link"] = "127.0.0.1:" + std::to_string(m_port) + "/raw";

                         res.set_content(response.dump(), "text/plain");
                     });
        m_server.Get("/raw/consumers/changes",
                     [this](const httplib::Request& req, httplib::Response& res)
                     {
                         if (m_errorsQueue.empty())
                         {
                             const auto response = R"(
                            {
                                "data":
                                [
                                    {
                                        "offset": 1,
                                        "type": "create",
                                        "version": 1,
                                        "context": "vulnerabilities",
                                        "resource": "CVE-2020-0546",
                                        "payload":
                                        {
                                            "description": "not defined",
                                            "identifier": "CVE-2020-0546",
                                            "references":
                                            [
                                                {
                                                    "url": "https://security.archlinux.org/CVE-2020-0546"
                                                }
                                            ],
                                            "state": "PUBLISHED"
                                        }
                                    },
                                    {
                                        "offset": 2,
                                        "type": "update",
                                        "version": 2,
                                        "context": "vulnerabilities",
                                        "resource": "CVE-2020-0546",
                                        "operations":
                                        []
                                    },
                                    {
                                        "offset": 3,
                                        "type": "update",
                                        "version": 2,
                                        "context": "vulnerabilities",
                                        "resource": "CVE-2020-0546",
                                        "operations":
                                        [
                                            {
                                                "op": "replace",
                                                "path": "/description",
                                                "value": "lalala"
                                            }
                                        ]
                                    }
                                ]
                            })"_json;
                             res.set_content(response.dump(), "text/plain");
                         }
                         else
                         {
                             constexpr auto RESPONSE {"Something bad happened."};
                             res.status = popError();
                             res.set_content(RESPONSE, "text/plain");
                         }
                     });
        m_server.set_keep_alive_max_count(1);
        m_server.listen(m_host.c_str(), m_port);
    }
};

#endif // _FAKE_SERVER_HPP
