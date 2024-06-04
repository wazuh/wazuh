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
#include <chrono>
#include <filesystem>
#include <fstream>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

const std::string SNAPSHOT_FILE_NAME {"content_snapshot.xyz"};

/**
 * @brief Struct that represents a query record received by the server.
 *
 */
struct ServerRecord
{
    const std::string endpoint;                                         ///< Endpoint where the query points to.
    const std::chrono::time_point<std::chrono::system_clock> timestamp; ///< Query timestamp.

    /**
     * @brief Creates a record with the given query endpoint and the current timestamp.
     *
     * @param queryEndpoint
     */
    ServerRecord(const std::string& queryEndpoint)
        : endpoint(queryEndpoint)
        , timestamp(std::chrono::system_clock::now()) {};
};

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
    std::string m_ctiMetadataMock;
    std::vector<ServerRecord> m_records; ///< Set of queries recorded by the server.

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

    /**
     * @brief Adds a handler routine for a given endpoint. The final handler is a wrapper of the one passed by
     * parameter, with the addition of a pre-handler routine.
     *
     * @param endpoint Endpoint that will trigger the handler.
     * @param handler Callback handler.
     */
    void addEndpointHandler(const std::string& endpoint, httplib::Server::Handler handler)
    {
        auto handlerWrapper {[this, endpoint, handler](const httplib::Request& req, httplib::Response& res)
                             {
                                 m_records.emplace_back(endpoint);

                                 handler(req, res);
                             }};
        m_server.Get(endpoint, std::move(handlerWrapper));
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
        m_server.wait_until_ready();
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
     * @brief Returns the list of records.
     *
     * @return const std::vector<ServerRecord>& Constant reference to the records vector.
     */
    const std::vector<ServerRecord>& getRecords() const
    {
        return m_records;
    }

    /**
     * @brief Removes all the registered records.
     *
     */
    void clearRecords()
    {
        m_records.clear();
    }

    /**
     * @brief Sets the CTI metadata to be returned in the next query.
     *
     * @param ctiMetadata New metadata to be used.
     */
    void setCtiMetadata(std::string ctiMetadata)
    {
        m_ctiMetadataMock = std::move(ctiMetadata);
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
        addEndpointHandler("/raw",
                           [](const httplib::Request& req, httplib::Response& res)
                           {
                               const auto response = R"(
                                {
                                    "key": "value"
                                })"_json;
                               res.set_content(response.dump(), "text/plain");
                           });
        addEndpointHandler("/xz",
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
        addEndpointHandler("/xz/consumers",
                           [this](const httplib::Request& req, httplib::Response& res)
                           {
                               auto response = R"(
                            {
                                "data": 
                                {
                                    "last_offset": 3,
                                    "last_snapshot_offset": 3
                                }
                            }
                         )"_json;
                               response["data"]["last_snapshot_link"] = "localhost:" + std::to_string(m_port) + "/xz";

                               res.set_content(response.dump(), "text/plain");
                           });
        addEndpointHandler("/xz/consumers/changes",
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
        addEndpointHandler("/raw/consumers",
                           [this](const httplib::Request& req, httplib::Response& res)
                           {
                               std::string response;
                               if (m_ctiMetadataMock.empty())
                               {
                                   auto responseJSON = R"(
                                {
                                    "data": 
                                    {
                                        "last_offset": 3,
                                        "last_snapshot_offset": 3
                                    }
                                }
                            )"_json;
                                   responseJSON["data"]["last_snapshot_link"] =
                                       "localhost:" + std::to_string(m_port) + "/raw";
                                   response = responseJSON.dump();
                               }
                               else
                               {
                                   response = std::move(m_ctiMetadataMock);
                                   m_ctiMetadataMock.clear();
                               }

                               res.set_content(response, "text/plain");
                           });
        addEndpointHandler("/raw/consumers/changes",
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

        // Endpoint that returns the link to a dummy snapshot file.
        addEndpointHandler("/snapshot/consumers",
                           [this](const httplib::Request& req, httplib::Response& res)
                           {
                               if (!m_errorsQueue.empty())
                               {
                                   constexpr auto RESPONSE {"Something bad happened."};
                                   res.status = popError();
                                   res.set_content(RESPONSE, "text/plain");
                                   return;
                               }

                               std::string response;
                               if (m_ctiMetadataMock.empty())
                               {
                                   auto responseJSON = R"(
                                {
                                    "data": 
                                    {
                                        "last_offset": 3,
                                        "last_snapshot_offset": 3
                                    }
                                }
                            )"_json;
                                   responseJSON["data"]["last_snapshot_link"] =
                                       "localhost:" + std::to_string(m_port) + "/" + SNAPSHOT_FILE_NAME;
                                   response = responseJSON.dump();
                               }
                               else
                               {
                                   response = std::move(m_ctiMetadataMock);
                                   m_ctiMetadataMock.clear();
                               }

                               res.set_content(response, "text/plain");
                           });

        // Endpoint that responses with a dummy snapshot file.
        addEndpointHandler("/" + SNAPSHOT_FILE_NAME,
                           [this](const httplib::Request& req, httplib::Response& res)
                           {
                               if (!m_errorsQueue.empty())
                               {
                                   constexpr auto RESPONSE {"Something bad happened."};
                                   res.status = popError();
                                   res.set_content(RESPONSE, "text/plain");
                                   return;
                               }

                               // Create dummy snapshot file.
                               std::ofstream snapshotFile {SNAPSHOT_FILE_NAME};
                               snapshotFile << R"({"data":"content"})"_json;
                               snapshotFile.close();

                               // Read and send dummy file.
                               std::ifstream inputFile {SNAPSHOT_FILE_NAME, std::ios::in | std::ios::binary};
                               if (inputFile)
                               {
                                   std::ostringstream response;
                                   response << inputFile.rdbuf();
                                   inputFile.close();
                                   res.set_content(response.str(), "application/octet-stream");
                               }
                               else
                               {
                                   res.status = 404;
                                   res.set_content("File not found", "text/plain");
                               }

                               // Remove dummy file.
                               std::filesystem::remove(SNAPSHOT_FILE_NAME);
                           });
        m_server.set_keep_alive_max_count(1);
        m_server.listen(m_host.c_str(), m_port);
    }
};

#endif // _FAKE_SERVER_HPP
