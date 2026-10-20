/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _INDEXER_CLIENT_BENCH_FAKE_HPP
#define _INDEXER_CLIENT_BENCH_FAKE_HPP

// In-process fake indexer shared by both benchmark executables (plan 18, E2c, I58; port of the E0b spike fake).
// It counts bytes, requests and distinct TCP connections without keeping any body, answers `/_cluster/health` with
// `green`, keeps the headers of the first `/_bulk` after each resetCounters() and answers `/_bulk` with a fixed status.
// The test fake (tests/fake/fakeIndexer.hpp) is not reused: it records every request under a mutex.

#include <external/cpp-httplib/httplib.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

namespace bench
{
    class BenchFake final
    {
    public:
        /// Plain HTTP. `bulkStatus` is the status of every `/_bulk` answer.
        explicit BenchFake(int bulkStatus = 200)
            : m_server(std::make_unique<httplib::Server>())
            , m_bulkStatus(bulkStatus)
        {
            setup();
        }

        /// HTTPS with the given PEM certificate and key.
        BenchFake(const std::string& certPath, const std::string& keyPath, int bulkStatus = 200)
            : m_server(std::make_unique<httplib::SSLServer>(certPath.c_str(), keyPath.c_str()))
            , m_tls(true)
            , m_bulkStatus(bulkStatus)
        {
            if (!m_server->is_valid())
            {
                throw std::runtime_error("bench fake: SSLServer invalid (certificate or key)");
            }
            setup();
        }

        ~BenchFake()
        {
            stop();
        }

        BenchFake(const BenchFake&) = delete;
        BenchFake& operator=(const BenchFake&) = delete;

        /// Binds 127.0.0.1 on an ephemeral port and serves from a background thread.
        void start()
        {
            m_port = m_server->bind_to_any_port("127.0.0.1");
            if (m_port <= 0)
            {
                throw std::runtime_error("bench fake: bind failed");
            }
            m_thread = std::thread([this] { m_server->listen_after_bind(); });
            while (!m_server->is_running())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }

        void stop()
        {
            if (m_server)
            {
                m_server->stop();
            }
            if (m_thread.joinable())
            {
                m_thread.join();
            }
        }

        std::string baseUrl() const
        {
            return std::string(m_tls ? "https" : "http") + "://127.0.0.1:" + std::to_string(m_port);
        }

        std::uint64_t bulkRequests() const
        {
            return m_bulkRequests.load();
        }

        std::uint64_t bulkBytes() const
        {
            return m_bulkBytes.load();
        }

        std::uint64_t requests() const
        {
            return m_requests.load();
        }

        /// Distinct client (address, port) pairs seen since the last reset = distinct TCP connections served.
        std::size_t distinctConnections() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_peers.size();
        }

        /// Headers of the first `/_bulk` since the last reset: lower-case name -> values, cpp-httplib's pseudo-headers
        /// (REMOTE_*, LOCAL_*) left out.
        std::multimap<std::string, std::string> firstBulkHeaders() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_firstBulkHeaders;
        }

        void resetCounters()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_bulkRequests = 0;
            m_bulkBytes = 0;
            m_requests = 0;
            m_peers.clear();
            m_firstBulkHeaders.clear();
            m_haveHeaders = false;
        }

    private:
        void notePeer(const httplib::Request& req, bool bulk)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            ++m_requests;
            m_peers.emplace(req.remote_addr, req.remote_port);
            if (bulk)
            {
                ++m_bulkRequests;
                m_bulkBytes += req.body.size();
                if (!m_haveHeaders)
                {
                    m_haveHeaders = true;
                    for (const auto& [name, value] : req.headers)
                    {
                        if (name == "REMOTE_ADDR" || name == "REMOTE_PORT" || name == "LOCAL_ADDR" ||
                            name == "LOCAL_PORT")
                        {
                            continue;
                        }
                        std::string lower(name);
                        std::transform(lower.begin(),
                                       lower.end(),
                                       lower.begin(),
                                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                        m_firstBulkHeaders.emplace(std::move(lower), value);
                    }
                }
            }
        }

        void setup()
        {
            auto& s = *m_server;
            s.new_task_queue = []
            {
                return new httplib::ThreadPool(64);
            };
            s.set_tcp_nodelay(true);             // Nagle + delayed ACK would add ~40 ms per small response.
            s.set_keep_alive_max_count(1000000); // cpp-httplib's default is 5 requests per connection.
            s.set_keep_alive_timeout(60);
            s.set_payload_max_length(64ULL * 1024 * 1024);
            s.set_read_timeout(60, 0);
            s.set_write_timeout(60, 0);

            s.Post("/_bulk",
                   [this](const httplib::Request& req, httplib::Response& res)
                   {
                       notePeer(req, true);
                       res.status = m_bulkStatus;
                       res.set_content(R"({"took":1,"errors":false,"items":[]})", "application/json");
                   });
            s.Get("/_cluster/health",
                  [this](const httplib::Request& req, httplib::Response& res)
                  {
                      notePeer(req, false);
                      res.set_content(R"({"cluster_name":"bench","status":"green"})", "application/json");
                  });
        }

        std::unique_ptr<httplib::Server> m_server;
        bool m_tls {false};
        int m_bulkStatus {200};
        std::thread m_thread;
        int m_port {0};
        std::atomic<std::uint64_t> m_bulkRequests {0};
        std::atomic<std::uint64_t> m_bulkBytes {0};
        std::atomic<std::uint64_t> m_requests {0};
        mutable std::mutex m_mutex;
        std::set<std::pair<std::string, int>> m_peers;
        std::multimap<std::string, std::string> m_firstBulkHeaders;
        bool m_haveHeaders {false};
    };
} // namespace bench

#endif // _INDEXER_CLIENT_BENCH_FAKE_HPP
