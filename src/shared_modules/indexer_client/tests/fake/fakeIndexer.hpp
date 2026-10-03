/*
 * Wazuh indexer client
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INDEXER_CLIENT_TESTS_FAKE_INDEXER_HPP
#define _INDEXER_CLIENT_TESTS_FAKE_INDEXER_HPP

#include "httplib.h"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <memory>
#include <mutex>
#include <optional>
#include <regex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace indexer_client::testing
{
    /**
     * @brief One scripted response of the fake indexer.
     *
     * Rules are evaluated in insertion order; the first one whose method and path match (and that still has
     * applications left) answers the request. A request no rule matches gets 200 `{}`.
     */
    struct Rule
    {
        /// HTTP method to match (exact, e.g. "POST"). Empty matches any method.
        std::string method;
        /// ECMAScript regex that must match the WHOLE request path (query string excluded).
        std::string pathRegex {".*"};
        /// Response status.
        int status {200};
        /// Response body (served as application/json).
        std::string body {"{}"};
        /// Delay before answering. Interrupted early by stop().
        std::chrono::milliseconds latency {0};
        /// Value of the Retry-After response header; absent means no header.
        std::optional<std::string> retryAfter;
        /// How many requests this rule answers before it stops matching; absent means unlimited.
        std::optional<std::size_t> times;
    };

    /**
     * @brief A request as the fake received it.
     */
    struct RecordedRequest
    {
        std::string method;
        /// Path without the query string.
        std::string path;
        /// Raw request target (path plus query string).
        std::string target;
        std::string body;
        httplib::Headers headers;
    };

    /**
     * @brief Tuning of the fake's HTTP server.
     */
    struct FakeIndexerOptions
    {
        /// Worker threads (one per concurrently served connection).
        std::size_t threads {16};
        /// Requests per keep-alive connection before the server closes it (cpp-httplib's default is 5).
        std::size_t keepAliveMaxCount {100000};
        /// Idle keep-alive timeout, seconds.
        time_t keepAliveTimeoutSec {30};
        /// Upper bound for start() to see the server listening.
        std::chrono::milliseconds readyTimeout {5000};
    };

    /**
     * @brief In-process fake indexer: plain HTTP on 127.0.0.1, ephemeral port, scripted by an ordered rule list.
     *
     * Thread-safe: rules can be added and requests inspected while the server is serving.
     */
    class FakeIndexer final
    {
    public:
        explicit FakeIndexer(FakeIndexerOptions options = {})
            : m_options(std::move(options))
        {
            setup();
        }

        ~FakeIndexer()
        {
            stop();
        }

        FakeIndexer(const FakeIndexer&) = delete;
        FakeIndexer& operator=(const FakeIndexer&) = delete;
        FakeIndexer(FakeIndexer&&) = delete;
        FakeIndexer& operator=(FakeIndexer&&) = delete;

        /**
         * @brief Binds 127.0.0.1 on an ephemeral port and serves from a dedicated thread.
         *
         * Waits at most FakeIndexerOptions::readyTimeout for the server to listen.
         *
         * @return The bound port.
         * @throws std::runtime_error if already started, the bind fails or the server is not ready in time.
         */
        int start()
        {
            if (m_thread.joinable())
            {
                throw std::runtime_error("FakeIndexer: already started");
            }
            m_port = m_server.bind_to_any_port("127.0.0.1");
            if (m_port <= 0)
            {
                throw std::runtime_error("FakeIndexer: bind failed");
            }
            m_stopping = false;
            m_threadDone = false;
            m_thread = std::thread(
                [this]
                {
                    m_server.listen_after_bind();
                    m_threadDone = true;
                });

            const auto deadline = std::chrono::steady_clock::now() + m_options.readyTimeout;
            while (!m_server.is_running())
            {
                if (m_threadDone.load() || std::chrono::steady_clock::now() >= deadline)
                {
                    stop();
                    throw std::runtime_error("FakeIndexer: server not ready in time");
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            return m_port;
        }

        /**
         * @brief Stops serving and joins the server thread. Idempotent.
         */
        void stop()
        {
            m_stopping = true;
            if (!m_thread.joinable())
            {
                return;
            }
            // httplib::Server::stop() is a no-op until the listen loop runs and asserts if called twice on a running
            // server, so call it exactly once, as soon as the loop is up, and wait for the thread to end.
            bool stopRequested {false};
            while (!m_threadDone.load())
            {
                if (!stopRequested && m_server.is_running())
                {
                    m_server.stop();
                    stopRequested = true;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            m_thread.join();
        }

        /// Bound port (0 before start()).
        int port() const
        {
            return m_port;
        }

        /// "http://127.0.0.1:<port>".
        std::string baseUrl() const
        {
            return "http://127.0.0.1:" + std::to_string(m_port);
        }

        /**
         * @brief Appends a rule (lowest priority so far).
         *
         * @return The rule's index, for hits().
         * @throws std::regex_error if pathRegex is invalid.
         */
        std::size_t addRule(Rule rule)
        {
            Entry entry {std::regex(rule.pathRegex, std::regex::ECMAScript), std::move(rule), 0};
            std::lock_guard lock(m_mutex);
            m_rules.push_back(std::move(entry));
            return m_rules.size() - 1;
        }

        /// Removes every rule (requests fall back to 200 `{}`).
        void clearRules()
        {
            std::lock_guard lock(m_mutex);
            m_rules.clear();
        }

        /// How many requests the rule at @p index has answered.
        std::size_t hits(std::size_t index) const
        {
            std::lock_guard lock(m_mutex);
            return m_rules.at(index).hits;
        }

        /// Copy of every request received so far, in arrival order.
        std::vector<RecordedRequest> requests() const
        {
            std::lock_guard lock(m_mutex);
            return m_requests;
        }

        /// Number of requests received so far.
        std::size_t requestCount() const
        {
            std::lock_guard lock(m_mutex);
            return m_requests.size();
        }

        /// Forgets the recorded requests.
        void clearRequests()
        {
            std::lock_guard lock(m_mutex);
            m_requests.clear();
        }

    private:
        struct Entry
        {
            std::regex regex;
            Rule rule;
            std::size_t hits;
        };

        void setup()
        {
            const auto threads = m_options.threads;
            m_server.new_task_queue = [threads]
            {
                return new httplib::ThreadPool(threads);
            };
            m_server.set_tcp_nodelay(true); // else Nagle + delayed ACK adds ~40 ms to small responses
            m_server.set_keep_alive_max_count(m_options.keepAliveMaxCount);
            m_server.set_keep_alive_timeout(m_options.keepAliveTimeoutSec);
            m_server.set_payload_max_length(64ULL * 1024 * 1024);

            const auto handler = [this](const httplib::Request& req, httplib::Response& res)
            {
                handle(req, res);
            };
            m_server.Get(".*", handler); // also serves HEAD
            m_server.Post(".*", handler);
            m_server.Put(".*", handler);
            m_server.Patch(".*", handler);
            m_server.Delete(".*", handler);
            m_server.Options(".*", handler);
        }

        void handle(const httplib::Request& req, httplib::Response& res)
        {
            int status {200};
            std::string body {"{}"};
            std::chrono::milliseconds latency {0};
            std::optional<std::string> retryAfter;
            {
                std::lock_guard lock(m_mutex);
                m_requests.push_back(RecordedRequest {req.method, req.path, req.target, req.body, req.headers});
                for (auto& entry : m_rules)
                {
                    const auto& rule = entry.rule;
                    if (rule.times.has_value() && entry.hits >= *rule.times)
                    {
                        continue;
                    }
                    if (!rule.method.empty() && rule.method != req.method)
                    {
                        continue;
                    }
                    if (!std::regex_match(req.path, entry.regex))
                    {
                        continue;
                    }
                    ++entry.hits;
                    status = rule.status;
                    body = rule.body;
                    latency = rule.latency;
                    retryAfter = rule.retryAfter;
                    break;
                }
            }

            const auto until = std::chrono::steady_clock::now() + latency;
            while (std::chrono::steady_clock::now() < until && !m_stopping.load())
            {
                std::this_thread::sleep_for(std::min<std::chrono::steady_clock::duration>(
                    until - std::chrono::steady_clock::now(), std::chrono::milliseconds(5)));
            }

            res.status = status;
            if (retryAfter.has_value())
            {
                res.set_header("Retry-After", *retryAfter);
            }
            res.set_content(body, "application/json");
        }

        FakeIndexerOptions m_options;
        httplib::Server m_server;
        std::thread m_thread;
        int m_port {0};
        std::atomic<bool> m_stopping {false};
        std::atomic<bool> m_threadDone {false};
        mutable std::mutex m_mutex;
        std::vector<Entry> m_rules;
        std::vector<RecordedRequest> m_requests;
    };
} // namespace indexer_client::testing

#endif // _INDEXER_CLIENT_TESTS_FAKE_INDEXER_HPP
