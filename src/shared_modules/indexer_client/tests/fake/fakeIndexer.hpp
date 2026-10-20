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

#ifndef _INDEXER_CLIENT_TESTS_FAKE_INDEXER_HPP
#define _INDEXER_CLIENT_TESTS_FAKE_INDEXER_HPP

#include "httplib.h"

#include <dirent.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <memory>
#include <mutex>
#include <optional>
#include <regex>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace indexer_client::testing
{
    /// How a scripted response body is framed on the wire.
    enum class Framing
    {
        /// `Content-Length` with the full body size (the default).
        ContentLength,
        /// `Transfer-Encoding: chunked`, in Rule::chunkSize pieces.
        Chunked
    };

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
        /// Hold the response until FakeIndexer::releaseHeld() (or stop()). Applied before #latency.
        bool hold {false};
        /// Serve exactly this many filler bytes ('x'), generated while streaming, instead of #body.
        std::optional<std::size_t> bodySize;
        /// Body framing. Any setting other than a plain ContentLength #body streams the body.
        Framing framing {Framing::ContentLength};
        /// Piece size when streaming (also the chunk size of Framing::Chunked).
        std::size_t chunkSize {16 * 1024};
        /// Close the connection after this many body bytes, before the declared length (or the final chunk).
        std::optional<std::size_t> cutAfter;
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
        /// Request body; empty unless FakeIndexerOptions::recordBodies.
        std::string body;
        /// Size of the request body as received (always recorded).
        std::size_t bodySize {0};
        httplib::Headers headers;
        /// Peer address and port: distinct ports are distinct TCP connections.
        std::string remoteAddr;
        int remotePort {0};
        /// When the handler saw the request (the whole request has been read).
        std::chrono::steady_clock::time_point receivedAt;
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
        /// Keep request bodies in RecordedRequest::body. Off by default: bulk tests must not retain their payloads.
        bool recordBodies {false};
        /// Socket write timeout, seconds: bounds how long a response stalls on a client that stopped reading.
        time_t writeTimeoutSec {5};
        /// listen() backlog. cpp-httplib listens with 5, so a burst of connections (64 at once) has SYNs dropped
        /// and retried a second later; start() re-listens with this value.
        int listenBacklog {1024};
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
            widenBacklog();
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
         *
         * Releases every held response first (the latch opens and stays open), so it never waits for releaseHeld().
         */
        void stop()
        {
            {
                std::lock_guard lock(m_mutex);
                m_stopping = true;
                m_holdOpen = true;
            }
            m_cv.notify_all();
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

        /**
         * @brief Waits until at least @p count requests have been received (recorded) in total.
         *
         * A request is recorded as soon as it is read, before any hold or latency, so this is the "received" event.
         *
         * @return Whether the count was reached within @p timeout.
         */
        bool waitForRequests(std::size_t count, std::chrono::milliseconds timeout) const
        {
            std::unique_lock lock(m_mutex);
            return m_cv.wait_for(lock, timeout, [&] { return m_requests.size() >= count; });
        }

        /// Number of distinct remote ports among the recorded requests (= TCP connections that sent a request).
        std::size_t distinctRemotePorts() const
        {
            std::lock_guard lock(m_mutex);
            std::set<int> ports;
            for (const auto& request : m_requests)
            {
                ports.insert(request.remotePort);
            }
            return ports.size();
        }

        /// Responses held by a Rule::hold rule right now.
        std::size_t heldNow() const
        {
            std::lock_guard lock(m_mutex);
            return m_held;
        }

        /**
         * @brief Waits until at least @p count responses are held at the same time.
         *
         * @return Whether that happened within @p timeout.
         */
        bool waitHeld(std::size_t count, std::chrono::milliseconds timeout) const
        {
            std::unique_lock lock(m_mutex);
            return m_cv.wait_for(lock, timeout, [&] { return m_held >= count; });
        }

        /// Opens the hold latch: every held response is answered, and later Rule::hold requests pass straight through.
        void releaseHeld()
        {
            {
                std::lock_guard lock(m_mutex);
                m_holdOpen = true;
            }
            m_cv.notify_all();
        }

        /// Closes the hold latch again (it starts closed). No effect after stop().
        void rearmHold()
        {
            std::lock_guard lock(m_mutex);
            if (!m_stopping)
            {
                m_holdOpen = false;
            }
        }

        /**
         * @brief Formats @p when as an IMF-fixdate (RFC 9110 §5.6.7), e.g. for Rule::retryAfter.
         *
         * Locale-independent: it never goes through strftime or the global locale.
         */
        static std::string httpDate(std::chrono::system_clock::time_point when)
        {
            static constexpr const char* DAYS[] {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
            static constexpr const char* MONTHS[] {
                "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
            const std::time_t seconds = std::chrono::system_clock::to_time_t(when);
            std::tm utc {};
            if (::gmtime_r(&seconds, &utc) == nullptr)
            {
                throw std::runtime_error("FakeIndexer: gmtime_r failed");
            }
            char buffer[64];
            std::snprintf(buffer,
                          sizeof(buffer),
                          "%s, %02d %s %04d %02d:%02d:%02d GMT",
                          DAYS[utc.tm_wday],
                          utc.tm_mday,
                          MONTHS[utc.tm_mon],
                          utc.tm_year + 1900,
                          utc.tm_hour,
                          utc.tm_min,
                          utc.tm_sec);
            return buffer;
        }

    private:
        /**
         * @brief Re-listens on the bound socket with FakeIndexerOptions::listenBacklog.
         *
         * cpp-httplib does not expose its listening socket, so it is found among this process's descriptors: the
         * listening TCP socket bound to 127.0.0.1:<port>. Best effort: if it is not found the backlog stays at 5.
         */
        void widenBacklog() const
        {
            DIR* directory = ::opendir("/proc/self/fd");
            if (directory == nullptr)
            {
                return;
            }
            while (const dirent* entry = ::readdir(directory))
            {
                char* end {nullptr};
                const long fd = std::strtol(entry->d_name, &end, 10);
                if (end == entry->d_name || *end != '\0' || fd == ::dirfd(directory))
                {
                    continue;
                }
                int listening {0};
                socklen_t optionLength = sizeof(listening);
                sockaddr_in address {};
                socklen_t addressLength = sizeof(address);
                if (::getsockopt(static_cast<int>(fd), SOL_SOCKET, SO_ACCEPTCONN, &listening, &optionLength) == 0 &&
                    listening == 1 &&
                    ::getsockname(static_cast<int>(fd), reinterpret_cast<sockaddr*>(&address), &addressLength) == 0 &&
                    address.sin_family == AF_INET && ntohs(address.sin_port) == m_port &&
                    address.sin_addr.s_addr == htonl(INADDR_LOOPBACK))
                {
                    ::listen(static_cast<int>(fd), m_options.listenBacklog);
                    break;
                }
            }
            ::closedir(directory);
        }

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
            m_server.set_write_timeout(m_options.writeTimeoutSec, 0);

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
            Rule matched;
            {
                std::lock_guard lock(m_mutex);
                m_requests.push_back(RecordedRequest {req.method,
                                                      req.path,
                                                      req.target,
                                                      m_options.recordBodies ? req.body : std::string {},
                                                      req.body.size(),
                                                      req.headers,
                                                      req.remote_addr,
                                                      req.remote_port,
                                                      std::chrono::steady_clock::now()});
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
                    matched = rule;
                    break;
                }
            }
            m_cv.notify_all(); // the "received" event

            if (matched.hold)
            {
                std::unique_lock lock(m_mutex);
                ++m_held;
                m_cv.notify_all();
                m_cv.wait(lock, [this] { return m_holdOpen; });
                --m_held;
            }

            const auto until = std::chrono::steady_clock::now() + matched.latency;
            while (std::chrono::steady_clock::now() < until && !m_stopping.load())
            {
                std::this_thread::sleep_for(std::min<std::chrono::steady_clock::duration>(
                    until - std::chrono::steady_clock::now(), std::chrono::milliseconds(5)));
            }

            res.status = matched.status;
            if (matched.retryAfter.has_value())
            {
                res.set_header("Retry-After", *matched.retryAfter);
            }
            respond(matched, res);
        }

        /// Fills the response body as the rule asks: a plain string, or a streamed (possibly cut) body.
        void respond(const Rule& rule, httplib::Response& res)
        {
            static constexpr const char* CONTENT_TYPE {"application/json"};
            const bool streamed =
                rule.bodySize.has_value() || rule.framing != Framing::ContentLength || rule.cutAfter.has_value();
            if (!streamed)
            {
                res.set_content(rule.body, CONTENT_TYPE);
                return;
            }

            auto source = std::make_shared<const std::string>(rule.bodySize.has_value() ? std::string {} : rule.body);
            const std::size_t total = rule.bodySize.value_or(source->size());
            const std::size_t limit = std::min(total, rule.cutAfter.value_or(total));
            const bool cut = rule.cutAfter.has_value() && *rule.cutAfter < total;
            const std::size_t piece = std::max<std::size_t>(1, rule.chunkSize);
            // Filler pieces are cut from one shared buffer, so even a multi-GiB body is never allocated.
            auto filler = std::make_shared<const std::string>(rule.bodySize.has_value() ? piece : 0, 'x');

            // Writes [offset, min(offset + piece, limit)); returns false (the connection is then closed) once a cut
            // body has written its limit, or when the client is gone or the fake is stopping.
            auto writeFrom = [this, source, filler, limit, cut, piece](std::size_t offset, httplib::DataSink& sink)
            {
                if (m_stopping.load())
                {
                    return false;
                }
                if (offset >= limit)
                {
                    if (cut)
                    {
                        return false;
                    }
                    sink.done();
                    return true;
                }
                const std::size_t length = std::min(piece, limit - offset);
                const char* data = filler->empty() ? source->data() + offset : filler->data();
                return sink.write(data, length);
            };

            if (rule.framing == Framing::Chunked)
            {
                res.set_chunked_content_provider(CONTENT_TYPE,
                                                 [writeFrom](std::size_t offset, httplib::DataSink& sink)
                                                 { return writeFrom(offset, sink); });
                return;
            }
            if (total == 0)
            {
                res.set_content(std::string {}, CONTENT_TYPE);
                return;
            }
            res.set_content_provider(total,
                                     CONTENT_TYPE,
                                     [writeFrom](std::size_t offset, std::size_t /*length*/, httplib::DataSink& sink)
                                     { return writeFrom(offset, sink); });
        }

        FakeIndexerOptions m_options;
        httplib::Server m_server;
        std::thread m_thread;
        int m_port {0};
        std::atomic<bool> m_stopping {false};
        std::atomic<bool> m_threadDone {false};
        mutable std::mutex m_mutex;
        mutable std::condition_variable m_cv;
        bool m_holdOpen {false};
        std::size_t m_held {0};
        std::vector<Entry> m_rules;
        std::vector<RecordedRequest> m_requests;
    };
} // namespace indexer_client::testing

#endif // _INDEXER_CLIENT_TESTS_FAKE_INDEXER_HPP
