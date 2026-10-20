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
#include <string_view>
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
     * @brief The credentials of a `Authorization: Basic` header, decoded byte for byte (RFC 7617).
     *
     * The user ends at the first ':'; the password is everything after it, colons and UTF-8 included.
     */
    struct BasicAuthorization
    {
        std::string user;
        std::string password;
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
        /// The decoded `Authorization: Basic` credentials; absent without the header, with another scheme, or when
        /// the value is not canonical base64 of `user:password`.
        std::optional<BasicAuthorization> basicAuthorization;
    };

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    /**
     * @brief TLS settings of the fake (component suite only: it needs CPPHTTPLIB_OPENSSL_SUPPORT).
     */
    struct FakeTlsOptions
    {
        /// Server certificate chain file (PEM), e.g. TlsMaterialFactory::serverCertificate().
        std::string certificate;
        /// Server private key file (PEM, unencrypted).
        std::string key;
        /// Non-empty: mTLS, the client must present a pair that chains to this CA file.
        std::string clientCa;
        /// Speak at most TLS 1.1 (the floor and the security level are lowered so that 1.0/1.1 really negotiate).
        bool maxTls11 {false};
    };
#endif

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
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        /// Present: serve HTTPS (cpp-httplib SSLServer) instead of plain HTTP.
        std::optional<FakeTlsOptions> tls;
#endif
    };

    /**
     * @brief In-process fake indexer: HTTP (or, in the component suite, HTTPS/mTLS) on 127.0.0.1, ephemeral port,
     * scripted by an ordered rule list.
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
            m_port = m_server->bind_to_any_port("127.0.0.1");
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
                    m_server->listen_after_bind();
                    m_threadDone = true;
                });

            const auto deadline = std::chrono::steady_clock::now() + m_options.readyTimeout;
            while (!m_server->is_running())
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
                if (!stopRequested && m_server->is_running())
                {
                    m_server->stop();
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

        /// Whether the fake serves HTTPS.
        bool tls() const
        {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
            return m_options.tls.has_value();
#else
            return false;
#endif
        }

        /// "http://127.0.0.1:<port>", or "https://…" when tls().
        std::string baseUrl() const
        {
            return std::string(tls() ? "https" : "http") + "://127.0.0.1:" + std::to_string(m_port);
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

        /**
         * @brief Strict standard base64 (RFC 4648 §4): padded to a multiple of 4, no whitespace, canonical padding
         * bits.
         *
         * @return The decoded bytes, or nothing if @p text is not canonical base64.
         */
        static std::optional<std::string> decodeBase64(std::string_view text)
        {
            const auto value = [](char c) -> int
            {
                if (c >= 'A' && c <= 'Z')
                {
                    return c - 'A';
                }
                if (c >= 'a' && c <= 'z')
                {
                    return c - 'a' + 26;
                }
                if (c >= '0' && c <= '9')
                {
                    return c - '0' + 52;
                }
                if (c == '+')
                {
                    return 62;
                }
                if (c == '/')
                {
                    return 63;
                }
                return -1;
            };
            if (text.size() % 4 != 0)
            {
                return std::nullopt;
            }
            std::string out;
            out.reserve(text.size() / 4 * 3);
            for (std::size_t i = 0; i < text.size(); i += 4)
            {
                const bool last = i + 4 == text.size();
                const std::size_t padding = !last ? 0 : (text[i + 3] == '=' ? (text[i + 2] == '=' ? 2 : 1) : 0);
                std::uint32_t group {0};
                for (std::size_t j = 0; j < 4; ++j)
                {
                    const int digit = j < 4 - padding ? value(text[i + j]) : 0;
                    if (digit < 0)
                    {
                        return std::nullopt;
                    }
                    group = (group << 6) | static_cast<std::uint32_t>(digit);
                }
                // Non-canonical: bits that the padding drops must be zero.
                if ((padding == 1 && (group & 0xffU) != 0) || (padding == 2 && (group & 0xffffU) != 0))
                {
                    return std::nullopt;
                }
                out.push_back(static_cast<char>((group >> 16) & 0xffU));
                if (padding < 2)
                {
                    out.push_back(static_cast<char>((group >> 8) & 0xffU));
                }
                if (padding < 1)
                {
                    out.push_back(static_cast<char>(group & 0xffU));
                }
            }
            return out;
        }

        /**
         * @brief Decodes an `Authorization` value of the Basic scheme (scheme case-insensitive, one or more spaces).
         *
         * @return user and password exactly as sent, or nothing for another scheme, bad base64 or no ':'.
         */
        static std::optional<BasicAuthorization> decodeBasicAuthorization(std::string_view header)
        {
            static constexpr std::string_view SCHEME {"basic"};
            if (header.size() <= SCHEME.size())
            {
                return std::nullopt;
            }
            for (std::size_t i = 0; i < SCHEME.size(); ++i)
            {
                const char c = header[i];
                if ((c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c) != SCHEME[i])
                {
                    return std::nullopt;
                }
            }
            std::size_t start = SCHEME.size();
            if (header[start] != ' ')
            {
                return std::nullopt;
            }
            while (start < header.size() && header[start] == ' ')
            {
                ++start;
            }
            const auto decoded = decodeBase64(header.substr(start));
            if (!decoded.has_value())
            {
                return std::nullopt;
            }
            const auto colon = decoded->find(':');
            if (colon == std::string::npos)
            {
                return std::nullopt;
            }
            return BasicAuthorization {decoded->substr(0, colon), decoded->substr(colon + 1)};
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
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
            if (m_options.tls.has_value())
            {
                const auto& tls = *m_options.tls;
                auto server = std::make_unique<httplib::SSLServer>(
                    tls.certificate.c_str(), tls.key.c_str(), tls.clientCa.empty() ? nullptr : tls.clientCa.c_str());
                if (!server->is_valid())
                {
                    throw std::runtime_error("FakeIndexer: cannot load the TLS certificate/key/client CA");
                }
                if (tls.maxTls11)
                {
                    SSL_CTX* context = server->ssl_context();
                    // OpenSSL 3 refuses TLS < 1.2 above security level 0; httplib sets a 1.2 floor.
                    SSL_CTX_set_security_level(context, 0);
                    if (SSL_CTX_set_min_proto_version(context, TLS1_VERSION) != 1 ||
                        SSL_CTX_set_max_proto_version(context, TLS1_1_VERSION) != 1)
                    {
                        throw std::runtime_error("FakeIndexer: cannot cap the TLS version");
                    }
                }
                m_server = std::move(server);
            }
            else
#endif
            {
                m_server = std::make_unique<httplib::Server>();
            }

            const auto threads = m_options.threads;
            m_server->new_task_queue = [threads]
            {
                return new httplib::ThreadPool(threads);
            };
            m_server->set_tcp_nodelay(true); // else Nagle + delayed ACK adds ~40 ms to small responses
            m_server->set_keep_alive_max_count(m_options.keepAliveMaxCount);
            m_server->set_keep_alive_timeout(m_options.keepAliveTimeoutSec);
            m_server->set_payload_max_length(64ULL * 1024 * 1024);
            m_server->set_write_timeout(m_options.writeTimeoutSec, 0);

            const auto handler = [this](const httplib::Request& req, httplib::Response& res)
            {
                handle(req, res);
            };
            m_server->Get(".*", handler); // also serves HEAD
            m_server->Post(".*", handler);
            m_server->Put(".*", handler);
            m_server->Patch(".*", handler);
            m_server->Delete(".*", handler);
            m_server->Options(".*", handler);
        }

        void handle(const httplib::Request& req, httplib::Response& res)
        {
            Rule matched;
            {
                std::lock_guard lock(m_mutex);
                m_requests.push_back(RecordedRequest {
                    req.method,
                    req.path,
                    req.target,
                    m_options.recordBodies ? req.body : std::string {},
                    req.body.size(),
                    req.headers,
                    req.remote_addr,
                    req.remote_port,
                    std::chrono::steady_clock::now(),
                    req.has_header("Authorization") ? decodeBasicAuthorization(req.get_header_value("Authorization"))
                                                    : std::nullopt});
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
        std::unique_ptr<httplib::Server> m_server;
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
