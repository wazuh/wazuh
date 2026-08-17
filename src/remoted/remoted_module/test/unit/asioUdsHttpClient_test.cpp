/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 25, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Exercises the async UDS HTTP client against an in-process Asio Unix-domain stub server:
// a canned response is parsed (status + body), a missing socket yields Connect, a silent server
// yields ResponseTimeout, a server that never reads yields WriteTimeout, and the body keep-alive is
// released (not leaked).
#include "downstream/asioUdsHttpClient.hpp"

#include <gtest/gtest.h>

#include <asio/buffer.hpp>
#include <asio/io_context.hpp>
#include <asio/local/stream_protocol.hpp>
#include <asio/post.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <future>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <unistd.h>
#include <utility>

using namespace remoted::downstream;

namespace
{
    using stream_protocol = asio::local::stream_protocol;

    std::string uniqueSocketPath(const char* tag)
    {
        static std::atomic<int> counter {0};
        return "/tmp/rmt_uds_" + std::string {tag} + "_" + std::to_string(::getpid()) + "_" +
               std::to_string(counter.fetch_add(1)) + ".sock";
    }

    // Accepts one connection, drains one read, and (unless silent) writes a canned response then closes.
    class StubUdsServer final
    {
    public:
        StubUdsServer(std::string path, std::string response, bool silent, bool acceptButNeverRead = false)
            : m_path {std::move(path)}
            , m_response {std::move(response)}
            , m_silent {silent}
            , m_acceptButNeverRead {acceptButNeverRead}
            , m_acceptor {m_ioc}
        {
            ::unlink(m_path.c_str());
            stream_protocol::endpoint endpoint {m_path};
            m_acceptor.open(endpoint.protocol());
            m_acceptor.bind(endpoint);
            m_acceptor.listen();
            doAccept();
            m_thread = std::thread([this] { m_ioc.run(); });
        }

        ~StubUdsServer()
        {
            m_ioc.stop();
            if (m_thread.joinable())
            {
                m_thread.join();
            }
            ::unlink(m_path.c_str());
        }

        const std::string& path() const
        {
            return m_path;
        }

        /// Bytes of the request as they arrived on the wire, for asserting what the client serialized.
        /// Only the FIRST read chunk: enough for a request head, which is all any test inspects.
        std::string capturedRequest() const
        {
            std::lock_guard<std::mutex> lock {m_captureMutex};
            return m_captured;
        }

    private:
        void doAccept()
        {
            m_acceptor.async_accept(
                [this](const std::error_code& ec, stream_protocol::socket socket)
                {
                    if (ec)
                    {
                        return;
                    }
                    auto conn = std::make_shared<stream_protocol::socket>(std::move(socket));
                    if (m_acceptButNeverRead)
                    {
                        // Never drains the socket's receive buffer -> the client's async_write
                        // eventually blocks once the kernel send buffer fills up.
                        m_held = conn;
                        return;
                    }
                    auto buffer = std::make_shared<std::array<char, 4096>>();
                    conn->async_read_some(asio::buffer(*buffer),
                                          [this, conn, buffer](const std::error_code& readEc, std::size_t bytesRead)
                                          {
                                              if (readEc)
                                              {
                                                  return;
                                              }
                                              {
                                                  std::lock_guard<std::mutex> lock {m_captureMutex};
                                                  m_captured.assign(buffer->data(), bytesRead);
                                              }
                                              if (m_silent)
                                              {
                                                  m_held = conn; // keep the connection open -> client times out
                                                  return;
                                              }
                                              auto resp = std::make_shared<std::string>(m_response);
                                              asio::async_write(*conn,
                                                                asio::buffer(*resp),
                                                                [conn, resp](const std::error_code&, std::size_t)
                                                                {
                                                                    std::error_code ignore;
                                                                    conn->shutdown(
                                                                        stream_protocol::socket::shutdown_both, ignore);
                                                                    conn->close(ignore);
                                                                });
                                          });
                });
        }

        std::string m_path;
        std::string m_response;
        bool m_silent;
        bool m_acceptButNeverRead;
        asio::io_context m_ioc;
        stream_protocol::acceptor m_acceptor;
        std::shared_ptr<stream_protocol::socket> m_held; // keeps a silent connection open
        std::thread m_thread;
        mutable std::mutex m_captureMutex;
        std::string m_captured;
    };

    struct Result
    {
        DownstreamError error;
        DownstreamResponse response;
    };

    // Fire one request and block for its completion. responseTimeoutMs == 0 means "use the client's
    // configured default", matching DownstreamRequest's own sentinel.
    Result sendAndWait(AsioUdsHttpClient& client,
                       const std::string& socketPath,
                       std::string_view body,
                       std::shared_ptr<const void> keepAlive = std::make_shared<int>(0),
                       int responseTimeoutMs = 0)
    {
        std::promise<Result> promise;
        auto future = promise.get_future();

        DownstreamRequest req;
        req.socketPath = socketPath;
        req.method = remoted::http::Method::Post;
        req.path = "/events/enriched";
        req.contentType = "application/x-ndjson";
        req.body = body;
        req.responseTimeoutMs = responseTimeoutMs;

        client.sendAsync(std::move(req),
                         std::move(keepAlive),
                         [&promise](DownstreamError error, DownstreamResponse response)
                         { promise.set_value(Result {error, std::move(response)}); });

        return future.get();
    }
} // namespace

TEST(AsioUdsHttpClientTest, ParsesSuccessfulResponse)
{
    StubUdsServer server {uniqueSocketPath("ok"), "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", false};

    AsioUdsHttpClient client {DownstreamConfig {}};
    client.start();

    const auto result = sendAndWait(client, server.path(), "H {}\nE evt");
    EXPECT_EQ(result.error, DownstreamError::None);
    EXPECT_EQ(result.response.status, 200);
    EXPECT_EQ(result.response.body, "hello");
}

TEST(AsioUdsHttpClientTest, ParsesErrorStatusAndBody)
{
    StubUdsServer server {
        uniqueSocketPath("bad"),
        "HTTP/1.1 400 Bad Request\r\nContent-Length: 27\r\n\r\n{\"error\":\"x\",\"code\":400}\r\n\r\n",
        false};

    AsioUdsHttpClient client {DownstreamConfig {}};
    client.start();

    const auto result = sendAndWait(client, server.path(), "body");
    EXPECT_EQ(result.error, DownstreamError::None);
    EXPECT_EQ(result.response.status, 400);
}

TEST(AsioUdsHttpClientTest, MissingSocketYieldsConnectError)
{
    AsioUdsHttpClient client {DownstreamConfig {}};
    client.start();

    const auto result = sendAndWait(client, uniqueSocketPath("missing"), "body");
    EXPECT_EQ(result.error, DownstreamError::Connect);
}

TEST(AsioUdsHttpClientTest, SilentServerYieldsResponseTimeout)
{
    StubUdsServer server {uniqueSocketPath("silent"), "", /*silent=*/true};

    DownstreamConfig config;
    config.responseTimeoutMs = 200; // fast timeout for the test
    AsioUdsHttpClient client {config};
    client.start();

    const auto result = sendAndWait(client, server.path(), "body");
    // Specifically the RESPONSE phase: the peer accepted the connection and drained the request,
    // it just never answered. That distinction is what tells an operator to look at
    // downstream_response_timeout rather than the connect or write ones.
    EXPECT_EQ(result.error, DownstreamError::ResponseTimeout);
}

TEST(AsioUdsHttpClientTest, ReleasesBodyKeepAlive)
{
    StubUdsServer server {uniqueSocketPath("keepalive"), "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", false};

    AsioUdsHttpClient client {DownstreamConfig {}};
    client.start();

    auto keepAlive = std::make_shared<int>(42);
    std::weak_ptr<int> weak = keepAlive;

    const std::string body = "body";
    const auto result = sendAndWait(client, server.path(), body, std::move(keepAlive));
    EXPECT_EQ(result.error, DownstreamError::None);

    // The client must not leak the keep-alive: by completion it has long been dropped (at send time).
    EXPECT_TRUE(weak.expired());
}

TEST(AsioUdsHttpClientTest, WriteHangYieldsWriteTimeoutNotIndefiniteHang)
{
    // The server accepts but never reads -> once the kernel's UDS send buffer fills, async_write
    // blocks. Without a write-phase timer this would hang forever, permanently pinning the
    // request's deferred-work slot and byte reservation.
    StubUdsServer server {uniqueSocketPath("writehang"), "", /*silent=*/false, /*acceptButNeverRead=*/true};

    DownstreamConfig config;
    config.writeTimeoutMs = 200;
    config.responseTimeoutMs = 200;
    AsioUdsHttpClient client {config};
    client.start();

    // Comfortably larger than any typical Linux UDS kernel buffer default, so the write genuinely
    // blocks instead of completing in one shot.
    const std::string bigBody(8U * 1024U * 1024U, 'A');

    const auto start = std::chrono::steady_clock::now();
    const auto result = sendAndWait(client, server.path(), bigBody);
    const auto elapsed = std::chrono::steady_clock::now() - start;

    // Specifically the WRITE phase: the peer accepted but never read, so the deadline that fired is
    // the one downstream_write_timeout controls -- not the response one.
    EXPECT_EQ(result.error, DownstreamError::WriteTimeout);
    EXPECT_LT(elapsed, std::chrono::seconds {5}); // bounded, not an indefinite hang
}

TEST(AsioUdsHttpClientTest, OversizedResponseBodyAbortsSession)
{
    const std::string hugeBody(4096, 'x');
    const std::string response =
        "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(hugeBody.size()) + "\r\n\r\n" + hugeBody;
    StubUdsServer server {uniqueSocketPath("hugebody"), response, false};

    DownstreamConfig config;
    config.maxResponseBodySize = 1024; // small cap so the test aborts quickly, well before hugeBody ends
    AsioUdsHttpClient client {config};
    client.start();

    const auto result = sendAndWait(client, server.path(), "body");
    EXPECT_EQ(result.error, DownstreamError::ResponseTooLarge);
}

TEST(AsioUdsHttpClientTest, ParsesResponseHeadersWithLowerCasedNames)
{
    // /stateful's postProcess relays Retry-After to the agent, so the client must surface response
    // headers -- names lower-cased (like HttpRequest::headers), values verbatim, order preserved.
    StubUdsServer server {uniqueSocketPath("hdrs"),
                          "HTTP/1.1 503 Service Unavailable\r\n"
                          "Content-Type: application/json\r\n"
                          "Retry-After: 60\r\n"
                          "Content-Length: 2\r\n\r\n{}",
                          false};

    AsioUdsHttpClient client {DownstreamConfig {}};
    client.start();

    const auto result = sendAndWait(client, server.path(), "body");
    ASSERT_EQ(result.error, DownstreamError::None);
    EXPECT_EQ(result.response.status, 503);
    ASSERT_EQ(result.response.headers.size(), 3U);
    EXPECT_EQ(result.response.headers[0], (std::pair<std::string, std::string> {"content-type", "application/json"}));
    EXPECT_EQ(result.response.headers[1], (std::pair<std::string, std::string> {"retry-after", "60"}));
    EXPECT_EQ(result.response.headers[2], (std::pair<std::string, std::string> {"content-length", "2"}));
}

TEST(AsioUdsHttpClientTest, OversizedResponseHeadersAbortSession)
{
    // Headers are capped by a fixed constant (kMaxResponseHeaderBytes, 16 KiB) rather than the
    // body tunable: a local service streaming an absurd header block must abort the session, not
    // grow the response allocation unboundedly.
    const std::string hugeValue(20U * 1024U, 'h');
    const std::string response = "HTTP/1.1 200 OK\r\nX-Huge: " + hugeValue + "\r\nContent-Length: 0\r\n\r\n";
    StubUdsServer server {uniqueSocketPath("hugehdr"), response, false};

    AsioUdsHttpClient client {DownstreamConfig {}};
    client.start();

    const auto result = sendAndWait(client, server.path(), "body");
    EXPECT_EQ(result.error, DownstreamError::ResponseTooLarge);
}

TEST(AsioUdsHttpClientTest, IoThreadGuardSurvivesUnexpectedException)
{
    // Defense-in-depth pattern check for the io_context worker thread wrapper: an uncaught
    // exception must not std::terminate() the process -- the try/catch around ioc.run() must
    // let the thread return cleanly instead.
    asio::io_context ioc;
    asio::post(ioc, [] { throw std::runtime_error("simulated bug"); });

    std::thread t(
        [&ioc]
        {
            try
            {
                ioc.run();
            }
            catch (...)
            {
                // swallow, mirroring AsioUdsHttpClient::start()'s guard
            }
        });
    t.join(); // must return, not std::terminate()
    SUCCEED();
}

// toString() feeds the diagnostic log lines, so a new DownstreamError enumerator added without
// updating the switch must fail loudly here rather than silently logging "unknown" in production.
TEST(AsioUdsHttpClientTest, ToStringCoversEveryDownstreamError)
{
    const DownstreamError all[] = {DownstreamError::None,
                                   DownstreamError::Connect,
                                   DownstreamError::ConnectTimeout,
                                   DownstreamError::WriteTimeout,
                                   DownstreamError::ResponseTimeout,
                                   DownstreamError::Transport,
                                   DownstreamError::Protocol,
                                   DownstreamError::ResponseTooLarge};

    std::set<std::string> seen;
    for (const auto error : all)
    {
        const char* tag = toString(error);
        ASSERT_NE(tag, nullptr);
        EXPECT_STRNE(tag, "unknown") << "missing switch case for " << static_cast<int>(error);
        EXPECT_TRUE(seen.insert(tag).second) << "duplicate tag '" << tag << "' -- tags must be distinguishable";
    }
    EXPECT_EQ(seen.size(), std::size(all));
}

TEST(AsioUdsHttpClientTest, PerRequestResponseTimeoutOverridesConfig)
{
    StubUdsServer server {uniqueSocketPath("override"), "", /*silent=*/true};

    // The client default is deliberately left at the built-in 5000 ms; the request asks for 200 ms.
    DownstreamConfig config;
    ASSERT_EQ(config.responseTimeoutMs, 5000) << "test assumes the built-in default";
    AsioUdsHttpClient client {config};
    client.start();

    const auto start = std::chrono::steady_clock::now();
    const auto result = sendAndWait(client, server.path(), "body", std::make_shared<int>(0), /*responseTimeoutMs=*/200);
    const auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_EQ(result.error, DownstreamError::ResponseTimeout);
    // The elapsed-time assertion is the one that matters: the error code alone would look identical
    // if the override were ignored and the 5 s default had been used instead.
    EXPECT_LT(elapsed, std::chrono::seconds {2}) << "the per-request override did not take effect";
}

TEST(AsioUdsHttpClientTest, ZeroResponseTimeoutFallsBackToTheConfiguredDefault)
{
    StubUdsServer server {uniqueSocketPath("fallback"), "", /*silent=*/true};

    DownstreamConfig config;
    config.responseTimeoutMs = 200;
    AsioUdsHttpClient client {config};
    client.start();

    // responseTimeoutMs left at 0 -> the client's 200 ms default applies (not "no timeout").
    const auto start = std::chrono::steady_clock::now();
    const auto result = sendAndWait(client, server.path(), "body");
    const auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_EQ(result.error, DownstreamError::ResponseTimeout);
    EXPECT_LT(elapsed, std::chrono::seconds {2});
}

TEST(AsioUdsHttpClientTest, CallerSuppliedHeadersAreSerializedOntoTheRequest)
{
    StubUdsServer server {uniqueSocketPath("headers"), "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", false};

    DownstreamConfig config;
    AsioUdsHttpClient client {config};
    client.start();

    std::promise<Result> promise;
    auto future = promise.get_future();

    DownstreamRequest req;
    req.socketPath = server.path();
    req.method = remoted::http::Method::Post;
    req.path = "/stats";
    req.contentType = "application/json";
    req.headers.emplace_back("X-Wazuh-Agent-Id", "042");
    req.body = "{}";

    client.sendAsync(std::move(req),
                     std::make_shared<int>(0),
                     [&promise](DownstreamError error, DownstreamResponse response)
                     { promise.set_value(Result {error, std::move(response)}); });

    ASSERT_EQ(future.get().error, DownstreamError::None);

    // This is the assertion that the agent id actually reaches modulesd: without it the endpoint
    // builds a header that is silently dropped on the floor and the downstream answers 400.
    const auto request = server.capturedRequest();
    EXPECT_NE(request.find("X-Wazuh-Agent-Id: 042\r\n"), std::string::npos) << "captured request:\n" << request;
    // Caller headers must not displace the ones the client owns.
    EXPECT_NE(request.find("Content-Type: application/json\r\n"), std::string::npos);
    EXPECT_NE(request.find("Content-Length: 2\r\n"), std::string::npos);
}
