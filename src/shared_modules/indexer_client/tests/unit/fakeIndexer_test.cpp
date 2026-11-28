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

#include "fakeIndexer.hpp"
#include "rawTcpServer.hpp"

#include "httplib.h"
#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using indexer_client::testing::FakeIndexer;
using indexer_client::testing::FakeIndexerOptions;
using indexer_client::testing::Framing;
using indexer_client::testing::Rule;
using indexer_client::testing::SilentServer;
using indexer_client::testing::StalledUploadServer;
using namespace std::chrono_literals;

namespace
{
    httplib::Client makeClient(const FakeIndexer& fake)
    {
        httplib::Client client("127.0.0.1", fake.port());
        client.set_connection_timeout(std::chrono::seconds(5));
        client.set_read_timeout(std::chrono::seconds(5));
        client.set_keep_alive(true);
        return client;
    }

    std::string headerValue(const httplib::Headers& headers, const std::string& key)
    {
        const auto it = headers.find(key); // case-insensitive comparator
        return it == headers.end() ? std::string {} : it->second;
    }

    /// Blocking client socket connected to 127.0.0.1:@p port, with 5 s send/receive timeouts. -1 on failure.
    int connectTo(int port)
    {
        const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0)
        {
            return -1;
        }
        timeval timeout {5, 0};
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        sockaddr_in address {};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons(static_cast<uint16_t>(port));
        if (::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0)
        {
            ::close(fd);
            return -1;
        }
        return fd;
    }

    int localPort(int fd)
    {
        sockaddr_in address {};
        socklen_t length = sizeof(address);
        ::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length);
        return ntohs(address.sin_port);
    }

    bool sendAll(int fd, const std::string& data)
    {
        std::size_t sent {0};
        while (sent < data.size())
        {
            const auto n = ::send(fd, data.data() + sent, data.size() - sent, MSG_NOSIGNAL);
            if (n <= 0)
            {
                return false;
            }
            sent += static_cast<std::size_t>(n);
        }
        return true;
    }

    /// Sends @p request on a fresh connection and returns every byte received until the server closes it.
    std::string rawExchange(int port, const std::string& request)
    {
        const int fd = connectTo(port);
        if (fd < 0 || !sendAll(fd, request))
        {
            if (fd >= 0)
            {
                ::close(fd);
            }
            return {};
        }
        std::string received;
        char buffer[16 * 1024];
        while (true)
        {
            const auto n = ::recv(fd, buffer, sizeof(buffer), 0);
            if (n <= 0)
            {
                break; // EOF, reset or the 5 s timeout
            }
            received.append(buffer, static_cast<std::size_t>(n));
        }
        ::close(fd);
        return received;
    }

    /// Splits a raw HTTP response into head (without the blank line) and body.
    std::pair<std::string, std::string> splitResponse(const std::string& raw)
    {
        const auto end = raw.find("\r\n\r\n");
        if (end == std::string::npos)
        {
            return {raw, {}};
        }
        return {raw.substr(0, end), raw.substr(end + 4)};
    }

    template<typename Duration>
    long long toMs(Duration duration)
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    }
} // namespace

TEST(FakeIndexerTest, RulesApply)
{
    FakeIndexer fake;

    Rule throttle;
    throttle.method = "POST";
    throttle.pathRegex = "/_bulk";
    throttle.status = 429;
    throttle.body = R"({"error":"too many requests"})";
    throttle.retryAfter = "3";
    fake.addRule(throttle);

    Rule slow;
    slow.method = "GET";
    slow.pathRegex = "/slow/.*";
    slow.latency = std::chrono::milliseconds(50);
    slow.body = R"({"slow":true})";
    fake.addRule(slow);

    ASSERT_GT(fake.start(), 0);
    auto client = makeClient(fake);

    const auto throttled = client.Post("/_bulk", "{}\n", "application/x-ndjson");
    ASSERT_TRUE(throttled);
    EXPECT_EQ(throttled->status, 429);
    EXPECT_EQ(throttled->get_header_value("Retry-After"), "3");
    EXPECT_EQ(throttled->body, R"({"error":"too many requests"})");

    const auto begin = std::chrono::steady_clock::now();
    const auto delayed = client.Get("/slow/x");
    const auto elapsed = std::chrono::steady_clock::now() - begin;
    ASSERT_TRUE(delayed);
    EXPECT_EQ(delayed->status, 200);
    EXPECT_FALSE(delayed->has_header("Retry-After"));
    EXPECT_EQ(delayed->body, R"({"slow":true})");
    EXPECT_GE(elapsed, std::chrono::milliseconds(50));

    // No rule matches: default 200 {}.
    const auto fallback = client.Get("/_cat/health");
    ASSERT_TRUE(fallback);
    EXPECT_EQ(fallback->status, 200);
    EXPECT_EQ(fallback->body, "{}");
    EXPECT_FALSE(fallback->has_header("Retry-After"));

    // Method mismatch falls through too.
    const auto wrongMethod = client.Get("/_bulk");
    ASSERT_TRUE(wrongMethod);
    EXPECT_EQ(wrongMethod->status, 200);
}

TEST(FakeIndexerTest, TimesLimitsRule)
{
    FakeIndexer fake;

    Rule twice;
    twice.pathRegex = "/_bulk";
    twice.status = 503;
    twice.times = 2;
    const auto twiceIndex = fake.addRule(twice);

    Rule fallback;
    fallback.pathRegex = "/_bulk";
    fallback.status = 201;
    const auto fallbackIndex = fake.addRule(fallback);

    fake.start();
    auto client = makeClient(fake);

    for (int i = 0; i < 2; ++i)
    {
        const auto res = client.Post("/_bulk", "x", "application/x-ndjson");
        ASSERT_TRUE(res);
        EXPECT_EQ(res->status, 503);
    }
    for (int i = 0; i < 3; ++i)
    {
        const auto res = client.Post("/_bulk", "x", "application/x-ndjson");
        ASSERT_TRUE(res);
        EXPECT_EQ(res->status, 201);
    }
    EXPECT_EQ(fake.hits(twiceIndex), 2U);
    EXPECT_EQ(fake.hits(fallbackIndex), 3U);

    fake.clearRules();
    const auto res = client.Post("/_bulk", "x", "application/x-ndjson");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 200);
    EXPECT_EQ(res->body, "{}");
}

TEST(FakeIndexerTest, RecordsRequests)
{
    FakeIndexerOptions options;
    options.recordBodies = true;
    FakeIndexer fake(options);
    fake.start();
    auto client = makeClient(fake);

    ASSERT_TRUE(client.Put("/idx/_doc/1?refresh=true", R"({"a":1})", "application/json"));
    ASSERT_TRUE(client.Delete("/idx/_doc/2"));
    ASSERT_TRUE(client.Get("/_cluster/health", httplib::Headers {{"X-Test", "yes"}}));

    const auto recorded = fake.requests();
    ASSERT_EQ(recorded.size(), 3U);
    EXPECT_EQ(fake.requestCount(), 3U);

    EXPECT_EQ(recorded[0].method, "PUT");
    EXPECT_EQ(recorded[0].path, "/idx/_doc/1");
    EXPECT_EQ(recorded[0].target, "/idx/_doc/1?refresh=true");
    EXPECT_EQ(recorded[0].body, R"({"a":1})");
    EXPECT_EQ(headerValue(recorded[0].headers, "Content-Type"), "application/json");

    EXPECT_EQ(recorded[1].method, "DELETE");
    EXPECT_EQ(recorded[1].path, "/idx/_doc/2");
    EXPECT_TRUE(recorded[1].body.empty());

    EXPECT_EQ(recorded[2].method, "GET");
    EXPECT_EQ(recorded[2].path, "/_cluster/health");
    EXPECT_EQ(headerValue(recorded[2].headers, "X-Test"), "yes");

    fake.clearRequests();
    EXPECT_EQ(fake.requestCount(), 0U);

    // stop() is idempotent; the destructor stops again.
    fake.stop();
    fake.stop();
}

TEST(FakeIndexerTest, StopWithoutStart)
{
    FakeIndexer fake;
    fake.stop();
    EXPECT_EQ(fake.port(), 0);
}

TEST(FakeIndexerTest, ConfigurableWorkersServe64Concurrently)
{
    constexpr std::size_t CLIENTS {64};
    FakeIndexerOptions options;
    options.threads = CLIENTS;
    FakeIndexer fake(options);
    Rule held;
    held.pathRegex = "/held";
    held.hold = true;
    fake.addRule(held);
    fake.start();

    std::atomic<std::size_t> ok {0};
    std::vector<std::thread> clients;
    for (std::size_t i = 0; i < CLIENTS; ++i)
    {
        clients.emplace_back(
            [&fake, &ok]
            {
                auto client = makeClient(fake);
                client.set_read_timeout(std::chrono::seconds(20));
                const auto res = client.Get("/held");
                if (res && res->status == 200)
                {
                    ++ok;
                }
            });
    }

    // Every request is held at once: one worker per connection, 64 of them.
    EXPECT_TRUE(fake.waitHeld(CLIENTS, 15s));
    EXPECT_EQ(fake.heldNow(), CLIENTS);
    EXPECT_EQ(fake.distinctRemotePorts(), CLIENTS);

    fake.releaseHeld();
    for (auto& client : clients)
    {
        client.join();
    }
    EXPECT_EQ(ok.load(), CLIENTS);
    EXPECT_EQ(fake.heldNow(), 0U);
}

TEST(FakeIndexerTest, HoldLatchReleasesAndCounts)
{
    FakeIndexer fake;
    Rule held;
    held.pathRegex = "/held";
    held.hold = true;
    held.body = R"({"held":true})";
    const auto heldIndex = fake.addRule(held);
    fake.start();

    std::atomic<std::size_t> answered {0};
    std::vector<std::thread> clients;
    for (int i = 0; i < 3; ++i)
    {
        clients.emplace_back(
            [&fake, &answered]
            {
                auto client = makeClient(fake);
                client.set_read_timeout(std::chrono::seconds(20));
                const auto res = client.Get("/held");
                if (res && res->status == 200 && res->body == R"({"held":true})")
                {
                    ++answered;
                }
            });
    }

    ASSERT_TRUE(fake.waitForRequests(3, 10s));
    ASSERT_TRUE(fake.waitHeld(3, 10s));
    EXPECT_EQ(fake.heldNow(), 3U);
    EXPECT_EQ(fake.hits(heldIndex), 3U);

    // Unheld paths are served while the latch is closed.
    auto other = makeClient(fake);
    const auto free = other.Get("/free");
    ASSERT_TRUE(free);
    EXPECT_EQ(free->status, 200);
    EXPECT_EQ(answered.load(), 0U);
    EXPECT_EQ(fake.heldNow(), 3U);

    fake.releaseHeld();
    for (auto& client : clients)
    {
        client.join();
    }
    EXPECT_EQ(answered.load(), 3U);
    EXPECT_EQ(fake.heldNow(), 0U);

    // An open latch lets later held requests straight through...
    const auto passes = other.Get("/held");
    ASSERT_TRUE(passes);
    EXPECT_EQ(passes->status, 200);

    // ...until it is rearmed.
    fake.rearmHold();
    std::thread again(
        [&fake]
        {
            auto client = makeClient(fake);
            client.set_read_timeout(std::chrono::seconds(20));
            EXPECT_TRUE(client.Get("/held"));
        });
    EXPECT_TRUE(fake.waitHeld(1, 10s));
    EXPECT_EQ(fake.heldNow(), 1U);
    fake.releaseHeld();
    again.join();
    EXPECT_EQ(fake.heldNow(), 0U);
}

TEST(FakeIndexerTest, ReceivedEventPrecedesResponse)
{
    FakeIndexer fake;
    Rule held;
    held.method = "HEAD";
    held.hold = true;
    fake.addRule(held);
    fake.start();

    std::thread client(
        [&fake]
        {
            auto headClient = makeClient(fake);
            headClient.set_read_timeout(std::chrono::milliseconds(300));
            EXPECT_FALSE(headClient.Head("/idx")); // the response is held: the client times out
        });

    // The fake confirms reception although it never answered.
    ASSERT_TRUE(fake.waitForRequests(1, 10s));
    const auto recorded = fake.requests();
    ASSERT_EQ(recorded.size(), 1U);
    EXPECT_EQ(recorded[0].method, "HEAD");
    EXPECT_EQ(recorded[0].path, "/idx");
    EXPECT_FALSE(fake.waitForRequests(2, 50ms));

    client.join();
    fake.releaseHeld();
}

TEST(FakeIndexerTest, StopReleasesHeldResponses)
{
    FakeIndexer fake;
    Rule held;
    held.hold = true;
    fake.addRule(held);
    fake.start();

    std::vector<std::thread> clients;
    for (int i = 0; i < 2; ++i)
    {
        clients.emplace_back(
            [&fake]
            {
                auto client = makeClient(fake);
                client.set_read_timeout(std::chrono::seconds(20));
                client.Get("/held"); // answered or cut by stop(); either is fine
            });
    }
    ASSERT_TRUE(fake.waitHeld(2, 10s));

    const auto begin = std::chrono::steady_clock::now();
    fake.stop(); // never releaseHeld()
    const auto elapsed = std::chrono::steady_clock::now() - begin;
    for (auto& client : clients)
    {
        client.join();
    }
    EXPECT_LT(elapsed, 2s);
    EXPECT_EQ(fake.heldNow(), 0U);
}

TEST(FakeIndexerTest, RetryAfterSecondsAndHttpDate)
{
    // RFC 9110's own example.
    EXPECT_EQ(FakeIndexer::httpDate(std::chrono::system_clock::from_time_t(784111777)),
              "Sun, 06 Nov 1994 08:49:37 GMT");
    EXPECT_EQ(FakeIndexer::httpDate(std::chrono::system_clock::from_time_t(0)), "Thu, 01 Jan 1970 00:00:00 GMT");

    FakeIndexer fake;
    Rule seconds;
    seconds.pathRegex = "/seconds";
    seconds.status = 429;
    seconds.retryAfter = "120";
    fake.addRule(seconds);

    const auto date = FakeIndexer::httpDate(std::chrono::system_clock::now() + std::chrono::seconds(120));
    Rule httpDate;
    httpDate.pathRegex = "/date";
    httpDate.status = 429;
    httpDate.retryAfter = date;
    fake.addRule(httpDate);
    fake.start();

    auto client = makeClient(fake);
    const auto bySeconds = client.Post("/seconds", "{}", "application/json");
    ASSERT_TRUE(bySeconds);
    EXPECT_EQ(bySeconds->status, 429);
    EXPECT_EQ(bySeconds->get_header_value("Retry-After"), "120");

    const auto byDate = client.Post("/date", "{}", "application/json");
    ASSERT_TRUE(byDate);
    EXPECT_EQ(byDate->status, 429);
    EXPECT_EQ(byDate->get_header_value("Retry-After"), date);
    EXPECT_EQ(date.size(), 29U); // IMF-fixdate is fixed width
    EXPECT_EQ(date.substr(25), " GMT");
}

TEST(FakeIndexerTest, CutMidResponse)
{
    FakeIndexer fake;
    Rule cutLength;
    cutLength.pathRegex = "/cut-length";
    cutLength.bodySize = 1000;
    cutLength.cutAfter = 100;
    cutLength.chunkSize = 30;
    fake.addRule(cutLength);

    Rule cutChunked;
    cutChunked.pathRegex = "/cut-chunked";
    cutChunked.bodySize = 1000;
    cutChunked.cutAfter = 100;
    cutChunked.chunkSize = 50;
    cutChunked.framing = Framing::Chunked;
    fake.addRule(cutChunked);

    Rule headersOnly;
    headersOnly.pathRegex = "/cut-zero";
    headersOnly.body = R"({"never":"sent"})";
    headersOnly.cutAfter = 0;
    fake.addRule(headersOnly);
    fake.start();

    // Content-Length 1000, then exactly 100 body bytes and the connection closes.
    {
        const auto [head, body] =
            splitResponse(rawExchange(fake.port(), "GET /cut-length HTTP/1.1\r\nHost: fake\r\n\r\n"));
        EXPECT_NE(head.find("HTTP/1.1 200"), std::string::npos) << head;
        EXPECT_NE(head.find("Content-Length: 1000"), std::string::npos) << head;
        EXPECT_EQ(body, std::string(100, 'x'));
    }
    // Chunked: two 50-byte chunks, no terminating chunk.
    {
        const auto [head, body] =
            splitResponse(rawExchange(fake.port(), "GET /cut-chunked HTTP/1.1\r\nHost: fake\r\n\r\n"));
        EXPECT_NE(head.find("Transfer-Encoding: chunked"), std::string::npos) << head;
        const std::string chunk = "32\r\n" + std::string(50, 'x') + "\r\n";
        EXPECT_EQ(body, chunk + chunk);
    }
    // Headers only.
    {
        const auto [head, body] =
            splitResponse(rawExchange(fake.port(), "GET /cut-zero HTTP/1.1\r\nHost: fake\r\n\r\n"));
        EXPECT_NE(head.find("Content-Length: 16"), std::string::npos) << head;
        EXPECT_TRUE(body.empty());
    }

    // A real client sees a failed (truncated) transfer.
    auto client = makeClient(fake);
    EXPECT_FALSE(client.Get("/cut-length"));
    EXPECT_FALSE(client.Get("/cut-chunked"));
}

TEST(FakeIndexerTest, ChunkedExactSize)
{
    FakeIndexer fake;
    Rule filler;
    filler.pathRegex = "/filler";
    filler.bodySize = 100000;
    filler.chunkSize = 4096;
    filler.framing = Framing::Chunked;
    fake.addRule(filler);

    Rule json;
    json.pathRegex = "/json";
    json.body = R"({"took":1,"errors":false,"items":[]})";
    json.chunkSize = 7;
    json.framing = Framing::Chunked;
    fake.addRule(json);

    Rule exactLength;
    exactLength.pathRegex = "/length";
    exactLength.bodySize = 100000;
    exactLength.chunkSize = 4096;
    fake.addRule(exactLength);
    fake.start();

    auto client = makeClient(fake);
    const auto res = client.Get("/filler");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 200);
    EXPECT_EQ(res->get_header_value("Transfer-Encoding"), "chunked");
    EXPECT_FALSE(res->has_header("Content-Length"));
    EXPECT_EQ(res->body, std::string(100000, 'x'));

    const auto jsonRes = client.Get("/json");
    ASSERT_TRUE(jsonRes);
    EXPECT_EQ(jsonRes->get_header_value("Transfer-Encoding"), "chunked");
    EXPECT_EQ(jsonRes->body, R"({"took":1,"errors":false,"items":[]})");

    const auto lengthRes = client.Get("/length");
    ASSERT_TRUE(lengthRes);
    EXPECT_EQ(lengthRes->get_header_value("Content-Length"), "100000");
    EXPECT_EQ(lengthRes->body.size(), 100000U);

    // The raw wire: 24 full 4096-byte chunks (hex 1000), one of 1696 (hex 6a0) and the terminator.
    const auto [head, body] =
        splitResponse(rawExchange(fake.port(), "GET /filler HTTP/1.1\r\nHost: fake\r\nConnection: close\r\n\r\n"));
    std::string expected;
    for (int i = 0; i < 24; ++i)
    {
        expected += "1000\r\n" + std::string(4096, 'x') + "\r\n";
    }
    expected += "6a0\r\n" + std::string(1696, 'x') + "\r\n0\r\n\r\n";
    EXPECT_EQ(body, expected);
}

TEST(FakeIndexerTest, LargeContentLengthStreams)
{
    constexpr std::size_t ONE_GIB {1024ULL * 1024 * 1024};
    FakeIndexer fake;
    Rule big;
    big.pathRegex = "/big";
    big.bodySize = ONE_GIB; // streamed from a 16 KiB filler, never allocated
    fake.addRule(big);
    fake.start();

    const int fd = connectTo(fake.port());
    ASSERT_GE(fd, 0);
    ASSERT_TRUE(sendAll(fd, "GET /big HTTP/1.1\r\nHost: fake\r\n\r\n"));
    std::string received;
    char buffer[64 * 1024];
    while (received.size() < 1024 * 1024)
    {
        const auto n = ::recv(fd, buffer, sizeof(buffer), 0);
        ASSERT_GT(n, 0);
        received.append(buffer, static_cast<std::size_t>(n));
    }
    const auto [head, body] = splitResponse(received);
    EXPECT_NE(head.find("Content-Length: " + std::to_string(ONE_GIB)), std::string::npos) << head;
    EXPECT_EQ(body.find_first_not_of('x'), std::string::npos);
    ::close(fd); // the client gives up mid-body

    // The server notices and a stop does not wait for the remaining GiB.
    const auto begin = std::chrono::steady_clock::now();
    fake.stop();
    EXPECT_LT(std::chrono::steady_clock::now() - begin, 2s);
}

TEST(FakeIndexerTest, RecordsBodyOnlyWhenAsked)
{
    {
        FakeIndexer fake; // default: bodies are not retained
        fake.start();
        auto client = makeClient(fake);
        ASSERT_TRUE(client.Post("/_bulk", "payload", "application/x-ndjson"));
        const auto recorded = fake.requests();
        ASSERT_EQ(recorded.size(), 1U);
        EXPECT_TRUE(recorded[0].body.empty());
        EXPECT_EQ(recorded[0].bodySize, 7U);
    }
    {
        FakeIndexerOptions options;
        options.recordBodies = true;
        FakeIndexer fake(options);
        fake.start();
        auto client = makeClient(fake);
        ASSERT_TRUE(client.Post("/_bulk", "payload", "application/x-ndjson"));
        const auto recorded = fake.requests();
        ASSERT_EQ(recorded.size(), 1U);
        EXPECT_EQ(recorded[0].body, "payload");
        EXPECT_EQ(recorded[0].bodySize, 7U);
    }
}

TEST(FakeIndexerTest, RecordsRemotePortPerConnection)
{
    FakeIndexer fake;
    fake.start();
    auto first = makeClient(fake);
    auto second = makeClient(fake);
    for (int i = 0; i < 3; ++i)
    {
        ASSERT_TRUE(first.Get("/a"));
        ASSERT_TRUE(second.Get("/b"));
    }

    const auto recorded = fake.requests();
    ASSERT_EQ(recorded.size(), 6U);
    EXPECT_EQ(fake.distinctRemotePorts(), 2U); // keep-alive: one connection per client
    for (std::size_t i = 0; i < recorded.size(); ++i)
    {
        EXPECT_EQ(recorded[i].remoteAddr, "127.0.0.1");
        EXPECT_GT(recorded[i].remotePort, 0);
        EXPECT_EQ(recorded[i].remotePort, recorded[i % 2].remotePort);
        if (i > 0)
        {
            EXPECT_GE(recorded[i].receivedAt, recorded[i - 1].receivedAt);
        }
    }
    EXPECT_NE(recorded[0].remotePort, recorded[1].remotePort);

    // A raw connection's port is the one recorded.
    const int fd = connectTo(fake.port());
    ASSERT_GE(fd, 0);
    const int port = localPort(fd);
    ASSERT_TRUE(sendAll(fd, "GET /raw HTTP/1.1\r\nHost: fake\r\n\r\n"));
    ASSERT_TRUE(fake.waitForRequests(7, 10s));
    EXPECT_EQ(fake.requests().back().remotePort, port);
    ::close(fd);
}

TEST(FakeIndexerTest, SilentServerReportsEof)
{
    SilentServer silent;
    const int fd = connectTo(silent.port());
    ASSERT_GE(fd, 0);
    const std::string request = "GET / HTTP/1.1\r\nHost: fake\r\n\r\n";
    ASSERT_TRUE(sendAll(fd, request));
    ASSERT_TRUE(silent.waitForAccepted(1, 10s));

    // It never answers.
    pollfd readable {fd, POLLIN, 0};
    EXPECT_EQ(::poll(&readable, 1, 100), 0);
    EXPECT_FALSE(silent.waitForEof(0, 10ms).has_value());

    const auto closedAt = std::chrono::steady_clock::now();
    ::close(fd);
    const auto eof = silent.waitForEof(0, 5s);
    ASSERT_TRUE(eof.has_value());
    EXPECT_GE(*eof, closedAt);
    EXPECT_LE(*eof - closedAt, 100ms) << toMs(*eof - closedAt) << " ms";

    const auto connections = silent.connections();
    ASSERT_EQ(connections.size(), 1U);
    EXPECT_EQ(connections[0].bytesRead, request.size());
    EXPECT_GT(connections[0].remotePort, 0);
    EXPECT_FALSE(silent.waitForEof(1, 10ms).has_value()); // no such socket
}

TEST(FakeIndexerTest, StalledUploadServerStallsAndReportsEof)
{
    constexpr std::size_t BODY {64ULL * 1024 * 1024};
    StalledUploadServer stalled;
    EXPECT_GE(stalled.receiveBufferBytes(), 64 * 1024);
    EXPECT_LT(stalled.receiveBufferBytes(), 1024 * 1024);

    const int fd = connectTo(stalled.port());
    ASSERT_GE(fd, 0);
    const int clientPort = localPort(fd);
    ASSERT_TRUE(stalled.waitForAccepted(1, 10s));
    ASSERT_EQ(::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL) | O_NONBLOCK), 0);

    // Push the 64 MiB body until the socket stays unwritable for 300 ms: the upload is stalled.
    const std::string piece(64 * 1024, 'b');
    std::size_t written {0};
    while (written < BODY)
    {
        pollfd writable {fd, POLLOUT, 0};
        if (::poll(&writable, 1, 300) <= 0)
        {
            break;
        }
        const auto n = ::send(fd, piece.data(), std::min(piece.size(), BODY - written), MSG_NOSIGNAL);
        if (n > 0)
        {
            written += static_cast<std::size_t>(n);
        }
    }
    EXPECT_GT(written, 0U);
    EXPECT_LT(written, BODY);
    auto connections = stalled.connections();
    ASSERT_EQ(connections.size(), 1U);
    EXPECT_EQ(connections[0].bytesRead, 0U);
    EXPECT_EQ(connections[0].remotePort, clientPort);

    // Closing with unsent data: the FIN sits behind the data, so nothing is seen until the server reads.
    ::close(fd);
    EXPECT_FALSE(stalled.waitForEof(0, 100ms).has_value());
    stalled.resumeReading();
    const auto eof = stalled.waitForEof(0, 5s);
    ASSERT_TRUE(eof.has_value());
    connections = stalled.connections();
    EXPECT_EQ(connections[0].bytesRead, written);
}

TEST(FakeIndexerTest, RawServersStopWithOpenSockets)
{
    auto silent = std::make_unique<SilentServer>();
    auto stalled = std::make_unique<StalledUploadServer>();
    const int toSilent = connectTo(silent->port());
    const int toStalled = connectTo(stalled->port());
    ASSERT_GE(toSilent, 0);
    ASSERT_GE(toStalled, 0);
    ASSERT_TRUE(silent->waitForAccepted(1, 10s));
    ASSERT_TRUE(stalled->waitForAccepted(1, 10s));

    const auto begin = std::chrono::steady_clock::now();
    silent->stop();
    silent->stop();  // idempotent
    stalled.reset(); // the destructor stops too
    silent.reset();
    EXPECT_LT(std::chrono::steady_clock::now() - begin, 2s);

    // The peers see their connections closed.
    char byte {};
    EXPECT_LE(::recv(toSilent, &byte, 1, 0), 0);
    EXPECT_LE(::recv(toStalled, &byte, 1, 0), 0);
    ::close(toSilent);
    ::close(toStalled);
}
