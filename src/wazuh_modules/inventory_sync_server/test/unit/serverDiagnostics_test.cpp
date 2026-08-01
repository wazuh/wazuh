/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 1, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "http_server/IUdsHttpServer.hpp"
#include "http_server/udsHttpServerFactory.hpp"
#include "inventory_sync_server.h"
#include "testLogRecorder.hpp"
#include "udsTestClient.hpp"

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using invsync::http::HttpRequest;
using invsync::http::HttpResponse;
using invsync::http::IHttpResponder;
using invsync::http::makeUdsHttpServer;
using invsync::http::Method;
using invsync::http::UdsHttpServerConfig;
using invsync::test::LogRecorder;
using invsync::test::peerRequest;
using invsync::test::sendRaw;
using invsync::test::testLogCallback;
using invsync::test::uniqueSocketPath;

namespace
{
    UdsHttpServerConfig configFor(const std::string& socketPath)
    {
        UdsHttpServerConfig config;
        config.socketPath = socketPath;
        config.ioThreads = 2;
        config.headerTimeoutSec = 2;
        config.bodyTimeoutSec = 2;
        config.responseTimeoutSec = 5;
        config.drainTimeoutSec = 1;
        return config;
    }

    /// Parks responders so a deferral stays open exactly as long as the test wants.
    struct Parking
    {
        std::mutex mutex;
        std::vector<std::shared_ptr<IHttpResponder>> responders;
        std::atomic<int> dispatched {0};

        invsync::http::RouteHandler handler()
        {
            return [this](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
            {
                {
                    std::lock_guard<std::mutex> lock {mutex};
                    responders.push_back(std::move(responder));
                }
                dispatched.fetch_add(1);
            };
        }

        bool waitFor(int count, std::chrono::seconds timeout = std::chrono::seconds {10})
        {
            const auto deadline = std::chrono::steady_clock::now() + timeout;
            while (dispatched.load() < count && std::chrono::steady_clock::now() < deadline)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds {5});
            }
            return dispatched.load() >= count;
        }
    };

    /// Connects and writes @p request, then hands back the fd WITHOUT reading the response, so the
    /// test can close it mid-exchange. -1 on failure.
    int connectAndSend(const std::string& socketPath, const std::string& request)
    {
        const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0)
        {
            return -1;
        }
        ::sockaddr_un address {};
        address.sun_family = AF_UNIX;
        std::snprintf(address.sun_path, sizeof(address.sun_path), "%s", socketPath.c_str());
        if (::connect(fd, reinterpret_cast<::sockaddr*>(&address), sizeof(address)) != 0 ||
            ::write(fd, request.data(), request.size()) < 0)
        {
            ::close(fd);
            return -1;
        }
        return fd;
    }
} // namespace

/**
 * Diagnosability of the transport: every rejection an operator may need to explain must leave a
 * (throttled) trace, and a peer that disappears must not pin resources.
 *
 * The suite starts and stops the module once so the .so's hidden log sink points at LogRecorder;
 * without that, LOGFN_* from a directly-constructed server goes nowhere (see testLogRecorder.hpp).
 */
class ServerDiagnosticsTest : public ::testing::Test
{
protected:
    static void SetUpTestSuite()
    {
        inventory_sync_server_config_t config {};
        const auto path = uniqueSocketPath("diag_sink");
        std::snprintf(config.socket_path, sizeof(config.socket_path), "%s", path.c_str());
        config.io_threads = 1;
        config.drain_timeout = 1;
        inventory_sync_server_start(testLogCallback, &config);
        LogRecorder::waitForMessageContaining("worker thread running");
        inventory_sync_server_stop();
    }

    void SetUp() override
    {
        LogRecorder::clear();
    }
};

TEST_F(ServerDiagnosticsTest, AThrowingHandlerAnswers500AndItsLogIsThrottled)
{
    const auto path = uniqueSocketPath("throwing");
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post,
                     "/inventory/sync",
                     [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder>)
                     { throw std::runtime_error {"handler bug"}; });
    server->start(configFor(path));

    const auto first = sendRaw(path, peerRequest("POST", "/inventory/sync", "x"));
    const auto second = sendRaw(path, peerRequest("POST", "/inventory/sync", "x"));

    EXPECT_EQ(500, first.status);
    EXPECT_EQ(500, second.status);
    EXPECT_TRUE(LogRecorder::waitForMessageContaining("handler bug")) << "the ERROR must carry the reason";
    EXPECT_EQ(1U, LogRecorder::countMessagesContaining("failed while being dispatched"))
        << "a deterministic handler bug fires per request; the second occurrence must be throttled";
}

TEST_F(ServerDiagnosticsTest, ARejectedOverLimitRequestLeavesAThrottledTrace)
{
    const auto path = uniqueSocketPath("limitlog");
    auto config = configFor(path);
    config.maxBodySize = 64;

    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post,
                     "/inventory/sync",
                     [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
                     { responder->send(HttpResponse::json(200, "{}")); });
    server->start(config);

    const auto response = sendRaw(path, peerRequest("POST", "/inventory/sync", std::string(100, 'x')));

    EXPECT_EQ(413, response.status);
    EXPECT_TRUE(LogRecorder::waitForMessageContaining("exceeding a configured limit"))
        << "a 413 the peer may never read must at least be visible in this log";
    EXPECT_TRUE(LogRecorder::sawMessageContaining("413"));
}

TEST_F(ServerDiagnosticsTest, AnUnknownRouteLeavesAThrottledTrace)
{
    const auto path = uniqueSocketPath("noroutelog");
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post,
                     "/inventory/sync",
                     [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
                     { responder->send(HttpResponse::json(200, "{}")); });
    server->start(configFor(path));

    const auto response = sendRaw(path, peerRequest("POST", "/nope", "x"));

    EXPECT_EQ(404, response.status);
    EXPECT_TRUE(LogRecorder::waitForMessageContaining("no route for POST '/nope'"))
        << "a route mismatch with remoted must be visible on this side";
}

TEST_F(ServerDiagnosticsTest, APeerClosingDuringDeferralFreesItsConnectionSlotPromptly)
{
    const auto path = uniqueSocketPath("peergone");
    auto config = configFor(path);
    // The point of the test: the slot must come back because the peer LEFT, not because a timer
    // fired. Long timeout + a 1-connection cap make the difference observable.
    config.responseTimeoutSec = 300;
    config.maxConnections = 1;

    Parking parking;
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post, "/slow", parking.handler());
    server->addRoute(Method::Post,
                     "/fast",
                     [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
                     { responder->send(HttpResponse::json(200, "{}")); });
    server->start(config);

    const int slowFd = connectAndSend(path, peerRequest("POST", "/slow", "x"));
    ASSERT_GE(slowFd, 0);
    ASSERT_TRUE(parking.waitFor(1)) << "the deferral must be in flight before the peer leaves";

    // The peer gives up. Its request occupies the only connection slot; without EOF detection the
    // slot would stay pinned for the whole responseTimeout.
    ::close(slowFd);

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds {3};
    int lastStatus {0};
    while (std::chrono::steady_clock::now() < deadline)
    {
        lastStatus = sendRaw(path, peerRequest("POST", "/fast", "y")).status;
        if (lastStatus == 200)
        {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds {25});
    }
    EXPECT_EQ(200, lastStatus) << "the abandoned deferral must release its connection slot promptly";
}

TEST_F(ServerDiagnosticsTest, ARemovedSocketFileIsReportedWhenTheServerStops)
{
    const auto path = uniqueSocketPath("takeover");
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post,
                     "/inventory/sync",
                     [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
                     { responder->send(HttpResponse::json(200, "{}")); });
    server->start(configFor(path));

    // Someone takes the path away while the server is running: unlinking blindly at stop would
    // remove whatever they put there, and staying silent would hide the takeover.
    ::unlink(path.c_str());
    server->stop();

    EXPECT_TRUE(LogRecorder::waitForMessageContaining("Not unlinking"))
        << "two managers fighting over the socket must leave a trace";
    EXPECT_TRUE(LogRecorder::sawMessageContaining("something removed it"));
}
