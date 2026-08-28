/*
 * Wazuh shared UDS HTTP server library - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "testLogRecorder.hpp"
#include "udsTestClient.hpp"
#include <uds_http_server/IUdsHttpServer.hpp>
#include <uds_http_server/udsHttpServerFactory.hpp>

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using wazuh::uds_http::HttpRequest;
using wazuh::uds_http::HttpResponse;
using wazuh::uds_http::IHttpResponder;
using wazuh::uds_http::makeUdsHttpServer;
using wazuh::uds_http::Method;
using wazuh::uds_http::TransportDiagnostics;
using wazuh::uds_http::UdsHttpServerConfig;
using wazuh::uds_http::test::LogRecorder;
using wazuh::uds_http::test::peerRequest;
using wazuh::uds_http::test::sendRaw;
using wazuh::uds_http::test::uniqueSocketPath;

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

    /// Raw POSIX sender that writes a request and deliberately does NOT read the response, so a
    /// parked deferral stays observable in the diagnostics for as long as the test wants.
    /// EXPECT rather than ASSERT: gtest's fatal assertions cannot be used in a constructor.
    struct OpenConnection
    {
        int fd {-1};

        explicit OpenConnection(const std::string& socketPath, const std::string& bytes)
        {
            fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
            EXPECT_GE(fd, 0);
            if (fd < 0)
            {
                return;
            }
            sockaddr_un addr {};
            addr.sun_family = AF_UNIX;
            std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socketPath.c_str());
            EXPECT_EQ(0, ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)));
            EXPECT_EQ(static_cast<ssize_t>(bytes.size()), ::write(fd, bytes.data(), bytes.size()));
        }

        ~OpenConnection()
        {
            if (fd >= 0)
            {
                ::close(fd);
            }
        }
    };

    bool waitUntil(const std::function<bool()>& condition, std::chrono::milliseconds timeout = std::chrono::seconds {5})
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline)
        {
            if (condition())
            {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds {10});
        }
        return condition();
    }
} // namespace

TEST(TransportDiagnosticsTest, AllZeroBeforeStart)
{
    auto server = makeUdsHttpServer();
    const auto snapshot = server->diagnostics();
    EXPECT_EQ(0U, snapshot.budgetAvailableBytes);
    EXPECT_EQ(0U, snapshot.budgetInFlightBytes);
    EXPECT_EQ(0U, snapshot.budgetInFlightCount);
    EXPECT_EQ(0U, snapshot.liveSessions);
}

TEST(TransportDiagnosticsTest, AParkedDeferralIsVisibleAndReleasesOnReply)
{
    const auto path = uniqueSocketPath("diag_park");
    auto server = makeUdsHttpServer();

    std::mutex mutex;
    // Request AND responder: the budget reservation travels with the REQUEST (dropping it
    // releases the bytes immediately, by contract), so holding only the responder would show
    // nothing in the diagnostics.
    std::vector<std::pair<std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder>>> parked;
    server->addRoute(Method::Post,
                     "/park",
                     [&](std::shared_ptr<const HttpRequest> request, std::shared_ptr<IHttpResponder> responder)
                     {
                         std::lock_guard<std::mutex> lock {mutex};
                         parked.emplace_back(std::move(request), std::move(responder));
                     });
    server->start(configFor(path));

    const auto idle = server->diagnostics();
    EXPECT_GT(idle.budgetAvailableBytes, 0U) << "the default budget must be enabled and empty";
    EXPECT_EQ(0U, idle.budgetInFlightCount);
    EXPECT_EQ(0U, idle.liveSessions);

    const std::string body(1024, 'x');
    OpenConnection connection {path, peerRequest("POST", "/park", body)};

    ASSERT_TRUE(waitUntil([&] { return server->diagnostics().budgetInFlightCount == 1; }));
    const auto busy = server->diagnostics();
    EXPECT_EQ(1U, busy.liveSessions);
    EXPECT_GE(busy.budgetInFlightBytes, body.size()) << "the reservation covers at least the declared payload";
    EXPECT_EQ(idle.budgetAvailableBytes, busy.budgetAvailableBytes + busy.budgetInFlightBytes)
        << "available + in-flight must equal the configured capacity";

    {
        std::lock_guard<std::mutex> lock {mutex};
        ASSERT_EQ(1U, parked.size());
        parked.front().second->send(HttpResponse::json(200, "{}"));
        parked.clear();
    }

    EXPECT_TRUE(waitUntil(
        [&]
        {
            const auto after = server->diagnostics();
            return after.budgetInFlightCount == 0 && after.budgetInFlightBytes == 0 && after.liveSessions == 0;
        }))
        << "replying and dropping the request must return the diagnostics to quiescent";

    server->stop();
    const auto stopped = server->diagnostics();
    EXPECT_EQ(0U, stopped.budgetInFlightCount) << "diagnostics stay callable and quiesced after stop()";
    EXPECT_EQ(0U, stopped.liveSessions);
}

/**
 * RF-6, the extraction's stability contract: with the first consumer's identity injected, the
 * operator-visible lines render byte-identically to what the module logged before the extraction.
 */
TEST(TransportDiagnosticsTest, IdentityInjectionRendersTheConsumerVocabulary)
{
    LogRecorder::clear();
    const auto path = uniqueSocketPath("diag_identity");
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Get,
                     "/",
                     [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
                     { responder->send(HttpResponse::json(200, "{}")); });

    auto config = configFor(path);
    config.logTag = "wazuh-manager-modulesd:inventory-sync-server:server";
    config.serverName = "inventory sync";
    server->start(config);

    EXPECT_TRUE(LogRecorder::waitForMessageContaining("inventory sync server bound to '"))
        << "the startup line must carry the consumer's vocabulary";

    server->stopAccepting();
    EXPECT_TRUE(LogRecorder::waitForMessageContaining("inventory sync server is no longer accepting on '"));
    server->stop();
    EXPECT_TRUE(LogRecorder::waitForMessageContaining("inventory sync server fully stopped."));
}

/// The clamp warning fires only when the ceiling moved the value, so a reserve that fits under it
/// left no trace, and that reserve is what an operator sizes max_parallel_connections against.
TEST(TransportDiagnosticsTest, TheStartupLineReportsTheResolvedRouteClasses)
{
    LogRecorder::clear();
    const auto path = uniqueSocketPath("diag_classes");
    auto server = makeUdsHttpServer();

    auto config = configFor(path);
    config.serverName = "test";
    config.maxConnections = 64;
    config.reservedControlConnections = 8; // under the ceiling of 64 / 4, so the clamp stays quiet
    server->start(config);

    EXPECT_TRUE(LogRecorder::waitForMessageContaining("max 64 connection(s), 8 reserved for control, "
                                                      "56 data session(s)"))
        << "the startup line must report the resolved reserve and the data session cap";

    server->stopAccepting();
    server->stop();
}

TEST(TransportDiagnosticsTest, TheBudgetHintSentenceRendersOnlyWhenConfigured)
{
    LogRecorder::clear();
    const auto path = uniqueSocketPath("diag_hint");
    auto server = makeUdsHttpServer();

    std::mutex mutex;
    // Request AND responder: the budget reservation travels with the REQUEST (dropping it
    // releases the bytes immediately, by contract), so holding only the responder would show
    // nothing in the diagnostics.
    std::vector<std::pair<std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder>>> parked;
    server->addRoute(Method::Post,
                     "/park",
                     [&](std::shared_ptr<const HttpRequest> request, std::shared_ptr<IHttpResponder> responder)
                     {
                         std::lock_guard<std::mutex> lock {mutex};
                         parked.emplace_back(std::move(request), std::move(responder));
                     });

    auto config = configFor(path);
    // Room for ONE request (overhead + a small body), so the second is shed by the budget. The
    // explicit maxBodySize matters: with the UNLIMITED default, start() clamps a small budget UP
    // to overhead + 1 MiB and nothing would ever be shed here.
    config.maxBodySize = 4096;
    config.maxInFlightBytes = 300U * 1024U;
    config.budgetOptionHint = "inventory_sync_server_max_inflight_bytes";
    server->start(config);

    OpenConnection first {path, peerRequest("POST", "/park", std::string(64, 'x'))};
    ASSERT_TRUE(waitUntil([&] { return server->diagnostics().budgetInFlightCount == 1; }));

    const auto response = sendRaw(path, peerRequest("POST", "/park", std::string(64, 'y')));
    EXPECT_EQ(503, response.status);
    EXPECT_TRUE(LogRecorder::waitForMessageContaining("Consider raising 'inventory_sync_server_max_inflight_bytes'."))
        << "the advice sentence must name the consumer's own internal option";

    {
        std::lock_guard<std::mutex> lock {mutex};
        for (const auto& entry : parked)
        {
            entry.second->send(HttpResponse::json(200, "{}"));
        }
        parked.clear();
    }
    server->stop();
}
