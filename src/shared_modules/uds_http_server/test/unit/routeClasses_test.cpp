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
#include <cstdio>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using wazuh::uds_http::HttpRequest;
using wazuh::uds_http::HttpResponse;
using wazuh::uds_http::IHttpResponder;
using wazuh::uds_http::makeUdsHttpServer;
using wazuh::uds_http::Method;
using wazuh::uds_http::RouteClass;
using wazuh::uds_http::RouteOptions;
using wazuh::uds_http::UdsHttpServerConfig;
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

    /// Parks request+responder pairs: holding the REQUEST keeps its byte reservation alive, and
    /// holding the RESPONDER keeps the session (and its class-occupancy charge) open.
    struct Parking
    {
        std::mutex mutex;
        std::vector<std::pair<std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder>>> parked;

        wazuh::uds_http::RouteHandler handler()
        {
            return [this](std::shared_ptr<const HttpRequest> request, std::shared_ptr<IHttpResponder> responder)
            {
                std::lock_guard<std::mutex> lock {mutex};
                parked.emplace_back(std::move(request), std::move(responder));
            };
        }

        std::size_t count()
        {
            std::lock_guard<std::mutex> lock {mutex};
            return parked.size();
        }

        void releaseAll()
        {
            std::lock_guard<std::mutex> lock {mutex};
            for (auto& entry : parked)
            {
                entry.second->send(HttpResponse::json(200, "{}"));
            }
            parked.clear();
        }
    };

    wazuh::uds_http::RouteHandler answer200()
    {
        return [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
        {
            responder->send(HttpResponse::json(200, "{}"));
        };
    }

    /// Writes a request and keeps the connection open unread, so its deferral stays parked.
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

/**
 * The central QoS guarantee: with the data plane pinned at its session cap, Control and
 * Liveness requests still answer -- the reserved headroom is what Data can never consume.
 */
TEST(RouteClassesTest, DataSaturationDoesNotShedControlNorLiveness)
{
    const auto path = uniqueSocketPath("class_sat");
    auto server = makeUdsHttpServer();

    Parking dataParking;
    server->addRoute(Method::Post, "/ingest", dataParking.handler(), RouteOptions {RouteClass::Data});
    server->addRoute(Method::Get, "/offset", answer200(), RouteOptions {RouteClass::Control});
    server->addRoute(Method::Get, "/", answer200(), RouteOptions {RouteClass::Liveness});

    auto config = configFor(path);
    config.maxConnections = 8;
    config.reservedControlConnections = 2; // ceiling is 8/4 = 2; Data resolves to 6
    server->start(config);

    std::vector<std::unique_ptr<OpenConnection>> pinned;
    for (int i = 0; i < 6; ++i)
    {
        pinned.push_back(std::make_unique<OpenConnection>(path, peerRequest("POST", "/ingest", "payload")));
    }
    ASSERT_TRUE(waitUntil([&] { return dataParking.count() == 6; })) << "the data plane must reach its cap";

    // The 7th data request is confined by ITS class: rejected at admission, not at accept.
    const auto shed = sendRaw(path, peerRequest("POST", "/ingest", "payload"));
    EXPECT_EQ(503, shed.status);
    EXPECT_NE(std::string::npos, shed.body.find("Data session limit reached")) << shed.body;

    // Control and Liveness ride the reserved headroom, repeatedly.
    for (int i = 0; i < 5; ++i)
    {
        EXPECT_EQ(200, sendRaw(path, peerRequest("GET", "/offset", "")).status) << "control poll " << i;
        EXPECT_EQ(200, sendRaw(path, peerRequest("GET", "/", "")).status) << "liveness probe " << i;
    }

    const auto diagnostics = server->diagnostics();
    EXPECT_EQ(6U, diagnostics.sessionsByClass[static_cast<std::size_t>(RouteClass::Data)]);

    dataParking.releaseAll();
    server->stop();
}

TEST(RouteClassesTest, ClassBodyCapAnswers413AtHeaders)
{
    const auto path = uniqueSocketPath("class_413");
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post, "/scan", answer200(), RouteOptions {RouteClass::Control});
    server->start(configFor(path)); // control cap: 64 KiB

    // Head only, declaring more than the cap and sending ZERO body bytes: the 413 must come from
    // the declared length at headers-complete.
    const std::string head = "POST /scan HTTP/1.1\r\nHost: localhost\r\nContent-Length: 65537\r\n"
                             "Connection: close\r\n\r\n";
    const auto response = sendRaw(path, head);
    EXPECT_EQ(413, response.status);
    EXPECT_NE(std::string::npos, response.body.find("control-class limit")) << response.body;

    // At the cap is fine.
    EXPECT_EQ(200, sendRaw(path, peerRequest("POST", "/scan", std::string(1024, 'x'))).status);
    server->stop();
}

TEST(RouteClassesTest, ClassSessionCapAnswers503AndReleasesOnClose)
{
    const auto path = uniqueSocketPath("class_cap");
    auto server = makeUdsHttpServer();

    Parking parking;
    server->addRoute(Method::Post, "/ctl", parking.handler(), RouteOptions {RouteClass::Control});

    auto config = configFor(path);
    config.controlPolicy.maxSessions = 2;
    server->start(config);

    OpenConnection first {path, peerRequest("POST", "/ctl", "a")};
    OpenConnection second {path, peerRequest("POST", "/ctl", "b")};
    ASSERT_TRUE(waitUntil([&] { return parking.count() == 2; }));

    const auto rejected = sendRaw(path, peerRequest("POST", "/ctl", "c"));
    EXPECT_EQ(503, rejected.status);
    EXPECT_NE(std::string::npos, rejected.body.find("Control session limit reached")) << rejected.body;

    parking.releaseAll();
    ASSERT_TRUE(waitUntil(
        [&] { return server->diagnostics().sessionsByClass[static_cast<std::size_t>(RouteClass::Control)] == 0; }))
        << "replying must release the class occupancy";
    EXPECT_TRUE(waitUntil([&] { return sendRaw(path, peerRequest("POST", "/ctl", "d")).status != 503; }))
        << "a freed slot must admit again";

    parking.releaseAll();
    server->stop();
}

TEST(RouteClassesTest, ReservedHeadroomKeepsControlServedUnderADataFlood)
{
    const auto path = uniqueSocketPath("class_flood");
    auto server = makeUdsHttpServer();

    Parking dataParking;
    server->addRoute(Method::Post, "/ingest", dataParking.handler(), RouteOptions {RouteClass::Data});
    server->addRoute(Method::Get, "/offset", answer200(), RouteOptions {RouteClass::Control});

    auto config = configFor(path);
    config.maxConnections = 8;
    config.reservedControlConnections = 2;
    server->start(config);

    // Saturate, then keep hammering the data plane while control polls. ONE flooder on purpose:
    // pre-classification connections occupy GLOBAL accept slots (class membership is unknowable
    // before the head is read), so the hard "every poll answers" guarantee holds while the
    // concurrency of NEW data connects stays below the reserve -- the documented residual of the
    // model. At or above the reserve, a transient accept race can shed a control poll too.
    std::vector<std::unique_ptr<OpenConnection>> pinned;
    for (int i = 0; i < 6; ++i)
    {
        pinned.push_back(std::make_unique<OpenConnection>(path, peerRequest("POST", "/ingest", "p")));
    }
    ASSERT_TRUE(waitUntil([&] { return dataParking.count() == 6; }));

    std::atomic<bool> flooding {true};
    std::vector<std::thread> flooders;
    for (int i = 0; i < 1; ++i)
    {
        flooders.emplace_back(
            [&]
            {
                while (flooding.load())
                {
                    (void)sendRaw(path, peerRequest("POST", "/ingest", "p"));
                }
            });
    }

    int served = 0;
    for (int i = 0; i < 10; ++i)
    {
        if (sendRaw(path, peerRequest("GET", "/offset", "")).status == 200)
        {
            ++served;
        }
    }
    flooding.store(false);
    for (auto& thread : flooders)
    {
        thread.join();
    }
    EXPECT_EQ(10, served) << "every control poll must ride the reserved headroom through the flood";

    dataParking.releaseAll();
    server->stop();
}

TEST(RouteClassesTest, BoolAddRouteShimMapsToDataAndLiveness)
{
    const auto path = uniqueSocketPath("class_shim");
    auto server = makeUdsHttpServer();
    // The pre-class spelling: true was "counts against the budget" (the data plane), false was
    // the exempt liveness probes. The class body caps make the mapping observable on the wire.
    server->addRoute(Method::Post, "/legacy-data", answer200(), true);
    server->addRoute(Method::Post, "/legacy-probe", answer200(), false);
    server->start(configFor(path));

    const std::string body(8 * 1024, 'x'); // over Liveness's 4 KiB, nothing to Data
    EXPECT_EQ(200, sendRaw(path, peerRequest("POST", "/legacy-data", body)).status);
    EXPECT_EQ(413, sendRaw(path, peerRequest("POST", "/legacy-probe", body)).status);
    server->stop();
}

TEST(RouteClassesTest, APerRouteSessionOverrideConfinesThatRouteOnly)
{
    const auto path = uniqueSocketPath("class_route");
    auto server = makeUdsHttpServer();

    Parking parking;
    RouteOptions capped {RouteClass::Control};
    capped.maxSessions = 1;
    server->addRoute(Method::Post, "/serialized", parking.handler(), capped);
    server->addRoute(Method::Get, "/offset", answer200(), RouteOptions {RouteClass::Control});
    server->start(configFor(path));

    OpenConnection first {path, peerRequest("POST", "/serialized", "a")};
    ASSERT_TRUE(waitUntil([&] { return parking.count() == 1; }));

    EXPECT_EQ(503, sendRaw(path, peerRequest("POST", "/serialized", "b")).status)
        << "the route's own cap must reject the second";
    EXPECT_EQ(200, sendRaw(path, peerRequest("GET", "/offset", "")).status)
        << "a sibling route of the SAME class must be untouched by the route-level cap";

    parking.releaseAll();
    server->stop();
}

TEST(RouteClassesTest, APerRouteBodyCapOverridesTheClassCapOnThatRouteOnly)
{
    const auto path = uniqueSocketPath("class_body");
    auto server = makeUdsHttpServer();

    RouteOptions capped {RouteClass::Control};
    capped.maxBodyBytes = 4096;
    server->addRoute(Method::Post, "/scan", answer200(), capped);
    server->addRoute(Method::Post, "/ctl", answer200(), RouteOptions {RouteClass::Control});
    server->start(configFor(path));

    // One byte over the ROUTE's cap, well under the 64 KiB class cap. Declared length only,
    // zero body bytes: the rejection must come at headers-complete, and the body text is still
    // keyed on the CLASS (the cap that fired is the route's).
    const std::string head = "POST /scan HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4097\r\n"
                             "Connection: close\r\n\r\n";
    const auto rejected = sendRaw(path, head);
    EXPECT_EQ(413, rejected.status);
    EXPECT_NE(std::string::npos, rejected.body.find("control-class limit")) << rejected.body;

    const std::string body(4097, 'x');
    EXPECT_EQ(200, sendRaw(path, peerRequest("POST", "/ctl", body)).status)
        << "a sibling route of the SAME class must keep the class cap";
    EXPECT_EQ(200, sendRaw(path, peerRequest("POST", "/scan", std::string(4096, 'x'))).status)
        << "at the route cap is fine";
    server->stop();
}

TEST(RouteClassesTest, DiagnosticsExposePerClassOccupancy)
{
    const auto path = uniqueSocketPath("class_diag");
    auto server = makeUdsHttpServer();

    Parking dataParking;
    Parking controlParking;
    server->addRoute(Method::Post, "/ingest", dataParking.handler(), RouteOptions {RouteClass::Data});
    server->addRoute(Method::Post, "/ctl", controlParking.handler(), RouteOptions {RouteClass::Control});
    server->start(configFor(path));

    OpenConnection data {path, peerRequest("POST", "/ingest", "d")};
    OpenConnection control {path, peerRequest("POST", "/ctl", "c")};
    ASSERT_TRUE(waitUntil([&] { return dataParking.count() == 1 && controlParking.count() == 1; }));

    const auto snapshot = server->diagnostics();
    EXPECT_EQ(1U, snapshot.sessionsByClass[static_cast<std::size_t>(RouteClass::Data)]);
    EXPECT_EQ(1U, snapshot.sessionsByClass[static_cast<std::size_t>(RouteClass::Control)]);
    EXPECT_EQ(0U, snapshot.sessionsByClass[static_cast<std::size_t>(RouteClass::Liveness)]);

    dataParking.releaseAll();
    controlParking.releaseAll();
    server->stop();
}
