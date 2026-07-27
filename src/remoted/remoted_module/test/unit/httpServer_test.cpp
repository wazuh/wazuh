/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 21, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "http_server/IHttpServer.hpp"
#include "http_server/httpServerConfig.hpp"
#include "http_server/httpServerFactory.hpp"
#include "proc.hpp"

#include <gtest/gtest.h>

#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <thread>

using namespace remoted::http;

namespace
{
    // Responder stub that captures whatever a handler sends (once).
    class CapturingResponder final : public IHttpResponder
    {
    public:
        void send(HttpResponse response) override
        {
            if (!captured.has_value())
            {
                captured = std::move(response);
            }
        }

        std::optional<HttpResponse> captured;
    };

    // Zero-initialized C-ABI config, like remoted's `= {0}`.
    remoted_module_config_t zeroedConfig()
    {
        remoted_module_config_t config;
        std::memset(&config, 0, sizeof(config));
        return config;
    }
} // namespace

// ---------------------------------------------------------------------------
// Config builder
// ---------------------------------------------------------------------------

TEST(HttpServerConfigTest, DefaultsWhenEmpty)
{
    const auto config = buildHttpServerConfig(zeroedConfig());

    EXPECT_EQ(config.bindAddress, "127.0.0.1");
    EXPECT_EQ(config.port, 9443);
    EXPECT_EQ(config.ioThreads, static_cast<std::size_t>(cpp_get_nproc()));
    EXPECT_EQ(config.workerThreads, 2U * static_cast<std::size_t>(cpp_get_nproc()));
    EXPECT_EQ(config.maxBodySize, 16U * 1024U * 1024U);
    EXPECT_EQ(config.readTimeoutSec, 10U);
    EXPECT_EQ(config.writeTimeoutSec, 10U);
    EXPECT_EQ(config.requestTimeoutSec, 30U);
    EXPECT_EQ(config.maxUrlSize, 2048U);
    EXPECT_EQ(config.maxHeaderNameSize, 256U);
    EXPECT_EQ(config.maxHeaderValueSize, 8192U);
    EXPECT_EQ(config.maxHeaderCount, 64U);
    EXPECT_EQ(config.maxPipelinedRequests, 4U);
    EXPECT_EQ(config.concurrentAccepts, 2U);
    EXPECT_EQ(config.bufferSize, 8192U);
    EXPECT_EQ(config.maxInFlightBytes, 256U * 1024U * 1024U);
    EXPECT_EQ(config.maxParallelConnections, 512U);
    EXPECT_EQ(config.certificatePath, "etc/https-manager.cert");
    EXPECT_EQ(config.privateKeyPath, "etc/https-manager.key");
}

TEST(HttpServerConfigTest, InFlightBytesStructWinsElseDefault)
{
    // remoted config field wins when positive.
    auto raw = zeroedConfig();
    raw.max_inflight_bytes = 5U * 1024U * 1024U;
    EXPECT_EQ(buildHttpServerConfig(raw).maxInFlightBytes, 5U * 1024U * 1024U);

    // Unset (<=0) -> built-in default (this setting is not env-driven).
    raw.max_inflight_bytes = 0;
    EXPECT_EQ(buildHttpServerConfig(raw).maxInFlightBytes, 256U * 1024U * 1024U);
}

TEST(HttpServerConfigTest, MaxConnectionsStructWinsElseDefault)
{
    auto raw = zeroedConfig();
    raw.max_parallel_connections = 128;
    EXPECT_EQ(buildHttpServerConfig(raw).maxParallelConnections, 128U);

    // Unset (<=0) -> built-in default (this setting is not env-driven).
    raw.max_parallel_connections = 0;
    EXPECT_EQ(buildHttpServerConfig(raw).maxParallelConnections, 512U);
}

TEST(HttpServerConfigTest, StructValuesWin)
{
    auto raw = zeroedConfig();
    raw.port = 12345;
    raw.io_threads = 3;
    raw.http_worker_threads = 7;
    raw.http_max_body_size = 1048576;
    raw.http_read_timeout = 20;
    raw.http_write_timeout = 15;
    raw.http_request_timeout = 45;
    raw.http_max_url_size = 4096;
    raw.http_max_header_name_size = 512;
    raw.http_max_header_value_size = 16384;
    raw.http_max_header_count = 128;
    raw.http_max_pipelined_requests = 8;
    raw.http_concurrent_accepts = 4;
    raw.http_buffer_size = 16384;
    std::snprintf(raw.certificate_path, sizeof(raw.certificate_path), "/custom/cert.pem");
    std::snprintf(raw.private_key_path, sizeof(raw.private_key_path), "/custom/key.pem");

    const auto config = buildHttpServerConfig(raw);

    EXPECT_EQ(config.port, 12345);
    EXPECT_EQ(config.ioThreads, 3U);
    EXPECT_EQ(config.workerThreads, 7U);
    EXPECT_EQ(config.maxBodySize, 1048576U);
    EXPECT_EQ(config.readTimeoutSec, 20U);
    EXPECT_EQ(config.writeTimeoutSec, 15U);
    EXPECT_EQ(config.requestTimeoutSec, 45U);
    EXPECT_EQ(config.maxUrlSize, 4096U);
    EXPECT_EQ(config.maxHeaderNameSize, 512U);
    EXPECT_EQ(config.maxHeaderValueSize, 16384U);
    EXPECT_EQ(config.maxHeaderCount, 128U);
    EXPECT_EQ(config.maxPipelinedRequests, 8U);
    EXPECT_EQ(config.concurrentAccepts, 4U);
    EXPECT_EQ(config.bufferSize, 16384U);
    EXPECT_EQ(config.certificatePath, "/custom/cert.pem");
    EXPECT_EQ(config.privateKeyPath, "/custom/key.pem");
}

// Negative values can't come from remoted (getDefine_Int_default's own min bound
// keeps them out), but buildHttpServerConfig() only trusts "positive", so a
// leftover/garbage negative must fall back to the default like 0 does, not
// underflow when cast to the unsigned HttpServerConfig fields.
TEST(HttpServerConfigTest, NegativeValuesFallBackToDefaults)
{
    auto raw = zeroedConfig();
    raw.port = -1;
    raw.io_threads = -5;
    raw.http_max_url_size = -2048;

    const auto config = buildHttpServerConfig(raw);

    EXPECT_EQ(config.port, 9443);
    EXPECT_EQ(config.ioThreads, static_cast<std::size_t>(cpp_get_nproc()));
    EXPECT_EQ(config.maxUrlSize, 2048U);
}

// ---------------------------------------------------------------------------
// Interface / registration (no network, no TLS)
// ---------------------------------------------------------------------------

TEST(HttpServerTest, RegisterRoutesDoesNotThrow)
{
    auto server = makeHttpServer();
    ASSERT_NE(server, nullptr);

    EXPECT_NO_THROW({
        server->addRoute(Method::Get,
                         "/",
                         [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> r)
                         { r->send(HttpResponse::json(200, "{}")); });
        server->addRoute(Method::Post,
                         "/events",
                         [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> r)
                         { r->send(HttpResponse::json(202, "{}")); });
    });
}

TEST(HttpServerTest, StartWithMissingCertificateThrowsAndStaysStopped)
{
    auto server = makeHttpServer();

    HttpServerConfig config;
    config.port = 0; // ask the OS for a free port (never actually bound: TLS fails first)
    config.certificatePath = "/nonexistent/remoted-tests/server.crt";
    config.privateKeyPath = "/nonexistent/remoted-tests/server.key";

    EXPECT_THROW(server->start(config), std::exception);

    // stopAccepting()/stop() must be safe after a failed start, and idempotent.
    EXPECT_NO_THROW(server->stopAccepting());
    EXPECT_NO_THROW(server->stop());
    EXPECT_NO_THROW(server->stop());
}

TEST(HttpServerTest, StopWithoutStartIsSafe)
{
    auto server = makeHttpServer();
    EXPECT_NO_THROW(server->stop());
}

TEST(HttpServerTest, StopAcceptingWithoutStartIsSafe)
{
    auto server = makeHttpServer();
    EXPECT_NO_THROW(server->stopAccepting());
}

TEST(HttpServerTest, StopAcceptingIsIdempotentAndStopStillFullyTearsDown)
{
    auto server = makeHttpServer();

    // Calling stopAccepting() repeatedly, then stop() repeatedly, must never re-invoke RESTinio's
    // own stop()/wait() a second time (documented as unsafe) -- the guard flag must hold up.
    EXPECT_NO_THROW(server->stopAccepting());
    EXPECT_NO_THROW(server->stopAccepting());
    EXPECT_NO_THROW(server->stop());
    EXPECT_NO_THROW(server->stop());
}

// ---------------------------------------------------------------------------
// Async responder contract (independent of the transport library)
// ---------------------------------------------------------------------------

TEST(HttpResponderContractTest, ImmediateResponseMapping)
{
    RouteHandler handler = [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
    {
        responder->send(HttpResponse::json(201, R"({"created":true})"));
    };

    auto request = std::make_shared<HttpRequest>();
    request->method = Method::Post;
    request->target = "/thing";

    auto responder = std::make_shared<CapturingResponder>();
    handler(request, responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(responder->captured->status, 201);
    EXPECT_EQ(responder->captured->body, R"({"created":true})");
    ASSERT_FALSE(responder->captured->headers.empty());
    EXPECT_EQ(responder->captured->headers.front().first, "Content-Type");
    EXPECT_EQ(responder->captured->headers.front().second, "application/json");
}

TEST(HttpResponderContractTest, DeferredResponseFromAnotherThread)
{
    std::shared_ptr<IHttpResponder> held;
    std::shared_ptr<const HttpRequest> heldRequest;

    // Handler defers: it stashes the request AND the responder and returns without answering.
    RouteHandler handler =
        [&held, &heldRequest](std::shared_ptr<const HttpRequest> request, std::shared_ptr<IHttpResponder> responder)
    {
        heldRequest = std::move(request);
        held = std::move(responder);
    };

    auto responder = std::make_shared<CapturingResponder>();
    {
        // The request the transport would build; it drops at the end of this scope.
        auto request = std::make_shared<const HttpRequest>();
        handler(request, responder);
    }

    // The shared request survived the handler call: it can travel across deferred stages.
    ASSERT_NE(heldRequest, nullptr);
    ASSERT_FALSE(responder->captured.has_value()); // not answered yet

    // Complete the response later, from a different thread.
    std::thread worker([&held] { held->send(HttpResponse::json(200, R"({"late":true})")); });
    worker.join();

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(responder->captured->status, 200);
    EXPECT_EQ(responder->captured->body, R"({"late":true})");
}

TEST(HttpResponderContractTest, SecondSendIsIgnored)
{
    auto responder = std::make_shared<CapturingResponder>();
    responder->send(HttpResponse::json(200, "first"));
    responder->send(HttpResponse::json(500, "second"));

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(responder->captured->body, "first");
}
