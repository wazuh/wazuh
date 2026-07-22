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

#include <gtest/gtest.h>

#include <cstdlib>
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

    void clearHttpEnvironment()
    {
        for (const auto* name : {"WAZUH_REMOTED_HTTPS_ADDRESS",
                                 "WAZUH_REMOTED_HTTPS_PORT",
                                 "WAZUH_REMOTED_HTTPS_IO_THREADS",
                                 "WAZUH_REMOTED_HTTPS_WORKER_THREADS",
                                 "WAZUH_REMOTED_HTTPS_MAX_BODY_SIZE",
                                 "WAZUH_REMOTED_HTTPS_CERTIFICATE",
                                 "WAZUH_REMOTED_HTTPS_PRIVATE_KEY"})
        {
            unsetenv(name);
        }
    }
} // namespace

// ---------------------------------------------------------------------------
// Config builder
// ---------------------------------------------------------------------------

TEST(HttpServerConfigTest, DefaultsWhenEmpty)
{
    clearHttpEnvironment();

    const auto config = buildHttpServerConfig(zeroedConfig());

    EXPECT_EQ(config.bindAddress, "127.0.0.1");
    EXPECT_EQ(config.port, 9443);
    EXPECT_EQ(config.ioThreads, 2U);
    EXPECT_EQ(config.workerThreads, 4U);
    EXPECT_EQ(config.certificatePath, "/etc/remoted-https/server.crt");
    EXPECT_EQ(config.privateKeyPath, "/etc/remoted-https/server.key");
}

TEST(HttpServerConfigTest, StructValuesWin)
{
    clearHttpEnvironment();

    auto raw = zeroedConfig();
    raw.port = 12345;
    raw.io_threads = 3;
    raw.http_worker_threads = 7;
    std::snprintf(raw.certificate_path, sizeof(raw.certificate_path), "/custom/cert.pem");
    std::snprintf(raw.private_key_path, sizeof(raw.private_key_path), "/custom/key.pem");

    const auto config = buildHttpServerConfig(raw);

    EXPECT_EQ(config.port, 12345);
    EXPECT_EQ(config.ioThreads, 3U);
    EXPECT_EQ(config.workerThreads, 7U);
    EXPECT_EQ(config.certificatePath, "/custom/cert.pem");
    EXPECT_EQ(config.privateKeyPath, "/custom/key.pem");
}

TEST(HttpServerConfigTest, WorkerThreadsFallBackToGenericWorkerThreads)
{
    clearHttpEnvironment();

    auto raw = zeroedConfig();
    raw.worker_threads = 9;      // generic
    raw.http_worker_threads = 0; // not set -> use generic

    EXPECT_EQ(buildHttpServerConfig(raw).workerThreads, 9U);
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
                         [](const HttpRequest&, std::shared_ptr<IHttpResponder> r)
                         { r->send(HttpResponse::json(200, "{}")); });
        server->addRoute(Method::Post,
                         "/events",
                         [](const HttpRequest&, std::shared_ptr<IHttpResponder> r)
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

    // stop() must be safe after a failed start, and idempotent.
    EXPECT_NO_THROW(server->stop());
    EXPECT_NO_THROW(server->stop());
}

TEST(HttpServerTest, StopWithoutStartIsSafe)
{
    auto server = makeHttpServer();
    EXPECT_NO_THROW(server->stop());
}

// ---------------------------------------------------------------------------
// Async responder contract (independent of the transport library)
// ---------------------------------------------------------------------------

TEST(HttpResponderContractTest, ImmediateResponseMapping)
{
    RouteHandler handler = [](const HttpRequest&, std::shared_ptr<IHttpResponder> responder)
    {
        responder->send(HttpResponse::json(201, R"({"created":true})"));
    };

    HttpRequest request;
    request.method = Method::Post;
    request.target = "/thing";

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

    // Handler defers: it stashes the responder and returns without answering.
    RouteHandler handler = [&held](const HttpRequest&, std::shared_ptr<IHttpResponder> responder)
    {
        held = std::move(responder);
    };

    auto responder = std::make_shared<CapturingResponder>();
    handler(HttpRequest {}, responder);

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
