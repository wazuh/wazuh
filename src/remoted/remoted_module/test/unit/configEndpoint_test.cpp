/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Unit-tests the /config endpoint policy: the downstream target it builds (including the agent-id
// header), how it maps a downstream result to the agent response, and the empty-body short circuit.
// Pure functions where possible -- no sockets, no async -- except the makeHandler() glue tests, which
// need a fake downstream client plus a real DeferredForwarder to prove the short circuit.
#include "endpoints/configEndpoint.hpp"

#include "downstream/IDownstreamClient.hpp"
#include "downstream/deferredWorkLimiter.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

using remoted::auth::AuthenticatedRequest;
using remoted::auth::Payload;
using remoted::downstream::DeferredForwarder;
using remoted::downstream::DeferredWorkLimiter;
using remoted::downstream::DownstreamError;
using remoted::downstream::DownstreamResponse;
using remoted::http::HttpResponse;
using remoted::http::Method;
// NOT named `config`: it would shadow remoted::endpoints::config inside this file.
namespace config_endpoint = remoted::endpoints::config;

namespace
{
    constexpr auto kSocketPath {"queue/sockets/inventory-sync.sock"};

    struct AuthReqFixture
    {
        std::shared_ptr<const AuthenticatedRequest> req;
        std::shared_ptr<std::string> buffer; // owns the payload bytes
    };

    AuthReqFixture makeAuthReq(const std::string& body, const std::string& agentId)
    {
        auto buffer = std::make_shared<std::string>(body);
        AuthenticatedRequest ar;
        ar.agentId = agentId;
        ar.method = "POST";
        ar.requestTarget = "/config";
        ar.payload = Payload {std::string_view {*buffer}, buffer};
        return {std::make_shared<const AuthenticatedRequest>(std::move(ar)), std::move(buffer)};
    }

    /// Templated because it is used on both a DownstreamTarget (what the endpoint builds) and a
    /// DownstreamRequest (what the client actually received) -- two distinct types with a `headers`
    /// member, and asserting on both is the point.
    template<typename THasHeaders>
    std::string headerValue(const THasHeaders& carrier, const std::string& name)
    {
        for (const auto& [headerName, value] : carrier.headers)
        {
            if (headerName == name)
            {
                return value;
            }
        }
        return {};
    }

    // Records the forwarded request and lets a test fire the completion callback by hand.
    class FakeDownstreamClient final : public remoted::downstream::IDownstreamClient
    {
    public:
        void sendAsync(remoted::downstream::DownstreamRequest req,
                       std::shared_ptr<const void> /*keepAlive*/,
                       remoted::downstream::DownstreamCallback cb) override
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            m_request = std::move(req);
            m_callback = std::move(cb);
            m_called = true;
        }

        bool called() const
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            return m_called;
        }

        remoted::downstream::DownstreamRequest request() const
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            return m_request;
        }

        void fire(DownstreamError error, DownstreamResponse response)
        {
            remoted::downstream::DownstreamCallback cb;
            {
                std::lock_guard<std::mutex> lock {m_mutex};
                cb = std::move(m_callback);
            }
            ASSERT_TRUE(static_cast<bool>(cb));
            cb(error, std::move(response));
        }

    private:
        mutable std::mutex m_mutex;
        remoted::downstream::DownstreamRequest m_request;
        remoted::downstream::DownstreamCallback m_callback;
        bool m_called {false};
    };

    class CapturingResponder final : public remoted::http::IHttpResponder
    {
    public:
        void send(HttpResponse response) override
        {
            if (!m_answered.exchange(true))
            {
                m_promise.set_value(std::move(response));
            }
        }
        std::future<HttpResponse> future()
        {
            return m_promise.get_future();
        }

    private:
        std::promise<HttpResponse> m_promise;
        std::atomic<bool> m_answered {false};
    };
} // namespace

/**
 * The path is a wire contract with the inventory sync server's own route table, which lives in a
 * different binary. Pinning it on both sides is what turns a drift into a failing test rather than
 * runtime 404s.
 */
TEST(ConfigEndpoint, TargetPointsAtTheInventorySyncServer)
{
    const auto target = config_endpoint::target(kSocketPath, "001");
    EXPECT_EQ(target.socketPath, kSocketPath);
    EXPECT_EQ(target.method, Method::Post);
    EXPECT_EQ(target.path, "/config");
    EXPECT_EQ(target.contentType, "application/json");
    // No per-endpoint override: the dummy answers immediately, so it stays on the global
    // remoted.downstream_response_timeout. A future slow implementation is what sets a value here.
    EXPECT_EQ(target.responseTimeoutMs, 0);
}

/// The agent id must travel as a header, because the document does not carry it -- modulesd is what
/// writes it into the JSON, and it can only do that if it receives it.
TEST(ConfigEndpoint, TargetCarriesTheAuthenticatedAgentIdAsAHeader)
{
    const auto target = config_endpoint::target(kSocketPath, "007");
    EXPECT_EQ(headerValue(target, "X-Wazuh-Agent-Id"), "007");
}

/// Naming the service is what keeps a downstream failure WARN attributable now that remoted talks to
/// more than one downstream.
TEST(ConfigEndpoint, TargetNamesTheDownstreamServiceForLogs)
{
    const auto target = config_endpoint::target(kSocketPath, "001");
    ASSERT_NE(target.serviceName, nullptr);
    EXPECT_STREQ(target.serviceName, "inventory sync server");
}

TEST(ConfigEndpoint, PostProcessMapsDownstreamResults)
{
    struct Case
    {
        DownstreamError error;
        int downstreamStatus;
        int expected;
    };

    const Case cases[] = {
        {DownstreamError::None, 200, 200},
        {DownstreamError::None, 201, 200},
        {DownstreamError::None, 299, 200},
        {DownstreamError::None, 400, 400},
        {DownstreamError::None, 413, 413},
        {DownstreamError::None, 404, 503},
        {DownstreamError::None, 500, 503},
        {DownstreamError::None, 503, 503},
        {DownstreamError::Connect, 0, 503},
        {DownstreamError::ConnectTimeout, 0, 503},
        {DownstreamError::WriteTimeout, 0, 503},
        {DownstreamError::ResponseTimeout, 0, 503},
        {DownstreamError::Transport, 0, 503},
        {DownstreamError::Protocol, 0, 503},
        {DownstreamError::ResponseTooLarge, 0, 503},
    };

    for (const auto& testCase : cases)
    {
        const auto response =
            config_endpoint::postProcess(testCase.error, DownstreamResponse {testCase.downstreamStatus, "{}"});
        EXPECT_EQ(response.status, testCase.expected)
            << "error=" << static_cast<int>(testCase.error) << " downstreamStatus=" << testCase.downstreamStatus;
    }
}

/**
 * The success path passes the downstream body through -- unlike /stateless, which discards it. That
 * is the whole point of the dummy: the caller can see what modulesd stamped onto the document.
 */
TEST(ConfigEndpoint, PostProcessPassesTheEnrichedBodyThroughOnSuccess)
{
    constexpr auto enriched {R"({"a":1,"wazuh":{"agent":{"id":"001"}},"@timestamp":"2026-07-30T00:00:00.000Z"})"};

    const auto response = config_endpoint::postProcess(DownstreamError::None, DownstreamResponse {200, enriched});

    EXPECT_EQ(response.status, 200);
    EXPECT_EQ(response.body, enriched);
}

/// A downstream error body must NOT be reflected to the agent: it is arbitrary text from another
/// process, and the agent-visible message is ours to control.
TEST(ConfigEndpoint, PostProcessDoesNotReflectADownstreamErrorBody)
{
    const auto response =
        config_endpoint::postProcess(DownstreamError::None, DownstreamResponse {400, R"({"error":"internal detail"})"});

    EXPECT_EQ(response.status, 400);
    EXPECT_EQ(response.body, R"({"error":"Invalid config document","code":400})");
}

TEST(ConfigMakeHandler, EmptyBodyShortCircuitsBeforeForward)
{
    auto client = std::make_shared<FakeDownstreamClient>();
    auto limiter = std::make_shared<DeferredWorkLimiter>(4);
    DeferredForwarder forwarder {client, limiter, 1};

    auto handler = config_endpoint::makeHandler(forwarder, kSocketPath);
    auto fixture = makeAuthReq("", "001");
    auto responder = std::make_shared<CapturingResponder>();
    auto fut = responder->future();

    handler(fixture.req, responder);

    ASSERT_EQ(fut.wait_for(std::chrono::seconds {2}), std::future_status::ready);
    const auto response = fut.get();
    EXPECT_EQ(response.status, 400);
    EXPECT_EQ(response.body, R"({"error":"Empty request body","code":400})");
    // Not spending a deferred-work slot or a UDS round trip on a body that cannot be a JSON object
    // is the only reason this check lives on the remoted side at all.
    EXPECT_FALSE(client->called());
}

TEST(ConfigMakeHandler, ForwardsTheDocumentAndTheAgentIdThenPostProcesses)
{
    auto client = std::make_shared<FakeDownstreamClient>();
    auto limiter = std::make_shared<DeferredWorkLimiter>(4);
    DeferredForwarder forwarder {client, limiter, 1};

    auto handler = config_endpoint::makeHandler(forwarder, kSocketPath);
    auto fixture = makeAuthReq(R"({"cpu":1})", "042");
    auto responder = std::make_shared<CapturingResponder>();
    auto fut = responder->future();

    handler(fixture.req, responder);

    ASSERT_TRUE(client->called());
    const auto req = client->request();
    EXPECT_EQ(req.socketPath, kSocketPath);
    EXPECT_EQ(req.path, "/config");
    EXPECT_EQ(req.contentType, "application/json");
    EXPECT_EQ(req.body, R"({"cpu":1})");
    // The id the gateway authenticated, not anything read out of the document.
    EXPECT_EQ(headerValue(req, "X-Wazuh-Agent-Id"), "042");

    client->fire(DownstreamError::None, DownstreamResponse {200, R"({"cpu":1,"@timestamp":"x"})"});

    ASSERT_EQ(fut.wait_for(std::chrono::seconds {2}), std::future_status::ready);
    const auto response = fut.get();
    EXPECT_EQ(response.status, 200);
    EXPECT_EQ(response.body, R"({"cpu":1,"@timestamp":"x"})");
}
