/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Unit-tests the /stateless endpoint policy: the downstream target it builds, how it maps a
// downstream result to the agent response, and the pre-forward H-line slice check + full handler.
// Pure functions where possible -- no sockets, no async -- except the makeHandler() glue tests,
// which need a (fake) downstream client + a real DeferredForwarder to prove the short-circuit.
#include "endpoints/statelessEndpoint.hpp"

#include "common/requestOutcomeMetrics.hpp"
#include "downstream/IDownstreamClient.hpp"
#include "downstream/deferredWorkLimiter.hpp"

#include <wazuh_metrics/manager.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

using remoted::auth::AuthenticatedRequest;
using remoted::auth::AuthError;
using remoted::auth::Payload;
using remoted::downstream::DeferredForwarder;
using remoted::downstream::DeferredWorkLimiter;
using remoted::downstream::DownstreamError;
using remoted::downstream::DownstreamResponse;
using remoted::http::HttpResponse;
using remoted::http::Method;
namespace stateless = remoted::endpoints::stateless;

namespace
{
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
        ar.requestTarget = "/stateless";
        ar.payload = Payload {std::string_view {*buffer}, buffer};
        return {std::make_shared<const AuthenticatedRequest>(std::move(ar)), std::move(buffer)};
    }
} // namespace

TEST(StatelessEndpoint, TargetPointsAtEngineEventIngress)
{
    const auto target = stateless::target("queue/sockets/engine-ingest-http.sock", "042");
    EXPECT_EQ(target.socketPath, "queue/sockets/engine-ingest-http.sock");
    EXPECT_EQ(target.method, Method::Post);
    EXPECT_EQ(target.path, "/events/enriched");
    EXPECT_EQ(target.contentType, "application/x-ndjson");
    // /stateless deliberately does NOT override the response deadline: event ingestion is fast, so
    // it stays on the global remoted.downstream_response_timeout. The 0 sentinel is what expresses
    // that -- a future slow endpoint is the one that sets a value here.
    EXPECT_EQ(target.responseTimeoutMs, 0);
    // The agent the batch belongs to travels outside the agent-written body, as on /stateful.
    ASSERT_EQ(target.headers.size(), 1U);
    EXPECT_EQ(target.headers[0].first, "X-Wazuh-Agent-Id");
    EXPECT_EQ(target.headers[0].second, "042");
}

TEST(StatelessEndpoint, PostProcessMapsDownstreamResults)
{
    struct Case
    {
        DownstreamError error;
        int downstreamStatus;
        int expected;
    };
    const Case cases[] = {
        {DownstreamError::None, 200, 202},           // engine enqueued -> Accepted
        {DownstreamError::None, 202, 202},           // any 2xx -> 202
        {DownstreamError::None, 400, 400},           // bad batch passes through
        {DownstreamError::None, 413, 413},           // too large passes through
        {DownstreamError::None, 500, 503},           // downstream 5xx -> transient 503
        {DownstreamError::Connect, 0, 503},          // could not connect -> 503
        {DownstreamError::ConnectTimeout, 0, 503},   // connect deadline -> 503
        {DownstreamError::WriteTimeout, 0, 503},     // send deadline -> 503
        {DownstreamError::ResponseTimeout, 0, 503},  // no timely answer -> 503
        {DownstreamError::Transport, 0, 503},        // broken pipe -> 503
        {DownstreamError::Protocol, 0, 503},         // bad HTTP -> 503
        {DownstreamError::ResponseTooLarge, 0, 503}, // oversized response body -> 503
    };
    // Every timeout phase must still collapse to the SAME agent-visible 503: which deadline
    // elapsed is manager-internal diagnostics (it picks the log line and names the knob), and must
    // not leak to the agent.

    for (const auto& c : cases)
    {
        const auto response = stateless::postProcess(c.error, DownstreamResponse {c.downstreamStatus, ""});
        EXPECT_EQ(response.status, c.expected)
            << "error=" << static_cast<int>(c.error) << " downstream=" << c.downstreamStatus;
    }
}

TEST(StatelessEndpoint, AcceptedResponseHasEmptyBody)
{
    const auto response = stateless::postProcess(DownstreamError::None, DownstreamResponse {200, "ignored"});
    EXPECT_EQ(response.status, 202);
    EXPECT_TRUE(response.body.empty());
}

TEST(StatelessEndpoint, ErrorResponsesCarryNeutralJson)
{
    const auto badBatch = stateless::postProcess(DownstreamError::None, DownstreamResponse {400, "engine internals"});
    EXPECT_EQ(badBatch.status, 400);
    EXPECT_EQ(badBatch.body, R"({"error":"Invalid event batch","code":400})"); // neutral, not the engine body

    const auto unavailable = stateless::postProcess(DownstreamError::ResponseTimeout, DownstreamResponse {0, ""});
    EXPECT_EQ(unavailable.status, 503);
    EXPECT_EQ(unavailable.body, R"({"error":"Service unavailable","code":503})");
}

// --- validatePayloadIdentity() ---------------------------------------------------------------

TEST(ValidatePayloadIdentity, RejectsMissingLiteralHeaderPrefix)
{
    for (const auto body : {"", "E some event\n", "H", "H\t{}\n", "h {}\n", "\nH {}\n"})
    {
        SCOPED_TRACE(body);
        const auto fixture = makeAuthReq(body, "001");
        EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::PayloadAgentMismatch);
    }
}

TEST(ValidatePayloadIdentity, AcceptsHeaderAtByteLimit)
{
    for (const auto suffix : {"", "\nE some event\n"})
    {
        const auto fixture = makeAuthReq("H " + std::string(8192, 'x') + suffix, "001");
        EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::None);
    }
}

TEST(ValidatePayloadIdentity, RejectsHeaderAboveByteLimit)
{
    for (const auto suffix : {"", "\nE some event\n"})
    {
        const auto fixture = makeAuthReq("H " + std::string(8193, 'x') + suffix, "001");
        EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::PayloadAgentMismatch);
    }
}

TEST(ValidatePayloadIdentity, MeasuresOnlyTheFirstHeaderLine)
{
    const auto fixture = makeAuthReq("H {}\nE " + std::string(8193, 'x') + "\n", "001");
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::None);
}

TEST(ValidatePayloadIdentity, LeavesHeaderContentsToEngine)
{
    const std::vector<std::string> headers {"",
                                            "{not json}",
                                            "{}",
                                            R"({"wazuh":{"agent":{"id":1}}})",
                                            R"({"wazuh":{"agent":{"id":"002"}}})",
                                            R"({"wazuh":{"agent":{"id":"0001"}}})",
                                            R"({"wazuh":{"agent":{"id":"001","id":"002"}}})",
                                            R"({"wazuh":{"agent":{"id":"001"}},"wazuh":{"agent":{"id":"002"}}})",
                                            std::string(1, '\0') + "{}"};
    for (const auto& header : headers)
    {
        SCOPED_TRACE(header);
        const auto fixture = makeAuthReq("H " + header + "\nE some event\n", "001");
        EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::None);
    }
}

TEST(ValidatePayloadIdentity, AcceptsHeaderOnlySlice)
{
    const auto fixture = makeAuthReq("H {}", "001");
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::None);
}

// --- makeHandler() ----------------------------------------------------------------------------

namespace
{
    // Captures the forwarded request and lets each test supply the downstream result.
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

TEST(StatelessMakeHandler, ValidationFailureShortCircuitsBeforeForward)
{
    for (const auto& body : {std::string("E some event\n"), "H " + std::string(8193, 'x') + "\n"})
    {
        auto client = std::make_shared<FakeDownstreamClient>();
        auto limiter = std::make_shared<DeferredWorkLimiter>(4);
        DeferredForwarder forwarder {client, limiter, 1};
        auto handler = stateless::makeHandler(forwarder, "queue/sockets/engine-ingest-http.sock");
        auto fixture = makeAuthReq(body, "001");
        auto responder = std::make_shared<CapturingResponder>();
        auto fut = responder->future();

        handler(fixture.req, responder);

        ASSERT_EQ(fut.wait_for(std::chrono::seconds {2}), std::future_status::ready);
        const auto response = fut.get();
        EXPECT_EQ(response.status, 400);
        EXPECT_EQ(response.body, R"({"error":"Invalid event batch","code":400})");
        EXPECT_FALSE(client->called());
    }
}

TEST(StatelessMakeHandler, ForwardsInvalidHeaderAndRelaysEngineRejection)
{
    const std::vector<std::string> headers {R"({"wazuh":{"agent":{"id":"002"}}})",
                                            R"({"wazuh":{"agent":{"id":"0001"}}})",
                                            R"({"wazuh":{"agent":{"id":"001","id":"002"}}})",
                                            R"({"wazuh":{"agent":{"id":"001"}},"wazuh":{"agent":{"id":"002"}}})",
                                            "{not json}",
                                            std::string(1, '\0') + "{}"};
    for (const auto& header : headers)
    {
        SCOPED_TRACE(header);
        auto client = std::make_shared<FakeDownstreamClient>();
        auto limiter = std::make_shared<DeferredWorkLimiter>(4);
        DeferredForwarder forwarder {client, limiter, 1};
        auto handler = stateless::makeHandler(forwarder, "queue/sockets/engine-ingest-http.sock");
        const std::string body = "H " + header + "\nE some event\n";
        auto fixture = makeAuthReq(body, "001");
        auto responder = std::make_shared<CapturingResponder>();
        auto fut = responder->future();

        handler(fixture.req, responder);

        ASSERT_TRUE(client->called());
        const auto request = client->request();
        EXPECT_EQ(request.body, body);
        ASSERT_EQ(request.headers.size(), 1U);
        EXPECT_EQ(request.headers[0].first, "X-Wazuh-Agent-Id");
        EXPECT_EQ(request.headers[0].second, "001");
        client->fire(DownstreamError::None, DownstreamResponse {400, "engine parser diagnostics"});

        ASSERT_EQ(fut.wait_for(std::chrono::seconds {2}), std::future_status::ready);
        const auto response = fut.get();
        EXPECT_EQ(response.status, 400);
        EXPECT_EQ(response.body, R"({"error":"Invalid event batch","code":400})");
    }
}

TEST(StatelessMakeHandler, ValidationSuccessForwardsAndPostProcesses)
{
    auto client = std::make_shared<FakeDownstreamClient>();
    auto limiter = std::make_shared<DeferredWorkLimiter>(4);
    DeferredForwarder forwarder {client, limiter, 1};

    auto handler = stateless::makeHandler(forwarder, "queue/sockets/engine-ingest-http.sock");
    auto fixture = makeAuthReq("H {\"wazuh\":{\"agent\":{\"id\":\"1001\"}}}\nE some event\n", "1001");
    auto responder = std::make_shared<CapturingResponder>();
    auto fut = responder->future();

    handler(fixture.req, responder);

    ASSERT_TRUE(client->called());
    const auto req = client->request();
    EXPECT_EQ(req.socketPath, "queue/sockets/engine-ingest-http.sock");
    EXPECT_EQ(req.path, "/events/enriched");

    client->fire(DownstreamError::None, DownstreamResponse {200, ""});

    ASSERT_EQ(fut.wait_for(std::chrono::seconds {2}), std::future_status::ready);
    EXPECT_EQ(fut.get().status, 202); // stateless::postProcess still runs on the success path
}

// The engine learns the batch's agent from the id the gateway verified, never from the request: the
// downstream request carries exactly one X-Wazuh-Agent-Id, and its value is the authenticated id.
TEST(StatelessMakeHandler, ForwardsTheVerifiedAgentIdAsTheOnlyIdentityHeader)
{
    auto client = std::make_shared<FakeDownstreamClient>();
    auto limiter = std::make_shared<DeferredWorkLimiter>(4);
    DeferredForwarder forwarder {client, limiter, 1};

    auto handler = stateless::makeHandler(forwarder, "queue/sockets/engine-ingest-http.sock");
    auto fixture = makeAuthReq("H {\"wazuh\":{\"agent\":{\"id\":\"042\"}}}\nE some event\n", "042");
    auto responder = std::make_shared<CapturingResponder>();

    handler(fixture.req, responder);

    ASSERT_TRUE(client->called());
    const auto req = client->request();
    std::size_t identityHeaders = 0;
    for (const auto& [name, value] : req.headers)
    {
        if (name == "X-Wazuh-Agent-Id")
        {
            ++identityHeaders;
            EXPECT_EQ(value, "042");
        }
    }
    EXPECT_EQ(identityHeaders, 1U);
    client->fire(DownstreamError::None, DownstreamResponse {200, ""});
}

// Local slice failures and relayed engine rejections share the response counter. Only local
// failures count as remoted.auth.reject.payload_mismatch; the engine owns identity rejections.
TEST(StatelessMakeHandler, MetricsCountBothTheLocal400AndTheDeliveredStatus)
{
    wazuh::metrics::Manager manager;
    const auto metrics = remoted::metrics::makeEndpointHttpMetrics(manager, "stateless", /*withLatency=*/true);
    const auto authMetrics = remoted::endpoints::makeAuthRejectMetrics(manager);
    remoted::endpoints::installAuthRejectMetrics(authMetrics);
    struct ResetAuthMetrics
    {
        ~ResetAuthMetrics()
        {
            remoted::endpoints::installAuthRejectMetrics({});
        }
    } resetAuthMetrics;

    auto client = std::make_shared<FakeDownstreamClient>();
    auto limiter = std::make_shared<DeferredWorkLimiter>(4);
    DeferredForwarder forwarder {client, limiter, 1};
    auto handler = stateless::makeHandler(forwarder, "queue/sockets/engine-ingest-http.sock", &metrics);

    // Missing prefix: answered 400 locally, before any forward.
    {
        auto fixture = makeAuthReq("E some event\n", "001");
        auto responder = std::make_shared<CapturingResponder>();
        auto fut = responder->future();
        handler(fixture.req, responder);
        ASSERT_EQ(fut.wait_for(std::chrono::seconds {2}), std::future_status::ready);
        EXPECT_EQ(fut.get().status, 400);
    }
    EXPECT_EQ(metrics.responses.c400->get(), 1U);
    EXPECT_EQ(authMetrics.payloadMismatch->get(), 1U);
    EXPECT_FALSE(client->called());

    // Mismatched identity: forwarded unchanged, then rejected by the engine.
    {
        auto fixture = makeAuthReq("H {\"wazuh\":{\"agent\":{\"id\":\"002\"}}}\nE some event\n", "001");
        auto responder = std::make_shared<CapturingResponder>();
        auto fut = responder->future();
        handler(fixture.req, responder);
        ASSERT_TRUE(client->called());
        client->fire(DownstreamError::None, DownstreamResponse {400, "identity mismatch"});
        ASSERT_EQ(fut.wait_for(std::chrono::seconds {2}), std::future_status::ready);
        EXPECT_EQ(fut.get().status, 400);
    }
    EXPECT_EQ(metrics.responses.c400->get(), 2U);
    EXPECT_EQ(authMetrics.payloadMismatch->get(), 1U);

    // Valid request: the forwarder counts the delivered 202 through the target's metric pointer.
    {
        auto fixture = makeAuthReq("H {\"wazuh\":{\"agent\":{\"id\":\"001\"}}}\nE some event\n", "001");
        auto responder = std::make_shared<CapturingResponder>();
        auto fut = responder->future();
        handler(fixture.req, responder);
        client->fire(DownstreamError::None, DownstreamResponse {200, ""});
        ASSERT_EQ(fut.wait_for(std::chrono::seconds {2}), std::future_status::ready);
        EXPECT_EQ(fut.get().status, 202);
    }
    EXPECT_EQ(metrics.responses.c2xx->get(), 1U);
    EXPECT_EQ(metrics.responses.c400->get(), 2U);
    EXPECT_EQ(authMetrics.payloadMismatch->get(), 1U);
}
