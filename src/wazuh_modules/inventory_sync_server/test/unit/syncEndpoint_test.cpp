/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "endpoints/syncEndpoint.hpp"

#include "testIndexerConnectorFakes.hpp"
#include "testSessionBuilder.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <vector>

using invsync::http::HttpRequest;
using invsync::http::HttpResponse;
using invsync::http::IHttpResponder;
using invsync::http::Method;
using invsync::test::ConnectorEvents;
using invsync::test::FakeIndexerConnectorSync;
using invsync::test::SessionSpec;

namespace
{
    constexpr auto CLUSTER {"test-cluster"};

    /// Captures whatever the handler sends; also resolves a future so a DEFERRED response (sent by
    /// a pipeline worker) can be awaited.
    class CapturingResponder final : public IHttpResponder
    {
    public:
        void send(HttpResponse response) override
        {
            ++sendCount;
            captured = response;
            if (!m_resolved)
            {
                m_resolved = true;
                m_promise.set_value(std::move(response));
            }
        }

        HttpResponse await()
        {
            auto future = m_promise.get_future();
            if (future.wait_for(std::chrono::seconds {10}) != std::future_status::ready)
            {
                ADD_FAILURE() << "no response arrived within the deadline";
                return HttpResponse {0, "", {}};
            }
            return future.get();
        }

        int sendCount {0};
        std::optional<HttpResponse> captured;

    private:
        std::promise<HttpResponse> m_promise;
        bool m_resolved {false};
    };

    std::shared_ptr<const HttpRequest> makeRequest(std::string body, const char* agentId = "1")
    {
        auto request = std::make_shared<HttpRequest>();
        request->method = Method::Post;
        request->target = invsync::endpoints::sync::path();
        request->body = std::move(body);
        if (agentId != nullptr)
        {
            request->headers.emplace(invsync::endpoints::sync::agentIdHeader(), agentId);
        }
        return request;
    }

    /// Handler + a real (fake-backed) pipeline: what the facade wires, minus the socket.
    struct HandlerUnderTest
    {
        std::shared_ptr<ConnectorEvents> events {std::make_shared<ConnectorEvents>()};
        std::shared_ptr<FakeIndexerConnectorSync> admission {
            std::make_shared<FakeIndexerConnectorSync>(events, "sync")};
        std::shared_ptr<invsync::sync::SyncPipeline> pipeline;
        invsync::http::RouteHandler handler;

        explicit HandlerUnderTest(invsync::sync::SyncPipelineConfig config = {}, int retryAfter = 60)
        {
            std::vector<std::shared_ptr<invsync::indexer::IIndexerConnectorSync>> connectors {admission};
            pipeline = std::make_shared<invsync::sync::SyncPipeline>(config, std::move(connectors), CLUSTER);
            handler = invsync::endpoints::sync::makeHandler(invsync::endpoints::sync::Dependencies {
                pipeline, admission, invsync::common::ClusterIdentity {CLUSTER, "test-node", false}, retryAfter});
        }
    };

    std::string validDelta()
    {
        return invsync::test::buildSyncDataSession(SessionSpec {}, {invsync::test::ValueSpec {}});
    }
} // namespace

/**
 * The path and verb are a wire contract with remoted's downstream configuration (its statefulEndpoint
 * forwards here). Pinning them is what turns a silent drift into a failing test.
 */
TEST(SyncEndpointTest, PathAndMethodAreStable)
{
    EXPECT_EQ(Method::Post, invsync::endpoints::sync::method());
    EXPECT_STREQ("/stateful", invsync::endpoints::sync::path());
    EXPECT_STREQ("x-wazuh-agent-id", invsync::endpoints::sync::agentIdHeader());
}

TEST(SyncEndpointTest, AMissingAgentIdHeaderIs400)
{
    HandlerUnderTest fixture;
    auto responder = std::make_shared<CapturingResponder>();

    fixture.handler(makeRequest(validDelta(), nullptr), responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(400, responder->captured->status);
}

TEST(SyncEndpointTest, AnEmptyBodyIs400)
{
    HandlerUnderTest fixture;
    auto responder = std::make_shared<CapturingResponder>();

    fixture.handler(makeRequest(""), responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(400, responder->captured->status);
}

TEST(SyncEndpointTest, GarbageIs400)
{
    HandlerUnderTest fixture;
    auto responder = std::make_shared<CapturingResponder>();

    fixture.handler(makeRequest("not a flatbuffer"), responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(400, responder->captured->status);
    EXPECT_NE(std::string::npos, responder->captured->body.find(R"("code":400)"));
}

TEST(SyncEndpointTest, AnIdentityMismatchIs403)
{
    HandlerUnderTest fixture;
    auto responder = std::make_shared<CapturingResponder>();

    fixture.handler(makeRequest(validDelta(), "42"), responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(403, responder->captured->status);
    EXPECT_NE(std::string::npos, responder->captured->body.find("identity mismatch"));
}

TEST(SyncEndpointTest, AVDSessionGets503WithRetryAfterAndNothingIsProcessed)
{
    HandlerUnderTest fixture {{}, 120};
    auto responder = std::make_shared<CapturingResponder>();

    SessionSpec spec;
    spec.option = invsync::test::fb::Option_VDFirst;
    fixture.handler(makeRequest(invsync::test::buildSyncDataSession(spec, {invsync::test::ValueSpec {}})), responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(503, responder->captured->status);
    EXPECT_NE(std::string::npos, responder->captured->body.find("vulnerability feed not ready"));

    bool hasRetryAfter {false};
    for (const auto& [name, value] : responder->captured->headers)
    {
        if (name == "Retry-After")
        {
            hasRetryAfter = true;
            EXPECT_EQ("120", value) << "the configured Retry-After must reach the wire";
        }
    }
    EXPECT_TRUE(hasRetryAfter);
    EXPECT_TRUE(fixture.events->syncOps().empty()) << "a rejected VD session must not touch the indexer";
}

TEST(SyncEndpointTest, AnUnavailableIndexerShedsAtAdmission)
{
    HandlerUnderTest fixture;
    fixture.events->m_syncAvailable.store(false);
    auto responder = std::make_shared<CapturingResponder>();

    fixture.handler(makeRequest(validDelta()), responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(503, responder->captured->status);
}

TEST(SyncEndpointTest, AnExpiredPipelineIs503)
{
    // Simulates the facade's stop(): the weak_ptr no longer locks.
    invsync::endpoints::sync::Dependencies deps;
    auto events = std::make_shared<ConnectorEvents>();
    auto connector = std::make_shared<FakeIndexerConnectorSync>(events, "sync");
    deps.indexer = connector;
    deps.cluster = invsync::common::ClusterIdentity {CLUSTER, "test-node", false};
    auto handler = invsync::endpoints::sync::makeHandler(deps); // pipeline weak_ptr left empty

    auto responder = std::make_shared<CapturingResponder>();
    handler(makeRequest(validDelta()), responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(503, responder->captured->status);
}

TEST(SyncEndpointTest, AFullPipelineQueueIs503)
{
    invsync::sync::SyncPipelineConfig config;
    config.maxQueueBytes = 1;
    HandlerUnderTest fixture {config};
    auto responder = std::make_shared<CapturingResponder>();

    fixture.handler(makeRequest(validDelta()), responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(503, responder->captured->status);
}

TEST(SyncEndpointTest, AValidSessionIsDeferredAndAnsweredByTheWorkerExactlyOnce)
{
    HandlerUnderTest fixture;
    auto responder = std::make_shared<CapturingResponder>();

    fixture.handler(makeRequest(validDelta()), responder);

    // The strand's part ends WITHOUT a response; the worker delivers it.
    const auto response = responder->await();
    EXPECT_EQ(200, response.status);
    EXPECT_EQ(R"({"status":"ok"})", response.body);
    EXPECT_EQ(1, responder->sendCount);
    EXPECT_FALSE(fixture.events->syncOps().empty()) << "the session must have reached the connector";
}
