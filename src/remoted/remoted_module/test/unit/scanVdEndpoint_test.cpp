/*
 * Wazuh remoted module - scanVdEndpoint unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 10, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Tests the JSON dispatch/validation layer of `POST /scan/vd` in isolation, with a fake
 * ScanVdHandler standing in for the real queue-backed implementation (tested separately in
 * scanVdHandler_test.cpp). This file only cares about: does the endpoint reject malformed input
 * correctly, does it hand the handler the right (agentId, requestedOffset), and does it translate
 * each ScanVdOutcome into the exact response the design doc specifies.
 */

#include "endpoints/scanVdEndpoint.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <json.hpp>
#include <memory>
#include <string>

using namespace remoted::endpoints::scanvd;
using remoted::auth::AuthenticatedRequest;
using remoted::auth::Payload;
using remoted::http::HttpResponse;
using remoted::http::IHttpResponder;

namespace
{
    // Minimal test responder that captures whatever send() receives. Same shape as
    // controlEndpoint_test.cpp's CapturingResponder.
    class CapturingResponder : public IHttpResponder
    {
    public:
        void send(HttpResponse response) override
        {
            ASSERT_FALSE(m_done) << "duplicate send() -- a handler must call responder->send() exactly once";
            m_response = std::move(response);
            m_done = true;
        }

        bool done() const
        {
            return m_done;
        }

        const HttpResponse& captured() const
        {
            return m_response;
        }

    private:
        bool m_done {false};
        HttpResponse m_response;
    };

    std::shared_ptr<AuthenticatedRequest> makeRequest(const std::string& agentId, const std::string& body)
    {
        struct Holder
        {
            std::shared_ptr<AuthenticatedRequest> req;
            std::shared_ptr<std::string> body;
        };
        auto req = std::make_shared<AuthenticatedRequest>();
        req->agentId = agentId;
        req->method = "POST";
        req->requestTarget = "/scan/vd";
        auto bodyBuf = std::make_shared<std::string>(body);
        req->payload = Payload(std::string_view(*bodyBuf), std::shared_ptr<const void>(bodyBuf, bodyBuf.get()));
        return req;
    }

    std::string feedUpdateBody(uint64_t offset)
    {
        nlohmann::json body;
        body["type"] = "feed_update";
        body["feed_offset"] = offset;
        return body.dump();
    }

    // Records the (agentId, requestedOffset) it was called with and immediately invokes the
    // callback with whatever response has been configured via setResponse().
    class FakeScanVdHandler final : public ScanVdHandler
    {
    public:
        void handleVdScan(uint32_t agentId, uint64_t requestedOffset, ScanVdCallback callback) override
        {
            calls++;
            lastAgentId = agentId;
            lastRequestedOffset = requestedOffset;
            callback(m_response);
        }

        void setResponse(ScanVdResponse response)
        {
            m_response = response;
        }

        int calls {0};
        uint32_t lastAgentId {0};
        uint64_t lastRequestedOffset {0};

    private:
        ScanVdResponse m_response {ScanVdOutcome::Accepted, 0};
    };

    struct ScanVdEndpointTest : ::testing::Test
    {
        FakeScanVdHandler handler;
        remoted::endpoints::AuthenticatedHandler endpointHandler {makeHandler(handler)};
        CapturingResponder responder;

        void dispatch(const std::string& agentId, const std::string& body)
        {
            endpointHandler(makeRequest(agentId, body), std::shared_ptr<IHttpResponder>(&responder, [](auto*) {}));
        }
    };
} // namespace

// -----------------------------------------------------------------------------
// Request validation: each rejection is a 400 with a distinct error code, and the
// handler must never be reached for any of them.
// -----------------------------------------------------------------------------

TEST_F(ScanVdEndpointTest, EmptyBodyReturns400InvalidBody)
{
    dispatch("001", "");

    ASSERT_TRUE(responder.done());
    EXPECT_EQ(responder.captured().status, 400);
    EXPECT_EQ(responder.captured().body, R"({"error":"invalid_body"})");
    EXPECT_EQ(handler.calls, 0);
}

TEST_F(ScanVdEndpointTest, OversizedBodyReturns400InvalidBody)
{
    const std::string oversized(4U * 1024U + 1U, 'a');
    dispatch("001", oversized);

    ASSERT_TRUE(responder.done());
    EXPECT_EQ(responder.captured().status, 400);
    EXPECT_EQ(responder.captured().body, R"({"error":"invalid_body"})");
    EXPECT_EQ(handler.calls, 0);
}

TEST_F(ScanVdEndpointTest, MalformedJsonReturns400InvalidJson)
{
    dispatch("001", "{not json");

    ASSERT_TRUE(responder.done());
    EXPECT_EQ(responder.captured().status, 400);
    EXPECT_EQ(responder.captured().body, R"({"error":"invalid_json"})");
    EXPECT_EQ(handler.calls, 0);
}

TEST_F(ScanVdEndpointTest, NonObjectJsonReturns400MissingType)
{
    // Valid JSON, but not an object -- "type" lookup fails the same way as if it were absent.
    dispatch("001", "[]");

    ASSERT_TRUE(responder.done());
    EXPECT_EQ(responder.captured().status, 400);
    EXPECT_EQ(responder.captured().body, R"({"error":"missing_type"})");
    EXPECT_EQ(handler.calls, 0);
}

TEST_F(ScanVdEndpointTest, ZeroAgentIdReturns400InvalidAgentId)
{
    dispatch("0", feedUpdateBody(100));

    ASSERT_TRUE(responder.done());
    EXPECT_EQ(responder.captured().status, 400);
    EXPECT_EQ(responder.captured().body, R"({"error":"invalid_agent_id"})");
    EXPECT_EQ(handler.calls, 0);
}

TEST_F(ScanVdEndpointTest, NonNumericAgentIdReturns400InvalidAgentId)
{
    dispatch("not-a-number", feedUpdateBody(100));

    ASSERT_TRUE(responder.done());
    EXPECT_EQ(responder.captured().status, 400);
    EXPECT_EQ(responder.captured().body, R"({"error":"invalid_agent_id"})");
    EXPECT_EQ(handler.calls, 0);
}

TEST_F(ScanVdEndpointTest, AgentIdWithTrailingGarbageReturns400InvalidAgentId)
{
    dispatch("001x", feedUpdateBody(100));

    ASSERT_TRUE(responder.done());
    EXPECT_EQ(responder.captured().status, 400);
    EXPECT_EQ(responder.captured().body, R"({"error":"invalid_agent_id"})");
    EXPECT_EQ(handler.calls, 0);
}

TEST_F(ScanVdEndpointTest, MissingTypeReturns400MissingType)
{
    dispatch("001", nlohmann::json {{"feed_offset", 100}}.dump());

    ASSERT_TRUE(responder.done());
    EXPECT_EQ(responder.captured().status, 400);
    EXPECT_EQ(responder.captured().body, R"({"error":"missing_type"})");
    EXPECT_EQ(handler.calls, 0);
}

TEST_F(ScanVdEndpointTest, NonStringTypeReturns400MissingType)
{
    dispatch("001", nlohmann::json {{"type", 123}, {"feed_offset", 100}}.dump());

    ASSERT_TRUE(responder.done());
    EXPECT_EQ(responder.captured().status, 400);
    EXPECT_EQ(responder.captured().body, R"({"error":"missing_type"})");
    EXPECT_EQ(handler.calls, 0);
}

TEST_F(ScanVdEndpointTest, TypeOtherThanFeedUpdateReturns400InvalidType)
{
    dispatch("001", nlohmann::json {{"type", "manual"}, {"feed_offset", 100}}.dump());

    ASSERT_TRUE(responder.done());
    EXPECT_EQ(responder.captured().status, 400);
    EXPECT_EQ(responder.captured().body, R"({"error":"invalid_type"})");
    EXPECT_EQ(handler.calls, 0);
}

TEST_F(ScanVdEndpointTest, MissingFeedOffsetReturns400MissingFeedOffset)
{
    dispatch("001", nlohmann::json {{"type", "feed_update"}}.dump());

    ASSERT_TRUE(responder.done());
    EXPECT_EQ(responder.captured().status, 400);
    EXPECT_EQ(responder.captured().body, R"({"error":"missing_feed_offset"})");
    EXPECT_EQ(handler.calls, 0);
}

TEST_F(ScanVdEndpointTest, NegativeFeedOffsetReturns400MissingFeedOffset)
{
    dispatch("001", nlohmann::json {{"type", "feed_update"}, {"feed_offset", -1}}.dump());

    ASSERT_TRUE(responder.done());
    EXPECT_EQ(responder.captured().status, 400);
    EXPECT_EQ(responder.captured().body, R"({"error":"missing_feed_offset"})");
    EXPECT_EQ(handler.calls, 0);
}

TEST_F(ScanVdEndpointTest, StringFeedOffsetReturns400MissingFeedOffset)
{
    dispatch("001", nlohmann::json {{"type", "feed_update"}, {"feed_offset", "100"}}.dump());

    ASSERT_TRUE(responder.done());
    EXPECT_EQ(responder.captured().status, 400);
    EXPECT_EQ(responder.captured().body, R"({"error":"missing_feed_offset"})");
    EXPECT_EQ(handler.calls, 0);
}

// -----------------------------------------------------------------------------
// Valid request: handler is invoked with the parsed (agentId, requestedOffset).
// -----------------------------------------------------------------------------

TEST_F(ScanVdEndpointTest, ValidRequestParsesAgentIdAndOffsetForHandler)
{
    dispatch("42", feedUpdateBody(123456789));

    EXPECT_EQ(handler.calls, 1);
    EXPECT_EQ(handler.lastAgentId, 42u);
    EXPECT_EQ(handler.lastRequestedOffset, 123456789u);
}

// -----------------------------------------------------------------------------
// Outcome -> response mapping, per the design doc.
// -----------------------------------------------------------------------------

TEST_F(ScanVdEndpointTest, AcceptedOutcomeReturns200EmptyBody)
{
    handler.setResponse({ScanVdOutcome::Accepted, 0});
    dispatch("001", feedUpdateBody(100));

    ASSERT_TRUE(responder.done());
    EXPECT_EQ(responder.captured().status, 200);
    EXPECT_EQ(responder.captured().body, "{}");
}

TEST_F(ScanVdEndpointTest, VersionMismatchReturns409WithCurrentOffset)
{
    handler.setResponse({ScanVdOutcome::VersionMismatch, 999});
    dispatch("001", feedUpdateBody(100));

    ASSERT_TRUE(responder.done());
    EXPECT_EQ(responder.captured().status, 409);
    const auto json = nlohmann::json::parse(responder.captured().body);
    EXPECT_EQ(json.at("error").get<std::string>(), "version_mismatch");
    EXPECT_EQ(json.at("current_version").get<uint64_t>(), 999u);
}

TEST_F(ScanVdEndpointTest, QueueFullReturns503ScanQueueFull)
{
    handler.setResponse({ScanVdOutcome::QueueFull, 0});
    dispatch("001", feedUpdateBody(100));

    ASSERT_TRUE(responder.done());
    EXPECT_EQ(responder.captured().status, 503);
    EXPECT_EQ(responder.captured().body, R"({"error":"scan_queue_full"})");
}

TEST_F(ScanVdEndpointTest, InvalidAgentOutcomeReturns400InvalidAgentId)
{
    handler.setResponse({ScanVdOutcome::InvalidAgent, 0});
    dispatch("001", feedUpdateBody(100));

    ASSERT_TRUE(responder.done());
    EXPECT_EQ(responder.captured().status, 400);
    EXPECT_EQ(responder.captured().body, R"({"error":"invalid_agent_id"})");
}

TEST_F(ScanVdEndpointTest, AllResponsesAreApplicationJson)
{
    dispatch("001", feedUpdateBody(100));

    ASSERT_TRUE(responder.done());
    const auto& headers = responder.captured().headers;
    const auto it =
        std::find_if(headers.begin(), headers.end(), [](const auto& header) { return header.first == "Content-Type"; });
    ASSERT_NE(it, headers.end());
    EXPECT_EQ(it->second, "application/json");
}
