/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "endpoints/configEndpoint.hpp"

#include <gtest/gtest.h>

#include <json.hpp>
#include <memory>
#include <optional>
#include <string>

using invsync::http::HttpRequest;
using invsync::http::HttpResponse;
using invsync::http::IHttpResponder;
using invsync::http::Method;

namespace
{
    /// Captures whatever the handler sends, so the endpoint can be tested with no socket at all.
    class CapturingResponder final : public IHttpResponder
    {
    public:
        void send(HttpResponse response) override
        {
            ++sendCount;
            captured = std::move(response);
        }

        int sendCount {0};
        std::optional<HttpResponse> captured;
    };

    /// The transport lower-cases header names, so the fixture stores them the way a real request would.
    std::shared_ptr<const HttpRequest> makeRequest(std::string body, std::string agentId, bool withAgentHeader = true)
    {
        auto request = std::make_shared<HttpRequest>();
        request->method = Method::Post;
        request->target = "/config";
        request->body = std::move(body);
        if (withAgentHeader)
        {
            request->headers.emplace(invsync::endpoints::config::agentIdHeader(), std::move(agentId));
        }
        return request;
    }

    /// Sends one request through a fresh handler and returns what came back.
    HttpResponse run(const std::shared_ptr<const HttpRequest>& request)
    {
        auto handler = invsync::endpoints::config::makeHandler();
        auto responder = std::make_shared<CapturingResponder>();
        handler(request, responder);
        EXPECT_EQ(1, responder->sendCount) << "the transport's exactly-once contract requires one send";
        return responder->captured.value_or(HttpResponse {});
    }
} // namespace

/**
 * The path and verb are a wire contract with remoted's downstream target for /config, which lives in a
 * different binary. Pinning them on both sides is what turns a drift into a failing test.
 */
TEST(ConfigEndpointTest, PathAndMethodAreStable)
{
    EXPECT_EQ(Method::Post, invsync::endpoints::config::method());
    EXPECT_STREQ("/config", invsync::endpoints::config::path());
}

/// Lower-case, because the transport normalizes header names and the handler looks it up directly.
TEST(ConfigEndpointTest, AgentIdHeaderNameIsLowerCase)
{
    EXPECT_STREQ("x-wazuh-agent-id", invsync::endpoints::config::agentIdHeader());
}

TEST(ConfigEndpointTest, EnrichesTheDocumentAndEchoesItBack)
{
    const auto response = run(makeRequest(R"({"cpu":42})", "007"));

    ASSERT_EQ(200, response.status);

    const auto document = nlohmann::json::parse(response.body, nullptr, false);
    ASSERT_FALSE(document.is_discarded());
    // The agent's own field survives untouched.
    EXPECT_EQ(42, document.at("cpu").get<int>());
    // ...and both stamps landed at the documented JSON pointers.
    ASSERT_TRUE(document.contains("wazuh"));
    EXPECT_EQ("007", document["/wazuh/agent/id"_json_pointer].get<std::string>());
    ASSERT_TRUE(document.contains("@timestamp"));
    EXPECT_FALSE(document.at("@timestamp").get<std::string>().empty());
}

/**
 * The timestamp shape is what makes the document indexable, so pin it rather than just its presence:
 * Utils::getCurrentISO8601() yields YYYY-MM-DDTHH:MM:SS.mmmZ (24 chars, milliseconds, trailing Z).
 */
TEST(ConfigEndpointTest, TimestampIsIso8601WithMillisecondsAndZulu)
{
    const auto response = run(makeRequest("{}", "001"));

    const auto document = nlohmann::json::parse(response.body, nullptr, false);
    ASSERT_FALSE(document.is_discarded());
    const auto timestamp = document.at("@timestamp").get<std::string>();

    ASSERT_EQ(24U, timestamp.size()) << "unexpected timestamp: " << timestamp;
    EXPECT_EQ('T', timestamp[10]);
    EXPECT_EQ('.', timestamp[19]);
    EXPECT_EQ('Z', timestamp.back());
}

/**
 * The authenticated id must win. A document claiming a different agent cannot override what remoted
 * verified -- otherwise the enrichment would be worthless as an identity.
 */
TEST(ConfigEndpointTest, TheAuthenticatedAgentIdOverridesOneClaimedInTheDocument)
{
    const auto response = run(makeRequest(R"({"wazuh":{"agent":{"id":"999"}}})", "001"));

    ASSERT_EQ(200, response.status);
    const auto document = nlohmann::json::parse(response.body, nullptr, false);
    ASSERT_FALSE(document.is_discarded());
    EXPECT_EQ("001", document["/wazuh/agent/id"_json_pointer].get<std::string>());
}

/// Same for a pre-existing @timestamp: the server's clock is the authoritative one.
TEST(ConfigEndpointTest, APreExistingTimestampIsOverwritten)
{
    const auto response = run(makeRequest(R"({"@timestamp":"1999-01-01T00:00:00.000Z"})", "001"));

    ASSERT_EQ(200, response.status);
    const auto document = nlohmann::json::parse(response.body, nullptr, false);
    ASSERT_FALSE(document.is_discarded());
    EXPECT_NE("1999-01-01T00:00:00.000Z", document.at("@timestamp").get<std::string>());
}

TEST(ConfigEndpointTest, NonObjectBodiesAreRejected)
{
    // Each of these parses as valid JSON but is not an object, so there is nothing to stamp onto.
    for (const auto* body : {"[]", R"("a string")", "42", "true", "null"})
    {
        const auto response = run(makeRequest(body, "001"));
        EXPECT_EQ(400, response.status) << "body: " << body;
    }
}

TEST(ConfigEndpointTest, MalformedJsonIsRejected)
{
    for (const auto* body : {"", "{", R"({"a":})", "not json at all"})
    {
        const auto response = run(makeRequest(body, "001"));
        EXPECT_EQ(400, response.status) << "body: " << body;
    }
}

/**
 * A request without the header did not come through remoted's authenticated route, so it is a
 * contract violation rather than agent input. Rejecting it is what stops the endpoint from inventing
 * an identity.
 */
TEST(ConfigEndpointTest, AMissingAgentIdHeaderIsRejected)
{
    const auto response = run(makeRequest("{}", "", /*withAgentHeader=*/false));

    EXPECT_EQ(400, response.status);
    EXPECT_NE(response.body.find("agent id"), std::string::npos) << response.body;
}

TEST(ConfigEndpointTest, AnEmptyAgentIdHeaderIsRejected)
{
    const auto response = run(makeRequest("{}", ""));

    EXPECT_EQ(400, response.status);
}

TEST(ConfigEndpointTest, ResponseIsJson)
{
    const auto response = run(makeRequest("{}", "001"));

    bool hasJsonContentType {false};
    for (const auto& [name, value] : response.headers)
    {
        if (name == "Content-Type" && value == "application/json")
        {
            hasJsonContentType = true;
        }
    }
    EXPECT_TRUE(hasJsonContentType);
}

// A null request must not crash the handler: the transport never passes one today, but a null deref
// here would be a daemon crash.
TEST(ConfigEndpointTest, NullRequestIsToleratedAndStillAnswered)
{
    auto handler = invsync::endpoints::config::makeHandler();
    auto responder = std::make_shared<CapturingResponder>();

    handler(nullptr, responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(400, responder->captured->status);
}

// The handler must not retain the payload: it discards the document, and holding the request would
// silently pin the transport's in-flight byte reservation.
TEST(ConfigEndpointTest, HandlerDoesNotRetainTheRequest)
{
    auto handler = invsync::endpoints::config::makeHandler();
    auto responder = std::make_shared<CapturingResponder>();

    auto request = makeRequest(R"({"a":1})", "001");
    std::weak_ptr<const HttpRequest> observer {request};

    handler(request, responder);
    request.reset();

    EXPECT_TRUE(observer.expired()) << "the handler must not keep the payload alive";
}
