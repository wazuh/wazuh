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

#include "common/clusterIdentity.hpp"
#include "endpoints/statsEndpoint.hpp"

#include <gtest/gtest.h>

#include <json.hpp>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

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
        request->target = "/stats";
        request->body = std::move(body);
        if (withAgentHeader)
        {
            request->headers.emplace(invsync::endpoints::stats::agentIdHeader(), std::move(agentId));
        }
        return request;
    }

    /**
     * @brief Stand-in for the async indexer connector.
     *
     * Local to this file rather than reused from testIndexerConnectorFakes.hpp on purpose: those fakes
     * exist to drive the facade's startup gate and carry its teardown bookkeeping, none of which an
     * endpoint test needs. Same reasoning as CapturingResponder above.
     */
    class FakeAsyncConnector final : public invsync::indexer::IIndexerConnectorAsync
    {
    public:
        explicit FakeAsyncConnector(bool available = true)
            : m_available {available}
        {
        }

        bool isAvailable() const override
        {
            return m_available;
        }

        void index(std::string_view id, std::string_view index, std::string_view data) override
        {
            indexed.emplace_back(std::string {id}, std::string {index}, std::string {data});
        }

        void indexDataStream(std::string_view index, std::string_view data) override
        {
            dataStreamed.emplace_back(std::string {index}, std::string {data});
        }

        /// Recorded writes. Empty today -- the endpoints do not write yet -- which is exactly what the
        /// NothingIsIndexedYet test pins, so the day someone starts writing, the test says so.
        std::vector<std::tuple<std::string, std::string, std::string>> indexed;
        std::vector<std::pair<std::string, std::string>> dataStreamed;

    private:
        bool m_available;
    };

    /// A fixed, non-empty identity most tests use -- only the cluster-stamping tests need a
    /// different one (and the empty-identity test needs the zeroed default).
    invsync::common::ClusterIdentity testClusterIdentity()
    {
        return {"test-cluster", "test-node-01"};
    }

    /// Sends one request through a fresh handler and returns what came back. The connector is available
    /// unless a test says otherwise.
    HttpResponse run(const std::shared_ptr<const HttpRequest>& request,
                     const std::shared_ptr<FakeAsyncConnector>& connector,
                     invsync::common::ClusterIdentity cluster)
    {
        auto handler = invsync::endpoints::stats::makeHandler(connector, std::move(cluster));
        auto responder = std::make_shared<CapturingResponder>();
        handler(request, responder);
        EXPECT_EQ(1, responder->sendCount) << "the transport's exactly-once contract requires one send";
        return responder->captured.value_or(HttpResponse {});
    }

    HttpResponse run(const std::shared_ptr<const HttpRequest>& request,
                     const std::shared_ptr<FakeAsyncConnector>& connector)
    {
        return run(request, connector, testClusterIdentity());
    }

    HttpResponse run(const std::shared_ptr<const HttpRequest>& request)
    {
        return run(request, std::make_shared<FakeAsyncConnector>(), testClusterIdentity());
    }
} // namespace

/**
 * The path and verb are a wire contract with remoted's downstream target for /stats, which lives in a
 * different binary. Pinning them on both sides is what turns a drift into a failing test.
 */
TEST(StatsEndpointTest, PathAndMethodAreStable)
{
    EXPECT_EQ(Method::Post, invsync::endpoints::stats::method());
    EXPECT_STREQ("/stats", invsync::endpoints::stats::path());
}

/// Lower-case, because the transport normalizes header names and the handler looks it up directly.
TEST(StatsEndpointTest, AgentIdHeaderNameIsLowerCase)
{
    EXPECT_STREQ("x-wazuh-agent-id", invsync::endpoints::stats::agentIdHeader());
}

TEST(StatsEndpointTest, EnrichesTheDocumentAndEchoesItBack)
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
TEST(StatsEndpointTest, TimestampIsIso8601WithMillisecondsAndZulu)
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
TEST(StatsEndpointTest, TheAuthenticatedAgentIdOverridesOneClaimedInTheDocument)
{
    const auto response = run(makeRequest(R"({"wazuh":{"agent":{"id":"999"}}})", "001"));

    ASSERT_EQ(200, response.status);
    const auto document = nlohmann::json::parse(response.body, nullptr, false);
    ASSERT_FALSE(document.is_discarded());
    EXPECT_EQ("001", document["/wazuh/agent/id"_json_pointer].get<std::string>());
}

/// Same for a pre-existing @timestamp: the server's clock is the authoritative one.
TEST(StatsEndpointTest, APreExistingTimestampIsOverwritten)
{
    const auto response = run(makeRequest(R"({"@timestamp":"1999-01-01T00:00:00.000Z"})", "001"));

    ASSERT_EQ(200, response.status);
    const auto document = nlohmann::json::parse(response.body, nullptr, false);
    ASSERT_FALSE(document.is_discarded());
    EXPECT_NE("1999-01-01T00:00:00.000Z", document.at("@timestamp").get<std::string>());
}

TEST(StatsEndpointTest, NonObjectBodiesAreRejected)
{
    // Each of these parses as valid JSON but is not an object, so there is nothing to stamp onto.
    for (const auto* body : {"[]", R"("a string")", "42", "true", "null"})
    {
        const auto response = run(makeRequest(body, "001"));
        EXPECT_EQ(400, response.status) << "body: " << body;
    }
}

TEST(StatsEndpointTest, MalformedJsonIsRejected)
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
TEST(StatsEndpointTest, AMissingAgentIdHeaderIsRejected)
{
    const auto response = run(makeRequest("{}", "", /*withAgentHeader=*/false));

    EXPECT_EQ(400, response.status);
    EXPECT_NE(response.body.find("agent id"), std::string::npos) << response.body;
}

TEST(StatsEndpointTest, AnEmptyAgentIdHeaderIsRejected)
{
    const auto response = run(makeRequest("{}", ""));

    EXPECT_EQ(400, response.status);
}

TEST(StatsEndpointTest, ResponseIsJson)
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
TEST(StatsEndpointTest, NullRequestIsToleratedAndStillAnswered)
{
    auto connector = std::make_shared<FakeAsyncConnector>();
    auto handler = invsync::endpoints::stats::makeHandler(connector, testClusterIdentity());
    auto responder = std::make_shared<CapturingResponder>();

    handler(nullptr, responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(400, responder->captured->status);
}

// The handler must not retain the payload: it discards the document, and holding the request would
// silently pin the transport's in-flight byte reservation.
TEST(StatsEndpointTest, HandlerDoesNotRetainTheRequest)
{
    auto connector = std::make_shared<FakeAsyncConnector>();
    auto handler = invsync::endpoints::stats::makeHandler(connector, testClusterIdentity());
    auto responder = std::make_shared<CapturingResponder>();

    auto request = makeRequest(R"({"a":1})", "001");
    std::weak_ptr<const HttpRequest> observer {request};

    handler(request, responder);
    request.reset();

    EXPECT_TRUE(observer.expired()) << "the handler must not keep the payload alive";
}

/**
 * The indexer gate. An unreachable indexer is a transient, server-side condition, so the caller gets a
 * 503 to retry rather than a 200 that pretends the document was handled.
 */
TEST(StatsEndpointTest, UnavailableIndexerYields503)
{
    auto connector = std::make_shared<FakeAsyncConnector>(/*available=*/false);

    const auto response = run(makeRequest(R"({"cpu":42})", "001"), connector);

    EXPECT_EQ(503, response.status);
    EXPECT_NE(response.body.find("Service unavailable"), std::string::npos) << response.body;
}

/**
 * The weak capture's other branch: stop() has already cleared the facade's connector, so lock() fails.
 * Same 503 to the caller (retry later is the same advice), distinguished only in the logs.
 */
TEST(StatsEndpointTest, AnExpiredConnectorYields503)
{
    auto connector = std::make_shared<FakeAsyncConnector>();
    auto handler = invsync::endpoints::stats::makeHandler(connector, testClusterIdentity());
    auto responder = std::make_shared<CapturingResponder>();

    connector.reset(); // the facade's phase-2 teardown, from the handler's point of view

    handler(makeRequest(R"({"cpu":42})", "001"), responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(503, responder->captured->status);
}

/**
 * Pins the ORDER of the checks, which is a deliberate design decision rather than an accident: a
 * malformed document is the caller's fault and stays a 400 even while the indexer is down. With the
 * checks reversed the agent would get a 503 and retry forever a payload that can never work.
 */
TEST(StatsEndpointTest, ValidationStillWinsOverAnUnavailableIndexer)
{
    auto connector = std::make_shared<FakeAsyncConnector>(/*available=*/false);

    for (const auto* body : {"", "{", "[]", R"("a string")", "not json at all"})
    {
        const auto response = run(makeRequest(body, "001"), connector);
        EXPECT_EQ(400, response.status) << "body: " << body;
    }
}

TEST(StatsEndpointTest, AMissingAgentIdHeaderIsRejectedEvenWhenTheIndexerIsDown)
{
    auto connector = std::make_shared<FakeAsyncConnector>(/*available=*/false);

    const auto response = run(makeRequest("{}", "", /*withAgentHeader=*/false), connector);

    EXPECT_EQ(400, response.status);
    EXPECT_NE(response.body.find("agent id"), std::string::npos) << response.body;
}

/**
 * The load-bearing property of the whole injection: the handler holds the connector WEAKLY.
 *
 * If it ever captured a strong reference, the facade's stop() would stop destroying the connector at
 * the point its phase-2 comment claims -- the transport's route table would keep it alive, and its
 * destructor (with its background threads) would run later, on whatever thread released the last
 * responder. This test is what makes that regression a failure instead of a subtle shutdown change.
 */
TEST(StatsEndpointTest, HandlerDoesNotHoldTheConnectorAliveAfterReturning)
{
    auto connector = std::make_shared<FakeAsyncConnector>();
    std::weak_ptr<FakeAsyncConnector> observer {connector};

    auto handler = invsync::endpoints::stats::makeHandler(connector, testClusterIdentity());
    auto responder = std::make_shared<CapturingResponder>();
    handler(makeRequest(R"({"cpu":42})", "001"), responder);
    ASSERT_EQ(200, responder->captured->status) << "the handler must have used the connector";

    connector.reset();

    EXPECT_TRUE(observer.expired())
        << "the handler (still alive) must not keep the connector alive -- see stop()'s phase 2";
}

/**
 * The endpoints are still dummies: the connector is injected and gated on, but nothing writes through
 * it yet. Pinned so that the day real processing lands, this test fails and has to be updated
 * deliberately rather than the behaviour changing silently.
 */
TEST(StatsEndpointTest, NothingIsIndexedYet)
{
    auto connector = std::make_shared<FakeAsyncConnector>();

    ASSERT_EQ(200, run(makeRequest(R"({"cpu":42})", "001"), connector).status);

    EXPECT_TRUE(connector->indexed.empty()) << "this endpoint does not index yet";
    EXPECT_TRUE(connector->dataStreamed.empty()) << "this endpoint does not index yet";
}

/**
 * The cluster identity is injected at registration time (makeHandler()'s `cluster` parameter), not
 * read from anything the caller sends -- unlike the agent id, there is no per-request source for it.
 */
TEST(StatsEndpointTest, StampsTheInjectedClusterNameAndNode)
{
    auto connector = std::make_shared<FakeAsyncConnector>();
    invsync::common::ClusterIdentity cluster {"prod-cluster", "node-03"};

    const auto response = run(makeRequest(R"({"cpu":42})", "001"), connector, cluster);

    ASSERT_EQ(200, response.status);
    const auto document = nlohmann::json::parse(response.body, nullptr, false);
    ASSERT_FALSE(document.is_discarded());
    EXPECT_EQ("prod-cluster", document["/wazuh/cluster/name"_json_pointer].get<std::string>());
    EXPECT_EQ("node-03", document["/wazuh/cluster/node"_json_pointer].get<std::string>());
}

/**
 * A document claiming its own cluster identity must not survive: this manager's configured identity
 * is authoritative, mirroring the same override rule already pinned for the agent id.
 */
TEST(StatsEndpointTest, TheInjectedClusterIdentityOverridesOneClaimedInTheDocument)
{
    auto connector = std::make_shared<FakeAsyncConnector>();
    invsync::common::ClusterIdentity cluster {"real-cluster", "real-node"};

    const auto response =
        run(makeRequest(R"({"wazuh":{"cluster":{"name":"fake","node":"fake"}}})", "001"), connector, cluster);

    ASSERT_EQ(200, response.status);
    const auto document = nlohmann::json::parse(response.body, nullptr, false);
    ASSERT_FALSE(document.is_discarded());
    EXPECT_EQ("real-cluster", document["/wazuh/cluster/name"_json_pointer].get<std::string>());
    EXPECT_EQ("real-node", document["/wazuh/cluster/node"_json_pointer].get<std::string>());
}

/**
 * inventory_sync_server_config_t documents an empty cluster_name/node_name buffer as "no opinion",
 * not as "omit the field" -- so an unconfigured identity is stamped as an explicit empty string,
 * exactly like buildClusterIdentity() reads it. Silently dropping the field on empty would leave an
 * unclustered manager's documents impossible to tell apart from a stamping bug.
 */
TEST(StatsEndpointTest, AnEmptyClusterIdentityIsStampedAsEmptyStringsNotOmitted)
{
    auto connector = std::make_shared<FakeAsyncConnector>();

    const auto response = run(makeRequest(R"({"cpu":42})", "001"), connector, invsync::common::ClusterIdentity {});

    ASSERT_EQ(200, response.status);
    const auto document = nlohmann::json::parse(response.body, nullptr, false);
    ASSERT_FALSE(document.is_discarded());
    ASSERT_TRUE(document.contains("wazuh"));
    EXPECT_EQ("", document["/wazuh/cluster/name"_json_pointer].get<std::string>());
    EXPECT_EQ("", document["/wazuh/cluster/node"_json_pointer].get<std::string>());
}
