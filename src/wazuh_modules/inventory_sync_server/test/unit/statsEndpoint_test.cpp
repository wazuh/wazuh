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
    /**
     * @brief A report shaped exactly like the agent's, for the tests that are not about the payload.
     *
     * Both modules come in clean and already named the way the index declares them: this is the wire
     * format agreed with the agent side (#37843), which is also what the document stores.
     *
     * It also claims an identity three ways -- the reporter's own `agent_id`/`cluster` at the root,
     * plus a `wazuh.agent.id` and `wazuh.cluster` spelled exactly like the authoritative ones. None
     * may survive, and the ones under `wazuh` are the interesting half: building the document from
     * scratch makes them trivially unreachable, and these are what would start leaking the day
     * someone goes back to stamping onto the agent's payload.
     */
    constexpr auto kAgentReport {
        R"({"modules":{)"
        R"("agent":{"status":"connected","last_keepalive":"2026-08-02T10:06:50Z",)"
        R"("messages":{"count":602},)"
        R"("tasks":{"dispatched":{"total":4},"discarded_duplicate":{"total":0},"failed":{"total":0}}},)"
        R"("logcollector":{"global":{"files":[{"location":"df -P","events":32}]}})"
        R"(},"agent_id":"001","cluster":{"name":"claimed","node":"claimed"},)"
        R"("wazuh":{"agent":{"id":"999"},"cluster":{"name":"claimed","node":"claimed"},)"
        R"("schema":{"version":"999"}},"state":{"document_version":999}})"};

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

        /// Recorded writes, as (document id, index, document).
        std::vector<std::tuple<std::string, std::string, std::string>> indexed;
        std::vector<std::pair<std::string, std::string>> dataStreamed;

    private:
        bool m_available;
    };

    /// A fixed, non-empty identity most tests use -- only the cluster-stamping tests need a
    /// different one (and the empty-identity test needs the zeroed default).
    invsync::common::ClusterIdentity testClusterIdentity()
    {
        return {"test-cluster"};
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

    /// The single document the connector was handed. The response no longer carries it, so every
    /// assertion about content reads it from here.
    nlohmann::json onlyIndexedDocument(const std::shared_ptr<FakeAsyncConnector>& connector)
    {
        EXPECT_EQ(1U, connector->indexed.size()) << "expected exactly one write";
        if (connector->indexed.size() != 1U)
        {
            return nlohmann::json::object();
        }
        auto document = nlohmann::json::parse(std::get<2>(connector->indexed.front()), nullptr, false);
        EXPECT_FALSE(document.is_discarded());
        return document;
    }

    /// Sends one report through a fresh handler, asserts the 200, and returns what got indexed, so a
    /// test that only cares about the document's content stays a single line.
    nlohmann::json indexedDocument(const char* body,
                                   const char* agentId,
                                   invsync::common::ClusterIdentity cluster = testClusterIdentity())
    {
        auto connector = std::make_shared<FakeAsyncConnector>();
        EXPECT_EQ(200, run(makeRequest(body, agentId), connector, std::move(cluster)).status);
        return onlyIndexedDocument(connector);
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

/// The index name is a contract with whoever reads it, from another codebase entirely -- and with
/// DELETE /agents, which wipes this index by that same name.
TEST(StatsEndpointTest, IndexNameIsStable)
{
    EXPECT_EQ("wazuh-agent-stats", invsync::endpoints::stats::indexName());
}

/**
 * The whole point of the endpoint: what the agent keys by module lands under
 * `wazuh.agent.statistics`, keyed the same way, so a reader fetches one module out of the document by
 * key.
 */
TEST(StatsEndpointTest, StoresTheReportedModulesUnderWazuhAgentStatistics)
{
    const auto document = indexedDocument(kAgentReport, "007");

    EXPECT_FALSE(document.contains("modules")) << "the agent's own key must not survive at the root";
    EXPECT_EQ(602, document["/wazuh/agent/statistics/agent/messages/count"_json_pointer].get<int>());
    EXPECT_EQ("df -P",
              document["/wazuh/agent/statistics/logcollector/global/files/0/location"_json_pointer].get<std::string>());
}

/// The document id IS the agent id: that is what makes every push replace the previous report.
TEST(StatsEndpointTest, IndexesUnderTheAuthenticatedAgentIdAsDocumentId)
{
    auto connector = std::make_shared<FakeAsyncConnector>();

    ASSERT_EQ(200, run(makeRequest(kAgentReport, "007"), connector).status);

    ASSERT_EQ(1U, connector->indexed.size());
    EXPECT_EQ("007", std::get<0>(connector->indexed.front()));
    EXPECT_EQ("wazuh-agent-stats", std::get<1>(connector->indexed.front()));
    EXPECT_TRUE(connector->dataStreamed.empty()) << "a data stream cannot carry a stable document id";
}

/**
 * Moving `modules` is the only thing that happens to a report: each module's body is stored as it
 * arrives, so every metric name in the index is the agent's own. Not even fields shaped like a
 * transport envelope are touched.
 */
TEST(StatsEndpointTest, StoresEachModuleBodyVerbatim)
{
    const auto report = nlohmann::json::parse(kAgentReport);
    const auto document = indexedDocument(kAgentReport, "001");

    EXPECT_EQ(report.at("modules"), document["/wazuh/agent/statistics"_json_pointer]);
}

/**
 * "Verbatim" is about this endpoint, NOT about what survives to the index. The `wazuh-agent-stats`
 * mapping is `dynamic: strict` with every leaf declared, so a module or a metric it does not declare
 * makes the indexer reject the WHOLE document with `strict_dynamic_mapping_exception` -- silently,
 * since the write is fire-and-forget and the agent already has its 200.
 *
 * Pinned so the asymmetry is visible here rather than discovered in production: modulesd passes an
 * undeclared module through untouched, and adding one is a change to the index template, not to this
 * file.
 */
TEST(StatsEndpointTest, AnUndeclaredModuleIsStillPassedThroughForTheIndexerToJudge)
{
    const auto document = indexedDocument(R"({"modules":{"fim":{"error":0,"data":{}}}})", "001");

    EXPECT_TRUE(document["/wazuh/agent/statistics/fim"_json_pointer].contains("error"));
    EXPECT_TRUE(document["/wazuh/agent/statistics/fim"_json_pointer].contains("data"));
}

/**
 * Every report that leaves nothing to store is a 400, never an empty document: indexing one would
 * wipe the agent's last good report. A module whose body is not an object is rejected here because
 * the index mapping would reject it silently -- the write is fire-and-forget.
 */
TEST(StatsEndpointTest, AReportWithNothingToStoreIsRejected)
{
    auto connector = std::make_shared<FakeAsyncConnector>();

    for (const auto* body : {R"({})",
                             R"({"modules":{}})",
                             R"({"modules":"agent"})",
                             R"({"modules":[{"module":"agent","stats":{}}]})",
                             R"({"modules":{"agent":[]}})",
                             R"({"modules":{"agent":42}})",
                             R"({"modules":{"agent":null}})",
                             R"({"modules":{"agent":{"messages":{}},"logcollector":"x"}})"})
    {
        EXPECT_EQ(400, run(makeRequest(body, "001"), connector).status) << "body: " << body;
    }
    EXPECT_TRUE(connector->indexed.empty());
}

/**
 * The document is built from scratch, so nothing the agent claims about its own identity is indexed:
 * neither the `agent_id`/`cluster` its reporter writes at the root, nor a `wazuh.agent.id` spelled
 * exactly like the authoritative one. The authenticated id, this manager's identity and the server's
 * envelope win on every field the report tried to occupy.
 */
TEST(StatsEndpointTest, NothingTheAgentClaimsAboutItsIdentityIsIndexed)
{
    const auto document = indexedDocument(kAgentReport, "001");

    EXPECT_FALSE(document.contains("agent_id"));
    EXPECT_FALSE(document.contains("cluster")) << "the reporter's root cluster object must not survive";
    EXPECT_EQ("001", document["/wazuh/agent/id"_json_pointer].get<std::string>()) << "claimed 999";
    EXPECT_EQ("test-cluster", document["/wazuh/cluster/name"_json_pointer].get<std::string>());
    EXPECT_EQ("1.0", document["/wazuh/schema/version"_json_pointer].get<std::string>()) << "claimed 999";
    EXPECT_EQ(1, document["/state/document_version"_json_pointer].get<int>()) << "claimed 999";
}

/**
 * The time field is `state.modified_at` and not `@timestamp`: this index follows the schema's
 * stateful convention, because the document id is stable and every push replaces the previous state.
 * Its shape is what makes the document indexable, so pin it rather than just its presence:
 * Utils::getCurrentISO8601() yields YYYY-MM-DDTHH:MM:SS.mmmZ (24 chars, milliseconds, trailing Z).
 */
TEST(StatsEndpointTest, StampsStateModifiedAtIso8601WithMillisecondsAndZulu)
{
    const auto document = indexedDocument(kAgentReport, "001");
    const auto modifiedAt = document["/state/modified_at"_json_pointer].get<std::string>();

    EXPECT_FALSE(document.contains("@timestamp")) << "the stateful convention replaces it";
    ASSERT_EQ(24U, modifiedAt.size()) << "unexpected timestamp: " << modifiedAt;
    EXPECT_EQ('T', modifiedAt[10]);
    EXPECT_EQ('.', modifiedAt[19]);
    EXPECT_EQ('Z', modifiedAt.back());
    EXPECT_EQ(1, document["/state/document_version"_json_pointer].get<int>());
}

/**
 * `wazuh.schema.version` is a string, not a number: it is declared `keyword`, so one schema marker
 * does not come back in two types depending on the index. The value matches `/config` and the
 * stateful `wazuh-states-*` indices.
 */
TEST(StatsEndpointTest, StampsTheSchemaVersionAsAKeyword)
{
    const auto version = indexedDocument(kAgentReport, "001")["/wazuh/schema/version"_json_pointer];

    ASSERT_TRUE(version.is_string()) << version.dump();
    EXPECT_EQ("1.0", version.get<std::string>());
}

TEST(StatsEndpointTest, NonObjectBodiesAreRejected)
{
    // Each of these parses as valid JSON but is not an object, so it cannot carry a `modules` member.
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
    const auto response = run(makeRequest(kAgentReport, "", /*withAgentHeader=*/false));

    EXPECT_EQ(400, response.status);
    EXPECT_NE(response.body.find("agent id"), std::string::npos) << response.body;
}

TEST(StatsEndpointTest, AnEmptyAgentIdHeaderIsRejected)
{
    EXPECT_EQ(400, run(makeRequest(kAgentReport, "")).status);
}

/// The protocol's acknowledgment: an empty object, so the agent has nothing to parse out of it.
TEST(StatsEndpointTest, SuccessAnswersAnEmptyJsonObject)
{
    const auto response = run(makeRequest(kAgentReport, "001"));

    ASSERT_EQ(200, response.status);
    EXPECT_EQ("{}", response.body);

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

// The handler must not retain the payload: the document it builds owns its own copy, and holding the
// request would silently pin the transport's in-flight byte reservation.
TEST(StatsEndpointTest, HandlerDoesNotRetainTheRequest)
{
    auto connector = std::make_shared<FakeAsyncConnector>();
    auto handler = invsync::endpoints::stats::makeHandler(connector, testClusterIdentity());
    auto responder = std::make_shared<CapturingResponder>();

    auto request = makeRequest(kAgentReport, "001");
    std::weak_ptr<const HttpRequest> observer {request};

    handler(request, responder);
    request.reset();

    EXPECT_TRUE(observer.expired()) << "the handler must not keep the payload alive";
}

/**
 * The indexer gate. An unreachable indexer is a transient, server-side condition, so the caller gets a
 * 503 to retry rather than a 200 that pretends the document was stored.
 */
TEST(StatsEndpointTest, UnavailableIndexerYields503)
{
    auto connector = std::make_shared<FakeAsyncConnector>(/*available=*/false);

    const auto response = run(makeRequest(kAgentReport, "001"), connector);

    EXPECT_EQ(503, response.status);
    EXPECT_NE(response.body.find("Service unavailable"), std::string::npos) << response.body;
    EXPECT_TRUE(connector->indexed.empty());
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

    handler(makeRequest(kAgentReport, "001"), responder);

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

    for (const auto* body : {"", "{", "[]", R"("a string")", "not json at all", R"({"modules":{}})"})
    {
        const auto response = run(makeRequest(body, "001"), connector);
        EXPECT_EQ(400, response.status) << "body: " << body;
    }
}

TEST(StatsEndpointTest, AMissingAgentIdHeaderIsRejectedEvenWhenTheIndexerIsDown)
{
    auto connector = std::make_shared<FakeAsyncConnector>(/*available=*/false);

    const auto response = run(makeRequest(kAgentReport, "", /*withAgentHeader=*/false), connector);

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
    handler(makeRequest(kAgentReport, "001"), responder);
    ASSERT_EQ(200, responder->captured->status) << "the handler must have used the connector";

    connector.reset();

    EXPECT_TRUE(observer.expired())
        << "the handler (still alive) must not keep the connector alive -- see stop()'s phase 2";
}

/**
 * The cluster identity is injected at registration time (makeHandler()'s `cluster` parameter), not
 * read from anything the caller sends -- unlike the agent id, there is no per-request source for it.
 * The report used here claims its own, which must not survive.
 */
TEST(StatsEndpointTest, StampsTheInjectedClusterName)
{
    const auto document = indexedDocument(kAgentReport, "001", {"prod-cluster"});

    EXPECT_EQ("prod-cluster", document["/wazuh/cluster/name"_json_pointer].get<std::string>());
}

/**
 * inventory_sync_server_config_t documents an empty cluster_name buffer as "no opinion", not as
 * "omit the field" -- so an unconfigured identity is stamped as an explicit empty string, exactly
 * like buildClusterIdentity() reads it. Silently dropping the field on empty would leave an
 * unclustered manager's documents impossible to tell apart from a stamping bug.
 */
TEST(StatsEndpointTest, AnEmptyClusterIdentityIsStampedAsEmptyStringNotOmitted)
{
    const auto document = indexedDocument(kAgentReport, "001", invsync::common::ClusterIdentity {});

    ASSERT_TRUE(document.contains("wazuh"));
    EXPECT_EQ("", document["/wazuh/cluster/name"_json_pointer].get<std::string>());
}
