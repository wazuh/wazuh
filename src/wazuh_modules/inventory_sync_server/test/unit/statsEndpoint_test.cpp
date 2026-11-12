/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "common/clusterIdentity.hpp"
#include "common/jsonNestingDepth.hpp"
#include "endpoints/statsEndpoint.hpp"
#include "testIndexerConnectorFakes.hpp"

#include <gtest/gtest.h>

#include <chrono>

#include <cstddef>
#include <json.hpp>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

using wazuh::uds_http::HttpRequest;
using wazuh::uds_http::HttpResponse;
using wazuh::uds_http::IHttpResponder;
using wazuh::uds_http::Method;

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
     * @brief The Client and the `agent-state` writer the handler is wired to, over the shared fakes.
     *
     * Reuses testIndexerConnectorFakes.hpp's FakeIndexerClient and scripted FakeWriter: the endpoint now only
     * asks the Client for its health and posts into the writer, so those two are all it can observe. The Client
     * is usable unless a test says otherwise (`events->m_clientUsable`).
     */
    struct Rig
    {
        std::shared_ptr<invsync::test::ConnectorEvents> events {std::make_shared<invsync::test::ConnectorEvents>()};
        std::shared_ptr<invsync::test::FakeIndexerClient> client {
            std::make_shared<invsync::test::FakeIndexerClient>(events)};
        std::shared_ptr<invsync::test::FakeWriter> writer {events->m_agentStateWriter};
        /// A post-deletion sweeper that never runs a pass (no query, a one-hour window): what the handler withdraws
        /// from it shows in its counters once stop() drops the rest.
        std::shared_ptr<invsync::indexer::AgentDeleteSweeper> sweeper {
            std::make_shared<invsync::indexer::AgentDeleteSweeper>(
                nullptr, std::chrono::hours {1}, std::chrono::seconds {1}, nullptr)};

        explicit Rig(bool usable = true)
        {
            events->m_clientUsable.store(usable);
        }

        /// What the handler posted, in call order.
        std::vector<indexer_client::Op> indexed() const
        {
            return writer->posted();
        }
    };

    /// A fixed, non-empty identity most tests use -- only the cluster-stamping tests need a
    /// different one (and the empty-identity test needs the zeroed default).
    invsync::common::ClusterIdentity testClusterIdentity()
    {
        return {"test-cluster"};
    }

    /// Sends one request through a fresh handler and returns what came back. The Client is usable
    /// unless the rig says otherwise.
    HttpResponse run(const std::shared_ptr<const HttpRequest>& request,
                     const std::shared_ptr<Rig>& rig,
                     invsync::common::ClusterIdentity cluster)
    {
        auto handler =
            invsync::endpoints::stats::makeHandler(rig->client, rig->writer, std::move(cluster), rig->sweeper);
        auto responder = std::make_shared<CapturingResponder>();
        handler(request, responder);
        EXPECT_EQ(1, responder->sendCount) << "the transport's exactly-once contract requires one send";
        return responder->captured.value_or(HttpResponse {});
    }

    HttpResponse run(const std::shared_ptr<const HttpRequest>& request, const std::shared_ptr<Rig>& rig)
    {
        return run(request, rig, testClusterIdentity());
    }

    HttpResponse run(const std::shared_ptr<const HttpRequest>& request)
    {
        return run(request, std::make_shared<Rig>(), testClusterIdentity());
    }

    /// The single document the handler posted. The response no longer carries it, so every assertion about
    /// content reads it from here.
    nlohmann::json onlyIndexedDocument(const std::shared_ptr<Rig>& rig)
    {
        const auto ops = rig->indexed();
        EXPECT_EQ(1U, ops.size()) << "expected exactly one write";
        if (ops.size() != 1U)
        {
            return nlohmann::json::object();
        }
        auto document = nlohmann::json::parse(ops.front().body, nullptr, false);
        EXPECT_FALSE(document.is_discarded());
        return document;
    }

    /// Sends one report through a fresh handler, asserts the 200, and returns what got posted, so a
    /// test that only cares about the document's content stays a single line.
    nlohmann::json indexedDocument(const char* body,
                                   const char* agentId,
                                   invsync::common::ClusterIdentity cluster = testClusterIdentity())
    {
        auto rig = std::make_shared<Rig>();
        EXPECT_EQ(200, run(makeRequest(body, agentId), rig, std::move(cluster)).status);
        return onlyIndexedDocument(rig);
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
/// the deletion route, which wipes this index by that same name.
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
    auto rig = std::make_shared<Rig>();

    ASSERT_EQ(200, run(makeRequest(kAgentReport, "007"), rig).status);

    const auto ops = rig->indexed();
    ASSERT_EQ(1U, ops.size());
    EXPECT_EQ("007", ops.front().id);
    EXPECT_EQ("wazuh-agent-stats", ops.front().index);
    EXPECT_EQ(indexer_client::Op::Kind::Index, ops.front().kind) << "a data stream cannot carry a stable document id";
}

/**
 * The op is tagged with the agent too: that tag is what a whole-agent deletion's cancel(agent) drops while this
 * write is still pending in the `agent-state` bucket (RF-26, CA-E7c-1).
 */
TEST(StatsEndpointTest, PostAcceptedIs200WithIdAndTagTheAgent)
{
    auto rig = std::make_shared<Rig>();

    const auto response = run(makeRequest(kAgentReport, "007"), rig);

    EXPECT_EQ(200, response.status);
    EXPECT_EQ("{}", response.body);
    const auto ops = rig->indexed();
    ASSERT_EQ(1U, ops.size());
    EXPECT_EQ("007", ops.front().id);
    EXPECT_EQ("007", ops.front().tag);
    EXPECT_TRUE(rig->writer->cancelled().empty()) << "/stats never cancels anything";
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
 * mapping is `dynamic: true`: an undeclared module or metric is indexed like any other field, not
 * rejected.
 *
 * Pinned because this endpoint's contract does not depend on the mapping: modulesd passes an
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
    auto rig = std::make_shared<Rig>();

    for (const auto* body : {R"({})",
                             R"({"modules":{}})",
                             R"({"modules":"agent"})",
                             R"({"modules":[{"module":"agent","stats":{}}]})",
                             R"({"modules":{"agent":[]}})",
                             R"({"modules":{"agent":42}})",
                             R"({"modules":{"agent":null}})",
                             R"({"modules":{"agent":{"messages":{}},"logcollector":"x"}})"})
    {
        EXPECT_EQ(400, run(makeRequest(body, "001"), rig).status) << "body: " << body;
    }
    EXPECT_TRUE(rig->indexed().empty());
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
 * The agent's groups and host are the one thing the report contributes beyond its statistics: they
 * land under `wazuh.agent`, next to the authenticated id, and nothing else from the `agent` block
 * follows them.
 */
TEST(StatsEndpointTest, CopiesReportedGroupsAndHostUnderWazuhAgent)
{
    const auto document =
        indexedDocument(R"({"modules":{"agent":{"messages":{"count":1}}},"agent_id":"001",)"
                        R"("agent":{"id":"999","name":"web-01","groups":["default","linux"],)"
                        R"("host":{"architecture":"x86_64","hostname":"web-01",)"
                        R"("os":{"name":"Ubuntu","platform":"ubuntu","type":"linux","version":"24.04"}}}})",
                        "001");

    const auto& agent = document["/wazuh/agent"_json_pointer];
    EXPECT_EQ("001", agent.at("id").get<std::string>()) << "claimed 999";
    EXPECT_EQ(nlohmann::json::parse(R"(["default","linux"])"), agent.at("groups"));
    EXPECT_EQ("web-01", agent.at("host").at("hostname").get<std::string>());
    EXPECT_EQ("24.04", agent.at("host").at("os").at("version").get<std::string>());
    EXPECT_FALSE(agent.contains("name"));
    EXPECT_EQ(1, agent.at("statistics").at("agent").at("messages").at("count").get<int>());
    EXPECT_FALSE(document.contains("agent"));
}

/// An agent that predates the metadata sends no `agent` block: its document is indexed exactly as
/// before, without empty groups or host standing in for values it never reported.
TEST(StatsEndpointTest, AReportWithoutAgentMetadataIndexesNoGroupsOrHost)
{
    const auto document = indexedDocument(kAgentReport, "001");

    EXPECT_FALSE(document["/wazuh/agent"_json_pointer].contains("groups"));
    EXPECT_FALSE(document["/wazuh/agent"_json_pointer].contains("host"));
}

/// Bad metadata is left empty, never a 400: the agent would resend it every cycle and stop reporting.
TEST(StatsEndpointTest, InvalidAgentMetadataIsLeftEmptyNotRejected)
{
    const auto document =
        indexedDocument(R"({"modules":{"agent":{"messages":{"count":1}}},)"
                        R"("agent":{"groups":["default",1],"host":{"hostname":42,"architecture":"x86_64"}}})",
                        "001");

    EXPECT_EQ(nlohmann::json::array(), document["/wazuh/agent/groups"_json_pointer]);
    EXPECT_EQ("", document["/wazuh/agent/host/hostname"_json_pointer].get<std::string>());
    EXPECT_EQ("x86_64", document["/wazuh/agent/host/architecture"_json_pointer].get<std::string>());
    EXPECT_EQ(1, document["/wazuh/agent/statistics/agent/messages/count"_json_pointer].get<int>());
}

TEST(StatsEndpointTest, AnAgentBlockThatIsNotAnObjectStillIndexesTheReport)
{
    const auto document = indexedDocument(R"({"modules":{"agent":{"messages":{"count":1}}},"agent":["g"]})", "001");

    EXPECT_FALSE(document["/wazuh/agent"_json_pointer].contains("groups"));
    EXPECT_EQ(1, document["/wazuh/agent/statistics/agent/messages/count"_json_pointer].get<int>());
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
 * dump() recurses once per level: a deep enough report would overflow the I/O thread's stack and crash
 * the whole of modulesd. The cap is checked on the raw body, so the deepest legal report still goes
 * through and one level more never reaches the parser or the indexer. The attack-sized body would
 * crash this test binary without the cap.
 */
TEST(StatsEndpointTest, ReportsNestedPastTheLimitAreRejectedBeforeParsing)
{
    // root, modules and the module body are three levels; the rest is arrays under one field.
    const auto nested = [](std::size_t depth)
    {
        const std::size_t arrays = depth - 3;
        return R"({"modules":{"m":{"x":)" + std::string(arrays, '[') + std::string(arrays, ']') + "}}}";
    };

    auto rig = std::make_shared<Rig>();
    EXPECT_EQ(200, run(makeRequest(nested(invsync::common::MAX_JSON_NESTING_DEPTH), "001"), rig).status);
    EXPECT_EQ(1U, rig->indexed().size());

    rig = std::make_shared<Rig>();
    EXPECT_EQ(400, run(makeRequest(nested(invsync::common::MAX_JSON_NESTING_DEPTH + 1), "001"), rig).status);
    EXPECT_EQ(400, run(makeRequest(nested(1'000'000), "001"), rig).status);
    EXPECT_TRUE(rig->indexed().empty());
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

/// The header is the document id and `wazuh.agent.id`, so it must be the one canonical spelling the
/// whole-agent deletion matches. remoted only ever sends that form; a caller that bypasses it with
/// another spelling, or an id out of range, would index a document no deletion reaches.
TEST(StatsEndpointTest, ANonCanonicalAgentIdHeaderIsRejected)
{
    for (const auto* agentId : {"1", "07", "0007", "agent-one", "4294967297"})
    {
        auto rig = std::make_shared<Rig>();
        const auto response = run(makeRequest(kAgentReport, agentId), rig);

        EXPECT_EQ(400, response.status) << "header '" << agentId << "'";
        EXPECT_TRUE(rig->indexed().empty()) << "header '" << agentId << "'";
    }
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
    auto rig = std::make_shared<Rig>();
    auto handler =
        invsync::endpoints::stats::makeHandler(rig->client, rig->writer, testClusterIdentity(), rig->sweeper);
    auto responder = std::make_shared<CapturingResponder>();

    handler(nullptr, responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(400, responder->captured->status);
}

// The handler must not retain the payload: the document it builds owns its own copy, and holding the
// request would silently pin the transport's in-flight byte reservation.
TEST(StatsEndpointTest, HandlerDoesNotRetainTheRequest)
{
    auto rig = std::make_shared<Rig>();
    auto handler =
        invsync::endpoints::stats::makeHandler(rig->client, rig->writer, testClusterIdentity(), rig->sweeper);
    auto responder = std::make_shared<CapturingResponder>();

    auto request = makeRequest(kAgentReport, "001");
    std::weak_ptr<const HttpRequest> observer {request};

    handler(request, responder);
    request.reset();

    EXPECT_TRUE(observer.expired()) << "the handler must not keep the payload alive";
}

/**
 * The indexer gate. With no node the client would use, the caller gets a 503 to retry rather than a 200 that
 * pretends the document was stored, and nothing is posted (I151).
 */
TEST(StatsEndpointTest, NoUsableNodeIs503)
{
    auto rig = std::make_shared<Rig>(/*usable=*/false);

    const auto response = run(makeRequest(kAgentReport, "001"), rig);

    EXPECT_EQ(503, response.status);
    EXPECT_NE(response.body.find("Service unavailable"), std::string::npos) << response.body;
    EXPECT_TRUE(rig->indexed().empty());
}

/**
 * A refused post is a 503, never a 200: the document was fine, the client did not admit the write. Before the
 * indexer client this was a silent 200 (the async queue dropped the write later), I151.
 */
TEST(StatsEndpointTest, PostRefusedIs503)
{
    for (const auto cause :
         {indexer_client::Cause::QueueFull, indexer_client::Cause::Unavailable, indexer_client::Cause::ClientClosed})
    {
        auto rig = std::make_shared<Rig>();
        rig->writer->refuseWith(cause);

        const auto response = run(makeRequest(kAgentReport, "001"), rig);

        EXPECT_EQ(503, response.status) << indexer_client::toString(cause);
        EXPECT_NE(response.body.find("Service unavailable"), std::string::npos) << response.body;
        EXPECT_EQ(1U, rig->indexed().size()) << "the handler did offer the op: " << indexer_client::toString(cause);
    }
}

/**
 * The weak captures' other branch: stop() has already cleared the facade's Client or its writer, so lock() fails.
 * Same 503 to the caller (retry later is the same advice), distinguished only in the logs.
 */
TEST(StatsEndpointTest, ClientGoneIs503)
{
    // The writer is null: the facade's writer slot was reset.
    {
        auto rig = std::make_shared<Rig>();
        auto handler = invsync::endpoints::stats::makeHandler(
            rig->client, std::shared_ptr<indexer_client::IWriter> {}, testClusterIdentity(), rig->sweeper);
        auto responder = std::make_shared<CapturingResponder>();
        handler(makeRequest(kAgentReport, "001"), responder);
        ASSERT_TRUE(responder->captured.has_value());
        EXPECT_EQ(503, responder->captured->status);
        EXPECT_TRUE(rig->indexed().empty());
    }

    // The Client is gone: the facade's phase-2 teardown, from the handler's point of view.
    {
        auto rig = std::make_shared<Rig>();
        auto handler =
            invsync::endpoints::stats::makeHandler(rig->client, rig->writer, testClusterIdentity(), rig->sweeper);
        auto responder = std::make_shared<CapturingResponder>();
        rig->client.reset();
        handler(makeRequest(kAgentReport, "001"), responder);
        ASSERT_TRUE(responder->captured.has_value());
        EXPECT_EQ(503, responder->captured->status);
        EXPECT_TRUE(rig->indexed().empty());
    }
}

/**
 * Pins the ORDER of the checks, which is a deliberate design decision rather than an accident: a
 * malformed document is the caller's fault and stays a 400 even while the indexer is down. With the
 * checks reversed the agent would get a 503 and retry forever a payload that can never work.
 */
TEST(StatsEndpointTest, ValidationStillWinsOverAnUnavailableIndexer)
{
    auto rig = std::make_shared<Rig>(/*usable=*/false);

    for (const auto* body : {"", "{", "[]", R"("a string")", "not json at all", R"({"modules":{}})"})
    {
        const auto response = run(makeRequest(body, "001"), rig);
        EXPECT_EQ(400, response.status) << "body: " << body;
    }
}

TEST(StatsEndpointTest, AMissingAgentIdHeaderIsRejectedEvenWhenTheIndexerIsDown)
{
    auto rig = std::make_shared<Rig>(/*usable=*/false);

    const auto response = run(makeRequest(kAgentReport, "", /*withAgentHeader=*/false), rig);

    EXPECT_EQ(400, response.status);
    EXPECT_NE(response.body.find("agent id"), std::string::npos) << response.body;
}

/**
 * The load-bearing property of the whole injection: the handler holds the Client and the writer WEAKLY.
 *
 * If it ever captured a strong reference, the facade's stop() would stop destroying them at the point its phase-2
 * comment claims -- the transport's route table would keep them alive, and their destructors (with the
 * Client's threads) would run later, on whatever thread released the last responder. This test is what makes that
 * regression a failure instead of a subtle shutdown change.
 */
TEST(StatsEndpointTest, HandlerDoesNotHoldTheClientOrTheWriterAliveAfterReturning)
{
    auto rig = std::make_shared<Rig>();
    std::weak_ptr<invsync::test::FakeIndexerClient> clientObserver {rig->client};
    std::weak_ptr<invsync::test::FakeWriter> writerObserver {rig->writer};

    auto handler =
        invsync::endpoints::stats::makeHandler(rig->client, rig->writer, testClusterIdentity(), rig->sweeper);
    auto responder = std::make_shared<CapturingResponder>();
    handler(makeRequest(kAgentReport, "001"), responder);
    ASSERT_EQ(200, responder->captured->status) << "the handler must have used the client and the writer";

    rig->client.reset();
    rig->writer.reset();
    rig->events->m_agentStateWriter.reset();

    EXPECT_TRUE(clientObserver.expired())
        << "the handler (still alive) must not keep the Client alive -- see stop()'s phase 2";
    EXPECT_TRUE(writerObserver.expired())
        << "the handler (still alive) must not keep the writer alive -- see stop()'s phase 2";
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

/**
 * An agent enrolled again with the id of one just deleted: its first accepted report withdraws that id from the
 * deletion's pending sweep, which would otherwise delete the new agent's document by `_id` a window or two later. Only
 * that id: another agent's pending sweep stays.
 */
TEST(StatsEndpointTest, AcceptedWriteWithdrawsTheAgentFromThePendingSweep)
{
    auto rig = std::make_shared<Rig>();
    rig->sweeper->note("001");
    rig->sweeper->note("002");

    const auto response = run(makeRequest(kAgentReport, "001"), rig);
    ASSERT_EQ(200, response.status);

    rig->sweeper->stop();
    const auto stats = rig->sweeper->stats();
    EXPECT_EQ(1U, stats.forgotten) << "the reporting agent's sweep is withdrawn";
    EXPECT_EQ(1U, stats.dropped) << "the other agent's sweep was still pending at stop()";
}

/// A refused write stores nothing, so the pending sweep stays: the agent retries and the accepted retry withdraws it.
TEST(StatsEndpointTest, RefusedWriteKeepsThePendingSweep)
{
    auto rig = std::make_shared<Rig>();
    rig->writer->refuseWith(indexer_client::Cause::QueueFull);
    rig->sweeper->note("001");

    const auto response = run(makeRequest(kAgentReport, "001"), rig);
    ASSERT_EQ(503, response.status);

    rig->sweeper->stop();
    EXPECT_EQ(0U, rig->sweeper->stats().forgotten);
    EXPECT_EQ(1U, rig->sweeper->stats().dropped);
}

/// Without a sweeper (the facade's slot already reset) the write is still accepted.
TEST(StatsEndpointTest, ExpiredSweeperDoesNotFailTheWrite)
{
    auto rig = std::make_shared<Rig>();
    rig->sweeper.reset();

    EXPECT_EQ(200, run(makeRequest(kAgentReport, "001"), rig).status);
    EXPECT_EQ(1U, rig->indexed().size());
}
