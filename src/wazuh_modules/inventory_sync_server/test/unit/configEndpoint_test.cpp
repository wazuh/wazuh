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
#include "endpoints/configEndpoint.hpp"
#include "testIndexerConnectorFakes.hpp"

#include <gtest/gtest.h>

#include <algorithm>
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

    /**
     * @brief The Client and the `agent-state` writer the handler is wired to, over the shared fakes.
     *
     * Reuses testIndexerConnectorFakes.hpp's FakeIndexerClient and scripted FakeWriter: the endpoint only asks
     * the Client for its health and posts into the writer, so those two are all it can observe. The Client is
     * usable unless a test says otherwise (`events->m_clientUsable`).
     */
    struct Rig
    {
        std::shared_ptr<invsync::test::ConnectorEvents> events {std::make_shared<invsync::test::ConnectorEvents>()};
        std::shared_ptr<invsync::test::FakeIndexerClient> client {
            std::make_shared<invsync::test::FakeIndexerClient>(events)};
        std::shared_ptr<invsync::test::FakeWriter> writer {events->m_agentStateWriter};

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
        auto handler = invsync::endpoints::config::makeHandler(rig->client, rig->writer, std::move(cluster));
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

    /// Parses the document of the single write a test expects the rig to have received.
    nlohmann::json soleIndexedDocument(const Rig& rig)
    {
        const auto ops = rig.indexed();
        if (ops.size() != 1)
        {
            return nlohmann::json {};
        }
        const auto document = nlohmann::json::parse(ops.front().body, nullptr, false);
        return document.is_discarded() ? nlohmann::json {} : document;
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

/**
 * The core positive path: a report with two modules lands, sanitized, under the agent id, in
 * wazuh-agent-config, and the agent gets the protocol-defined empty acknowledgment rather than the
 * document echoed back.
 */
TEST(ConfigEndpointTest, IndexesTheSanitizedModulesUnderTheAgentIdAndFixedIndexName)
{
    auto rig = std::make_shared<Rig>();
    const auto body = R"({"modules":{"fim":{"cpu":42},"logcollector":{"lines":1}}})";

    const auto response = run(makeRequest(body, "007"), rig);

    ASSERT_EQ(200, response.status);
    EXPECT_EQ("{}", response.body);

    const auto ops = rig->indexed();
    ASSERT_EQ(1U, ops.size());
    const auto& id = ops.front().id;
    const auto& index = ops.front().index;
    const auto& data = ops.front().body;
    EXPECT_EQ("007", ops.front().tag) << "the tag is what a deletion cancels";
    EXPECT_EQ("007", id);
    EXPECT_EQ("wazuh-agent-config", index);

    const auto document = nlohmann::json::parse(data, nullptr, false);
    ASSERT_FALSE(document.is_discarded());
    EXPECT_EQ("007", document["/wazuh/agent/id"_json_pointer].get<std::string>());
    const auto content = document["/wazuh/agent/configuration/content"_json_pointer];
    ASSERT_TRUE(content.is_object());
    ASSERT_EQ(2U, content.size());
    EXPECT_EQ(42, content.at("fim").at("cpu").get<int>());
    EXPECT_EQ(1, content.at("logcollector").at("lines").get<int>());
}

/// `modules` is derived from `content`'s keys, so the two can never drift apart.
TEST(ConfigEndpointTest, ModulesListsExactlyTheContentKeys)
{
    auto rig = std::make_shared<Rig>();
    const auto body = R"({"modules":{"fim":{},"logcollector":{}}})";

    ASSERT_EQ(200, run(makeRequest(body, "007"), rig).status);

    const auto document = soleIndexedDocument(*rig);
    const auto modules = document["/wazuh/agent/configuration/modules"_json_pointer];
    ASSERT_TRUE(modules.is_array());
    ASSERT_EQ(2U, modules.size());
    EXPECT_NE(std::find(modules.begin(), modules.end(), "fim"), modules.end());
    EXPECT_NE(std::find(modules.begin(), modules.end(), "logcollector"), modules.end());
}

/**
 * A module is unique per report by construction: `modules` is a JSON object, so a duplicate key in
 * the raw body resolves to the last value (nlohmann's parse semantics) rather than reaching `content`
 * twice or being rejected.
 */
TEST(ConfigEndpointTest, ADuplicateModuleNameIsResolvedByTheLastEntryWinning)
{
    auto rig = std::make_shared<Rig>();
    const auto body = R"({"modules":{"fim":{"cpu":1},"fim":{"cpu":2}}})";

    ASSERT_EQ(200, run(makeRequest(body, "001"), rig).status);

    const auto document = soleIndexedDocument(*rig);
    const auto content = document["/wazuh/agent/configuration/content"_json_pointer];
    EXPECT_EQ(1U, content.size());
    EXPECT_EQ(2, content.at("fim").at("cpu").get<int>());
    const auto modules = document["/wazuh/agent/configuration/modules"_json_pointer];
    ASSERT_EQ(1U, modules.size());
    EXPECT_EQ("fim", modules[0].get<std::string>());
}

TEST(ConfigEndpointTest, IndexedDocumentStampsTheWcsSchemaVersion)
{
    auto rig = std::make_shared<Rig>();

    ASSERT_EQ(200, run(makeRequest(R"({"modules":{"fim":{}}})", "001"), rig).status);

    const auto document = soleIndexedDocument(*rig);
    EXPECT_EQ("1.0", document["/wazuh/schema/version"_json_pointer].get<std::string>());
}

/**
 * The timestamp shape is what makes the document indexable, so pin it rather than just its presence:
 * Utils::getCurrentISO8601() yields YYYY-MM-DDTHH:MM:SS.mmmZ (24 chars, milliseconds, trailing Z).
 */
TEST(ConfigEndpointTest, IndexedDocumentModifiedAtIsIso8601WithMillisecondsAndZulu)
{
    auto rig = std::make_shared<Rig>();

    ASSERT_EQ(200, run(makeRequest(R"({"modules":{"fim":{}}})", "001"), rig).status);

    const auto document = soleIndexedDocument(*rig);
    const auto timestamp = document["/state/modified_at"_json_pointer].get<std::string>();

    ASSERT_EQ(24U, timestamp.size()) << "unexpected timestamp: " << timestamp;
    EXPECT_EQ('T', timestamp[10]);
    EXPECT_EQ('.', timestamp[19]);
    EXPECT_EQ('Z', timestamp.back());
}

/// The layout generation of `configuration`, not a per-report counter -- always 1 for this layout.
TEST(ConfigEndpointTest, IndexedDocumentVersionIsAlwaysOne)
{
    auto rig = std::make_shared<Rig>();

    ASSERT_EQ(200, run(makeRequest(R"({"modules":{"fim":{}}})", "001"), rig).status);

    const auto document = soleIndexedDocument(*rig);
    EXPECT_EQ(1, document["/state/document_version"_json_pointer].get<int>());
}

TEST(ConfigEndpointTest, ResponseIsAnEmptyJsonAcknowledgment)
{
    const auto response = run(makeRequest(R"({"modules":{"fim":{}}})", "001"));

    EXPECT_EQ(200, response.status);
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

/**
 * An empty `modules` object is rejected, not indexed: the document `_id` is the agent id, so a push
 * with no modules would replace the agent's last good configuration with an empty one. The agent's
 * collector skips a cycle rather than send an empty report, so this is a protocol violation. Same
 * rule POST /stats applies to its own empty report.
 */
TEST(ConfigEndpointTest, AnEmptyModulesObjectIsRejected)
{
    auto rig = std::make_shared<Rig>();

    const auto response = run(makeRequest(R"({"modules":{}})", "001"), rig);

    EXPECT_EQ(400, response.status);
    EXPECT_TRUE(rig->indexed().empty()) << "an empty report must never overwrite the stored document";
}

/**
 * The endpoint stores each module's configuration verbatim: it never judges or rewrites the inner
 * `config` object (the template is `dynamic: true`, so an undeclared key is indexed like any other
 * field). Only the outer shape -- a `modules` object whose every value is an object -- is validated.
 */
TEST(ConfigEndpointTest, ModuleConfigurationIsStoredVerbatim)
{
    auto rig = std::make_shared<Rig>();
    const auto body = R"({"modules":{"fim":{"cpu":1,"undeclared":"kept"}}})";

    ASSERT_EQ(200, run(makeRequest(body, "001"), rig).status);

    const auto document = soleIndexedDocument(*rig);
    const auto content = document["/wazuh/agent/configuration/content"_json_pointer];
    EXPECT_EQ(1U, content.size()) << content.dump();
    EXPECT_EQ(1, content.at("fim").at("cpu").get<int>());
    EXPECT_EQ("kept", content.at("fim").at("undeclared").get<std::string>());
}

TEST(ConfigEndpointTest, BodiesWithoutAModulesObjectAreRejected)
{
    // Each parses as valid JSON but does not carry a `modules` object, so there is nothing to store.
    for (const auto* body : {R"({"modules":[{"fim":{}}]})", // the legacy array wire, no longer accepted
                             R"({"modules":[]})",           // modules must be an object, not an array
                             R"({"modules":42})",
                             R"({"nope":{}})",
                             R"("a string")",
                             "42",
                             "true",
                             "null"})
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

TEST(ConfigEndpointTest, NonObjectModuleConfigurationsAreRejected)
{
    for (const auto* body : {R"({"modules":{"fim":"not an object"}})",
                             R"({"modules":{"fim":42}})",
                             R"({"modules":{"fim":[]}})",
                             R"({"modules":{"fim":null}})"})
    {
        const auto response = run(makeRequest(body, "001"));
        EXPECT_EQ(400, response.status) << "body: " << body;
    }
}

/**
 * The copy out of the parsed document and dump() both recurse once per level: a deep enough report
 * would overflow the I/O thread's stack and crash the whole of modulesd. The cap is checked on the raw
 * body, so the deepest legal report still goes through and one level more never reaches the parser or
 * the indexer. The attack-sized body would crash this test binary without the cap.
 */
TEST(ConfigEndpointTest, ReportsNestedPastTheLimitAreRejectedBeforeParsing)
{
    // root, modules and the module body are three levels; the rest is arrays under one field.
    const auto nested = [](std::size_t depth)
    {
        const std::size_t arrays = depth - 3;
        return R"({"modules":{"fim":{"x":)" + std::string(arrays, '[') + std::string(arrays, ']') + "}}}";
    };

    auto rig = std::make_shared<Rig>();
    EXPECT_EQ(200, run(makeRequest(nested(invsync::common::MAX_JSON_NESTING_DEPTH), "001"), rig).status);
    EXPECT_EQ(1U, rig->indexed().size());

    rig = std::make_shared<Rig>();
    EXPECT_EQ(400, run(makeRequest(nested(invsync::common::MAX_JSON_NESTING_DEPTH + 1), "001"), rig).status);
    EXPECT_EQ(400, run(makeRequest(nested(1'000'000), "001"), rig).status);
    EXPECT_TRUE(rig->indexed().empty());
}

TEST(ConfigEndpointTest, The400BodyIsValidParseableJsonEvenWhenTheReasonContainsQuotes)
{
    const auto response = run(makeRequest(R"({"modules":{"fim":42}})", "001"));

    ASSERT_EQ(400, response.status);
    const auto parsed = nlohmann::json::parse(response.body, nullptr, /*allow_exceptions=*/false);
    ASSERT_FALSE(parsed.is_discarded()) << "400 body is not valid JSON: " << response.body;
    EXPECT_EQ(400, parsed.value("code", 0));
    EXPECT_NE(parsed.value("error", std::string {}).find("object"), std::string::npos) << response.body;
}

/**
 * A request without the header did not come through remoted's authenticated route, so it is a
 * contract violation rather than agent input. Rejecting it is what stops the endpoint from inventing
 * an identity.
 */
TEST(ConfigEndpointTest, AMissingAgentIdHeaderIsRejected)
{
    const auto response = run(makeRequest(R"({"modules":{"fim":{}}})", "", /*withAgentHeader=*/false));

    EXPECT_EQ(400, response.status);
    EXPECT_NE(response.body.find("agent id"), std::string::npos) << response.body;
}

TEST(ConfigEndpointTest, AnEmptyAgentIdHeaderIsRejected)
{
    const auto response = run(makeRequest(R"({"modules":{"fim":{}}})", ""));

    EXPECT_EQ(400, response.status);
}

/// The header is the document id and `wazuh.agent.id`, so it must be the one canonical spelling the
/// whole-agent deletion matches. remoted only ever sends that form; a caller that bypasses it with
/// another spelling, or an id out of range, would index a document no deletion reaches.
TEST(ConfigEndpointTest, ANonCanonicalAgentIdHeaderIsRejected)
{
    for (const auto* agentId : {"1", "07", "0007", "agent-one", "4294967297"})
    {
        auto rig = std::make_shared<Rig>();
        const auto response = run(makeRequest(R"({"modules":{"fim":{}}})", agentId), rig);

        EXPECT_EQ(400, response.status) << "header '" << agentId << "'";
        EXPECT_TRUE(rig->indexed().empty()) << "header '" << agentId << "'";
    }
}

// A null request must not crash the handler: the transport never passes one today, but a null deref
// here would be a daemon crash.
TEST(ConfigEndpointTest, NullRequestIsToleratedAndStillAnswered)
{
    auto rig = std::make_shared<Rig>();
    auto handler = invsync::endpoints::config::makeHandler(rig->client, rig->writer, testClusterIdentity());
    auto responder = std::make_shared<CapturingResponder>();

    handler(nullptr, responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(400, responder->captured->status);
}

// The handler must not retain the payload: it does not need it once the sanitized copy is built, and
// holding the request would silently pin the transport's in-flight byte reservation.
TEST(ConfigEndpointTest, HandlerDoesNotRetainTheRequest)
{
    auto rig = std::make_shared<Rig>();
    auto handler = invsync::endpoints::config::makeHandler(rig->client, rig->writer, testClusterIdentity());
    auto responder = std::make_shared<CapturingResponder>();

    auto request = makeRequest(R"({"modules":{"fim":{}}})", "001");
    std::weak_ptr<const HttpRequest> observer {request};

    handler(request, responder);
    request.reset();

    EXPECT_TRUE(observer.expired()) << "the handler must not keep the payload alive";
}

/**
 * The indexer gate. An unreachable indexer is a transient, server-side condition, so the caller gets a
 * 503 to retry rather than a 200 that pretends the document was handled.
 */
TEST(ConfigEndpointTest, PostAcceptedIs200)
{
    auto rig = std::make_shared<Rig>();

    const auto response = run(makeRequest(R"({"modules":{"fim":{"cpu":1}}})", "007"), rig);

    EXPECT_EQ(200, response.status);
    EXPECT_EQ("{}", response.body);
    const auto ops = rig->indexed();
    ASSERT_EQ(1U, ops.size());
    EXPECT_EQ("007", ops.front().id);
    EXPECT_EQ("007", ops.front().tag);
    EXPECT_EQ("wazuh-agent-config", ops.front().index);
    EXPECT_EQ(indexer_client::Op::Kind::Index, ops.front().kind);
    EXPECT_TRUE(rig->writer->cancelled().empty()) << "/config never cancels anything";
}

/// With no node the client would use, the caller gets a 503 to retry, and nothing is posted (I151).
TEST(ConfigEndpointTest, NoUsableNodeIs503)
{
    auto rig = std::make_shared<Rig>(/*usable=*/false);

    const auto response = run(makeRequest(R"({"modules":{"fim":{}}})", "001"), rig);

    EXPECT_EQ(503, response.status);
    EXPECT_NE(response.body.find("Service unavailable"), std::string::npos) << response.body;
    EXPECT_TRUE(rig->indexed().empty());
}

/// A refused post is a 503, never a 200 and never a 400: the document was fine, the client did not admit it.
TEST(ConfigEndpointTest, PostRefusedIs503)
{
    for (const auto cause :
         {indexer_client::Cause::QueueFull, indexer_client::Cause::Unavailable, indexer_client::Cause::ClientClosed})
    {
        auto rig = std::make_shared<Rig>();
        rig->writer->refuseWith(cause);

        const auto response = run(makeRequest(R"({"modules":{"fim":{"cpu":1}}})", "001"), rig);

        EXPECT_EQ(503, response.status) << indexer_client::toString(cause);
        EXPECT_NE(response.body.find("Service unavailable"), std::string::npos) << response.body;
        EXPECT_EQ(1U, rig->indexed().size()) << "the handler did offer the op: " << indexer_client::toString(cause);
    }
}

/**
 * The weak captures' other branch: stop() has already cleared the facade's Client or its writer, so lock() fails.
 * Same 503 to the caller (retry later is the same advice), distinguished only in the logs.
 */
TEST(ConfigEndpointTest, ClientGoneIs503)
{
    {
        auto rig = std::make_shared<Rig>();
        auto handler = invsync::endpoints::config::makeHandler(
            rig->client, std::shared_ptr<indexer_client::IWriter> {}, testClusterIdentity());
        auto responder = std::make_shared<CapturingResponder>();
        handler(makeRequest(R"({"modules":{"fim":{}}})", "001"), responder);
        ASSERT_TRUE(responder->captured.has_value());
        EXPECT_EQ(503, responder->captured->status);
        EXPECT_TRUE(rig->indexed().empty());
    }

    {
        auto rig = std::make_shared<Rig>();
        auto handler = invsync::endpoints::config::makeHandler(rig->client, rig->writer, testClusterIdentity());
        auto responder = std::make_shared<CapturingResponder>();
        rig->client.reset(); // the facade's phase-2 teardown, from the handler's point of view
        handler(makeRequest(R"({"modules":{"fim":{}}})", "001"), responder);
        ASSERT_TRUE(responder->captured.has_value());
        EXPECT_EQ(503, responder->captured->status);
        EXPECT_TRUE(rig->indexed().empty());
    }
}

TEST(ConfigEndpointTest, ValidationStillWinsOverAnUnavailableIndexer)
{
    auto rig = std::make_shared<Rig>(/*usable=*/false);

    for (const auto* body : {"", "{", "{}", R"("a string")", "not json at all", R"({"modules":{"fim":42}})"})
    {
        const auto response = run(makeRequest(body, "001"), rig);
        EXPECT_EQ(400, response.status) << "body: " << body;
    }
}

TEST(ConfigEndpointTest, AMissingAgentIdHeaderIsRejectedEvenWhenTheIndexerIsDown)
{
    auto rig = std::make_shared<Rig>(/*usable=*/false);

    const auto response = run(makeRequest(R"({"modules":{"fim":{}}})", "", /*withAgentHeader=*/false), rig);

    EXPECT_EQ(400, response.status);
    EXPECT_NE(response.body.find("agent id"), std::string::npos) << response.body;
}

/**
 * The load-bearing property of the whole injection: the handler holds the Client and the writer WEAKLY.
 *
 * If it ever captured a strong reference, the facade's stop() would stop destroying them at the point its phase-2
 * comment claims -- the transport's route table would keep them alive, and their destructors (with the
 * Client's threads) would run later, on whatever thread released the last responder.
 */
TEST(ConfigEndpointTest, HandlerDoesNotHoldTheClientOrTheWriterAliveAfterReturning)
{
    auto rig = std::make_shared<Rig>();
    std::weak_ptr<invsync::test::FakeIndexerClient> clientObserver {rig->client};
    std::weak_ptr<invsync::test::FakeWriter> writerObserver {rig->writer};

    auto handler = invsync::endpoints::config::makeHandler(rig->client, rig->writer, testClusterIdentity());
    auto responder = std::make_shared<CapturingResponder>();
    handler(makeRequest(R"({"modules":{"fim":{}}})", "001"), responder);
    ASSERT_EQ(200, responder->captured->status) << "the handler must have used the client and the writer";

    rig->client.reset();
    rig->writer.reset();
    rig->events->m_agentStateWriter.reset();

    EXPECT_TRUE(clientObserver.expired())
        << "the handler (still alive) must not keep the Client alive -- see stop()'s phase 2";
    EXPECT_TRUE(writerObserver.expired())
        << "the handler (still alive) must not keep the writer alive -- see stop()'s phase 2";
}

/// The agent's groups and host land under `wazuh.agent`, next to the authenticated id and the
/// configuration, and nothing else from the `agent` block follows them.
TEST(ConfigEndpointTest, CopiesReportedGroupsAndHostUnderWazuhAgent)
{
    auto rig = std::make_shared<Rig>();
    const auto body = R"({"modules":{"fim":{"cpu":42}},)"
                      R"("agent":{"id":"999","version":"v5.0.0","groups":["default"],)"
                      R"("host":{"architecture":"aarch64","hostname":"db-01",)"
                      R"("os":{"name":"Amazon Linux","platform":"amzn","type":"linux","version":"2023"}}}})";

    ASSERT_EQ(200, run(makeRequest(body, "007"), rig).status);

    const auto document = soleIndexedDocument(*rig);
    const auto& agent = document["/wazuh/agent"_json_pointer];
    EXPECT_EQ("007", agent.at("id").get<std::string>()) << "claimed 999";
    EXPECT_EQ(nlohmann::json::parse(R"(["default"])"), agent.at("groups"));
    EXPECT_EQ("aarch64", agent.at("host").at("architecture").get<std::string>());
    EXPECT_EQ("amzn", agent.at("host").at("os").at("platform").get<std::string>());
    EXPECT_FALSE(agent.contains("version"));
    EXPECT_EQ(42, agent.at("configuration").at("content").at("fim").at("cpu").get<int>());
}

/// An agent that predates the metadata sends no `agent` block: no empty groups or host are made up.
TEST(ConfigEndpointTest, AReportWithoutAgentMetadataIndexesNoGroupsOrHost)
{
    auto rig = std::make_shared<Rig>();

    ASSERT_EQ(200, run(makeRequest(R"({"modules":{"fim":{}}})", "001"), rig).status);

    const auto document = soleIndexedDocument(*rig);
    const auto& agent = document["/wazuh/agent"_json_pointer];
    EXPECT_FALSE(agent.contains("groups"));
    EXPECT_FALSE(agent.contains("host"));
}

/// Bad metadata is left empty, never a 400: the agent would resend it every cycle and stop reporting.
TEST(ConfigEndpointTest, InvalidAgentMetadataIsLeftEmptyNotRejected)
{
    auto rig = std::make_shared<Rig>();
    const auto body = R"({"modules":{"fim":{}},"agent":{"groups":"default","host":{"os":{"version":2023}}}})";

    ASSERT_EQ(200, run(makeRequest(body, "001"), rig).status);

    const auto document = soleIndexedDocument(*rig);
    EXPECT_EQ(nlohmann::json::array(), document["/wazuh/agent/groups"_json_pointer]);
    EXPECT_EQ("", document["/wazuh/agent/host/os/version"_json_pointer].get<std::string>());
    EXPECT_TRUE(document["/wazuh/agent/configuration/content"_json_pointer].contains("fim"));
}

/**
 * The cluster identity is injected at registration time (makeHandler()'s `cluster` parameter), not
 * read from anything the caller sends -- there is no per-request source for it in the new array body
 * shape either.
 */
TEST(ConfigEndpointTest, StampsTheInjectedClusterName)
{
    auto rig = std::make_shared<Rig>();
    invsync::common::ClusterIdentity cluster {"prod-cluster"};

    ASSERT_EQ(200, run(makeRequest(R"({"modules":{"fim":{}}})", "001"), rig, cluster).status);

    const auto document = soleIndexedDocument(*rig);
    EXPECT_EQ("prod-cluster", document["/wazuh/cluster/name"_json_pointer].get<std::string>());
}

/**
 * inventory_sync_server_config_t documents an empty cluster_name buffer as "no opinion", not as
 * "omit the field" -- so an unconfigured identity is stamped as an explicit empty string, exactly
 * like buildClusterIdentity() reads it. Silently dropping the field on empty would leave an
 * unclustered manager's documents impossible to tell apart from a stamping bug.
 */
TEST(ConfigEndpointTest, AnEmptyClusterIdentityIsStampedAsEmptyStringNotOmitted)
{
    auto rig = std::make_shared<Rig>();

    ASSERT_EQ(200,
              run(makeRequest(R"({"modules":{"fim":{}}})", "001"), rig, invsync::common::ClusterIdentity {}).status);

    const auto document = soleIndexedDocument(*rig);
    ASSERT_TRUE(document.contains("wazuh"));
    EXPECT_EQ("", document["/wazuh/cluster/name"_json_pointer].get<std::string>());
}
