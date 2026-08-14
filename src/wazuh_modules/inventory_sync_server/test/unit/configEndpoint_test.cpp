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
#include "endpoints/configEndpoint.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <json.hpp>
#include <memory>
#include <optional>
#include <stdexcept>
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
        request->target = "/config";
        request->body = std::move(body);
        if (withAgentHeader)
        {
            request->headers.emplace(invsync::endpoints::config::agentIdHeader(), std::move(agentId));
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

        // Simulates a transient write-time failure (e.g. a queue/broker error) on an otherwise
        // healthy, available connector -- distinct from isAvailable()==false, which the handler
        // checks beforehand and never even reaches this call.
        void index(std::string_view id, std::string_view index, std::string_view data) override
        {
            if (throwOnIndex)
            {
                throw std::runtime_error {"simulated indexer write failure"};
            }
            indexed.emplace_back(std::string {id}, std::string {index}, std::string {data});
        }

        bool throwOnIndex {false};

        void indexDataStream(std::string_view index, std::string_view data) override
        {
            dataStreamed.emplace_back(std::string {index}, std::string {data});
        }

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
        auto handler = invsync::endpoints::config::makeHandler(connector, std::move(cluster));
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

    /// Parses the data half of the single write a test expects `connector` to have received.
    nlohmann::json soleIndexedDocument(const FakeAsyncConnector& connector)
    {
        if (connector.indexed.size() != 1)
        {
            return nlohmann::json {};
        }
        const auto document = nlohmann::json::parse(std::get<2>(connector.indexed.front()), nullptr, false);
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
    auto connector = std::make_shared<FakeAsyncConnector>();
    const auto body = R"({"modules":{"fim":{"cpu":42},"logcollector":{"lines":1}}})";

    const auto response = run(makeRequest(body, "007"), connector);

    ASSERT_EQ(200, response.status);
    EXPECT_EQ("{}", response.body);

    ASSERT_EQ(1U, connector->indexed.size());
    const auto& [id, index, data] = connector->indexed.front();
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
    auto connector = std::make_shared<FakeAsyncConnector>();
    const auto body = R"({"modules":{"fim":{},"logcollector":{}}})";

    ASSERT_EQ(200, run(makeRequest(body, "007"), connector).status);

    const auto document = soleIndexedDocument(*connector);
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
    auto connector = std::make_shared<FakeAsyncConnector>();
    const auto body = R"({"modules":{"fim":{"cpu":1},"fim":{"cpu":2}}})";

    ASSERT_EQ(200, run(makeRequest(body, "001"), connector).status);

    const auto document = soleIndexedDocument(*connector);
    const auto content = document["/wazuh/agent/configuration/content"_json_pointer];
    EXPECT_EQ(1U, content.size());
    EXPECT_EQ(2, content.at("fim").at("cpu").get<int>());
    const auto modules = document["/wazuh/agent/configuration/modules"_json_pointer];
    ASSERT_EQ(1U, modules.size());
    EXPECT_EQ("fim", modules[0].get<std::string>());
}

TEST(ConfigEndpointTest, IndexedDocumentStampsTheWcsSchemaVersion)
{
    auto connector = std::make_shared<FakeAsyncConnector>();

    ASSERT_EQ(200, run(makeRequest(R"({"modules":{"fim":{}}})", "001"), connector).status);

    const auto document = soleIndexedDocument(*connector);
    EXPECT_EQ("1.0", document["/wazuh/schema/version"_json_pointer].get<std::string>());
}

/**
 * The timestamp shape is what makes the document indexable, so pin it rather than just its presence:
 * Utils::getCurrentISO8601() yields YYYY-MM-DDTHH:MM:SS.mmmZ (24 chars, milliseconds, trailing Z).
 */
TEST(ConfigEndpointTest, IndexedDocumentModifiedAtIsIso8601WithMillisecondsAndZulu)
{
    auto connector = std::make_shared<FakeAsyncConnector>();

    ASSERT_EQ(200, run(makeRequest(R"({"modules":{"fim":{}}})", "001"), connector).status);

    const auto document = soleIndexedDocument(*connector);
    const auto timestamp = document["/state/modified_at"_json_pointer].get<std::string>();

    ASSERT_EQ(24U, timestamp.size()) << "unexpected timestamp: " << timestamp;
    EXPECT_EQ('T', timestamp[10]);
    EXPECT_EQ('.', timestamp[19]);
    EXPECT_EQ('Z', timestamp.back());
}

/// The layout generation of `configuration`, not a per-report counter -- always 1 for this layout.
TEST(ConfigEndpointTest, IndexedDocumentVersionIsAlwaysOne)
{
    auto connector = std::make_shared<FakeAsyncConnector>();

    ASSERT_EQ(200, run(makeRequest(R"({"modules":{"fim":{}}})", "001"), connector).status);

    const auto document = soleIndexedDocument(*connector);
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
    auto connector = std::make_shared<FakeAsyncConnector>();

    const auto response = run(makeRequest(R"({"modules":{}})", "001"), connector);

    EXPECT_EQ(400, response.status);
    EXPECT_TRUE(connector->indexed.empty()) << "an empty report must never overwrite the stored document";
}

/**
 * The endpoint stores each module's configuration verbatim: it never judges or rewrites the inner
 * `config` object (the template is `dynamic: false`, so an undeclared key is stored in `_source` and
 * simply not indexed). Only the outer shape -- a `modules` object whose every value is an object --
 * is validated.
 */
TEST(ConfigEndpointTest, ModuleConfigurationIsStoredVerbatim)
{
    auto connector = std::make_shared<FakeAsyncConnector>();
    const auto body = R"({"modules":{"fim":{"cpu":1,"undeclared":"kept"}}})";

    ASSERT_EQ(200, run(makeRequest(body, "001"), connector).status);

    const auto document = soleIndexedDocument(*connector);
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

// A null request must not crash the handler: the transport never passes one today, but a null deref
// here would be a daemon crash.
TEST(ConfigEndpointTest, NullRequestIsToleratedAndStillAnswered)
{
    auto connector = std::make_shared<FakeAsyncConnector>();
    auto handler = invsync::endpoints::config::makeHandler(connector, testClusterIdentity());
    auto responder = std::make_shared<CapturingResponder>();

    handler(nullptr, responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(400, responder->captured->status);
}

// The handler must not retain the payload: it does not need it once the sanitized copy is built, and
// holding the request would silently pin the transport's in-flight byte reservation.
TEST(ConfigEndpointTest, HandlerDoesNotRetainTheRequest)
{
    auto connector = std::make_shared<FakeAsyncConnector>();
    auto handler = invsync::endpoints::config::makeHandler(connector, testClusterIdentity());
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
TEST(ConfigEndpointTest, UnavailableIndexerYields503)
{
    auto connector = std::make_shared<FakeAsyncConnector>(/*available=*/false);

    const auto response = run(makeRequest(R"({"modules":{"fim":{}}})", "001"), connector);

    EXPECT_EQ(503, response.status);
    EXPECT_NE(response.body.find("Service unavailable"), std::string::npos) << response.body;
    EXPECT_TRUE(connector->indexed.empty());
}

TEST(ConfigEndpointTest, AWriteFailureOnAnAvailableIndexerYields503NotBadRequest)
{
    auto connector = std::make_shared<FakeAsyncConnector>();
    connector->throwOnIndex = true;

    const auto response = run(makeRequest(R"({"modules":{"fim":{"cpu":1}}})", "001"), connector);

    EXPECT_EQ(503, response.status);
    EXPECT_NE(response.body.find("Service unavailable"), std::string::npos) << response.body;
    EXPECT_TRUE(connector->indexed.empty());
}

/**
 * The weak capture's other branch: stop() has already cleared the facade's connector, so lock() fails.
 * Same 503 to the caller (retry later is the same advice), distinguished only in the logs.
 */
TEST(ConfigEndpointTest, AnExpiredConnectorYields503)
{
    auto connector = std::make_shared<FakeAsyncConnector>();
    auto handler = invsync::endpoints::config::makeHandler(connector, testClusterIdentity());
    auto responder = std::make_shared<CapturingResponder>();

    connector.reset(); // the facade's phase-2 teardown, from the handler's point of view

    handler(makeRequest(R"({"modules":{"fim":{}}})", "001"), responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(503, responder->captured->status);
}

/**
 * Pins the ORDER of the checks, which is a deliberate design decision rather than an accident: a
 * malformed document is the caller's fault and stays a 400 even while the indexer is down. With the
 * checks reversed the agent would get a 503 and retry forever a payload that can never work.
 */
TEST(ConfigEndpointTest, ValidationStillWinsOverAnUnavailableIndexer)
{
    auto connector = std::make_shared<FakeAsyncConnector>(/*available=*/false);

    for (const auto* body : {"", "{", "{}", R"("a string")", "not json at all", R"({"modules":{"fim":42}})"})
    {
        const auto response = run(makeRequest(body, "001"), connector);
        EXPECT_EQ(400, response.status) << "body: " << body;
    }
}

TEST(ConfigEndpointTest, AMissingAgentIdHeaderIsRejectedEvenWhenTheIndexerIsDown)
{
    auto connector = std::make_shared<FakeAsyncConnector>(/*available=*/false);

    const auto response = run(makeRequest(R"({"modules":{"fim":{}}})", "", /*withAgentHeader=*/false), connector);

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
TEST(ConfigEndpointTest, HandlerDoesNotHoldTheConnectorAliveAfterReturning)
{
    auto connector = std::make_shared<FakeAsyncConnector>();
    std::weak_ptr<FakeAsyncConnector> observer {connector};

    auto handler = invsync::endpoints::config::makeHandler(connector, testClusterIdentity());
    auto responder = std::make_shared<CapturingResponder>();
    handler(makeRequest(R"({"modules":{"fim":{}}})", "001"), responder);
    ASSERT_EQ(200, responder->captured->status) << "the handler must have used the connector";

    connector.reset();

    EXPECT_TRUE(observer.expired())
        << "the handler (still alive) must not keep the connector alive -- see stop()'s phase 2";
}

/**
 * The cluster identity is injected at registration time (makeHandler()'s `cluster` parameter), not
 * read from anything the caller sends -- there is no per-request source for it in the new array body
 * shape either.
 */
TEST(ConfigEndpointTest, StampsTheInjectedClusterName)
{
    auto connector = std::make_shared<FakeAsyncConnector>();
    invsync::common::ClusterIdentity cluster {"prod-cluster"};

    ASSERT_EQ(200, run(makeRequest(R"({"modules":{"fim":{}}})", "001"), connector, cluster).status);

    const auto document = soleIndexedDocument(*connector);
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
    auto connector = std::make_shared<FakeAsyncConnector>();

    ASSERT_EQ(
        200,
        run(makeRequest(R"({"modules":{"fim":{}}})", "001"), connector, invsync::common::ClusterIdentity {}).status);

    const auto document = soleIndexedDocument(*connector);
    ASSERT_TRUE(document.contains("wazuh"));
    EXPECT_EQ("", document["/wazuh/cluster/name"_json_pointer].get<std::string>());
}
