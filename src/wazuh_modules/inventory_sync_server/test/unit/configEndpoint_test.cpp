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

        void index(std::string_view id, std::string_view index, std::string_view data) override
        {
            indexed.emplace_back(std::string {id}, std::string {index}, std::string {data});
            callOrder.emplace_back("index");
        }

        void indexDataStream(std::string_view index, std::string_view data) override
        {
            dataStreamed.emplace_back(std::string {index}, std::string {data});
            callOrder.emplace_back("indexDataStream");
        }

        void deleteByQuery(std::string_view index, std::string_view agentId, std::string_view clusterName) override
        {
            callOrder.emplace_back("deleteByQuery");
            if (deleteByQueryShouldThrow)
            {
                throw std::runtime_error("simulated deleteByQuery failure");
            }
            deletedByQuery.emplace_back(std::string {index}, std::string {agentId}, std::string {clusterName});
        }

        std::vector<std::tuple<std::string, std::string, std::string>> indexed;
        std::vector<std::pair<std::string, std::string>> dataStreamed;
        std::vector<std::tuple<std::string, std::string, std::string>> deletedByQuery;
        std::vector<std::string> callOrder;
        bool deleteByQueryShouldThrow {false};

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
    const auto body = R"([{"module":"fim","config":{"cpu":42}},{"module":"logcollector","config":{"lines":1}}])";

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
    ASSERT_TRUE(content.is_array());
    ASSERT_EQ(2U, content.size());
    EXPECT_EQ("fim", content[0].at("module").get<std::string>());
    EXPECT_EQ(42, content[0].at("config").at("cpu").get<int>());
    EXPECT_EQ("logcollector", content[1].at("module").get<std::string>());
}

/**
 * The timestamp shape is what makes the document indexable, so pin it rather than just its presence:
 * Utils::getCurrentISO8601() yields YYYY-MM-DDTHH:MM:SS.mmmZ (24 chars, milliseconds, trailing Z).
 */
TEST(ConfigEndpointTest, IndexedDocumentModifiedAtIsIso8601WithMillisecondsAndZulu)
{
    auto connector = std::make_shared<FakeAsyncConnector>();

    ASSERT_EQ(200, run(makeRequest("[]", "001"), connector).status);

    const auto document = soleIndexedDocument(*connector);
    const auto timestamp = document["/state/modified_at"_json_pointer].get<std::string>();

    ASSERT_EQ(24U, timestamp.size()) << "unexpected timestamp: " << timestamp;
    EXPECT_EQ('T', timestamp[10]);
    EXPECT_EQ('.', timestamp[19]);
    EXPECT_EQ('Z', timestamp.back());
}

/// document_version never carries over from whatever deleteByQuery just removed: each report
/// replaces the previous document outright, so there is no revision count to continue.
TEST(ConfigEndpointTest, IndexedDocumentVersionIsAlwaysOne)
{
    auto connector = std::make_shared<FakeAsyncConnector>();

    ASSERT_EQ(200, run(makeRequest("[]", "001"), connector).status);

    const auto document = soleIndexedDocument(*connector);
    EXPECT_EQ(1, document["/state/document_version"_json_pointer].get<int>());
}

TEST(ConfigEndpointTest, ResponseIsAnEmptyJsonAcknowledgment)
{
    const auto response = run(makeRequest("[]", "001"));

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

/// An empty array is a legitimate report (an agent with no configured modules), not a validation error.
TEST(ConfigEndpointTest, EmptyArrayIsAcceptedAndIndexedWithEmptyContent)
{
    auto connector = std::make_shared<FakeAsyncConnector>();

    ASSERT_EQ(200, run(makeRequest("[]", "001"), connector).status);

    const auto document = soleIndexedDocument(*connector);
    const auto content = document["/wazuh/agent/configuration/content"_json_pointer];
    ASSERT_TRUE(content.is_array());
    EXPECT_TRUE(content.empty());
}

/**
 * wazuh-agent-config's template is dynamic:strict: an extra key on an element would make the
 * (fire-and-forget) write fail with no way to report that back to the caller. Every element is
 * therefore rebuilt from just module/config rather than validated in place.
 */
TEST(ConfigEndpointTest, ExtraKeysOnAnElementAreDroppedBeforeIndexing)
{
    auto connector = std::make_shared<FakeAsyncConnector>();
    const auto body = R"([{"module":"fim","config":{"cpu":1},"bogus":"should not survive"}])";

    ASSERT_EQ(200, run(makeRequest(body, "001"), connector).status);

    const auto document = soleIndexedDocument(*connector);
    const auto entry = document["/wazuh/agent/configuration/content"_json_pointer][0];
    EXPECT_EQ(2U, entry.size()) << "only module and config must survive: " << entry.dump();
    EXPECT_TRUE(entry.contains("module"));
    EXPECT_TRUE(entry.contains("config"));
}

TEST(ConfigEndpointTest, NonArrayBodiesAreRejected)
{
    // Each of these parses as valid JSON but is not an array, so there is nothing to sanitize.
    for (const auto* body : {"{}", R"({"module":"fim","config":{}})", R"("a string")", "42", "true", "null"})
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

TEST(ConfigEndpointTest, NonObjectElementsAreRejected)
{
    for (const auto* body : {R"(["not an object"])", "[42]", "[[]]", "[null]"})
    {
        const auto response = run(makeRequest(body, "001"));
        EXPECT_EQ(400, response.status) << "body: " << body;
    }
}

TEST(ConfigEndpointTest, ElementsMissingModuleAreRejected)
{
    const auto response = run(makeRequest(R"([{"config":{}}])", "001"));
    EXPECT_EQ(400, response.status);
}

TEST(ConfigEndpointTest, ElementsWithNonStringOrEmptyModuleAreRejected)
{
    for (const auto* body : {R"([{"module":42,"config":{}}])", R"([{"module":"","config":{}}])"})
    {
        const auto response = run(makeRequest(body, "001"));
        EXPECT_EQ(400, response.status) << "body: " << body;
    }
}

TEST(ConfigEndpointTest, ElementsMissingConfigAreRejected)
{
    const auto response = run(makeRequest(R"([{"module":"fim"}])", "001"));
    EXPECT_EQ(400, response.status);
}

TEST(ConfigEndpointTest, ElementsWithNonObjectConfigAreRejected)
{
    for (const auto* body :
        {R"([{"module":"fim","config":42}])", R"([{"module":"fim","config":[]}])", R"([{"module":"fim","config":"x"}])"})
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
    const auto response = run(makeRequest("[]", "", /*withAgentHeader=*/false));

    EXPECT_EQ(400, response.status);
    EXPECT_NE(response.body.find("agent id"), std::string::npos) << response.body;
}

TEST(ConfigEndpointTest, AnEmptyAgentIdHeaderIsRejected)
{
    const auto response = run(makeRequest("[]", ""));

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

    auto request = makeRequest(R"([{"module":"fim","config":{}}])", "001");
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

    const auto response = run(makeRequest(R"([{"module":"fim","config":{}}])", "001"), connector);

    EXPECT_EQ(503, response.status);
    EXPECT_NE(response.body.find("Service unavailable"), std::string::npos) << response.body;
    EXPECT_TRUE(connector->indexed.empty());
    EXPECT_TRUE(connector->deletedByQuery.empty()) << "an unhealthy indexer must not even be asked to delete";
}

/**
 * The load-bearing ordering guarantee: deleteByQuery must complete before index() is even attempted,
 * so a document left over for this agent under a stale _id cannot survive alongside the fresh one.
 */
TEST(ConfigEndpointTest, DeleteByQueryRunsBeforeIndexingWithTheSameAgentIdAndClusterName)
{
    auto connector = std::make_shared<FakeAsyncConnector>();
    invsync::common::ClusterIdentity cluster {"prod-cluster", "node-03"};

    const auto response = run(makeRequest(R"([{"module":"fim","config":{}}])", "007"), connector, cluster);

    ASSERT_EQ(200, response.status);
    ASSERT_EQ(1U, connector->deletedByQuery.size());
    const auto& [index, agentId, clusterName] = connector->deletedByQuery.front();
    EXPECT_EQ("wazuh-agent-config", index);
    EXPECT_EQ("007", agentId);
    EXPECT_EQ("prod-cluster", clusterName);

    ASSERT_EQ(std::vector<std::string>({"deleteByQuery", "index"}), connector->callOrder);
}

/**
 * A deleteByQuery failure is the same kind of transient, server-side condition as an unavailable
 * indexer: the caller gets 503 to retry, and nothing gets indexed on top of whatever deleteByQuery
 * may or may not have removed.
 */
TEST(ConfigEndpointTest, ADeleteByQueryFailureYields503AndSkipsIndexing)
{
    auto connector = std::make_shared<FakeAsyncConnector>();
    connector->deleteByQueryShouldThrow = true;

    const auto response = run(makeRequest(R"([{"module":"fim","config":{}}])", "001"), connector);

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

    handler(makeRequest(R"([{"module":"fim","config":{}}])", "001"), responder);

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

    for (const auto* body : {"", "{", "{}", R"("a string")", "not json at all", R"([{"module":"fim"}])"})
    {
        const auto response = run(makeRequest(body, "001"), connector);
        EXPECT_EQ(400, response.status) << "body: " << body;
    }
}

TEST(ConfigEndpointTest, AMissingAgentIdHeaderIsRejectedEvenWhenTheIndexerIsDown)
{
    auto connector = std::make_shared<FakeAsyncConnector>(/*available=*/false);

    const auto response = run(makeRequest("[]", "", /*withAgentHeader=*/false), connector);

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
    handler(makeRequest(R"([{"module":"fim","config":{}}])", "001"), responder);
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
TEST(ConfigEndpointTest, StampsTheInjectedClusterNameAndNode)
{
    auto connector = std::make_shared<FakeAsyncConnector>();
    invsync::common::ClusterIdentity cluster {"prod-cluster", "node-03"};

    ASSERT_EQ(200, run(makeRequest("[]", "001"), connector, cluster).status);

    const auto document = soleIndexedDocument(*connector);
    EXPECT_EQ("prod-cluster", document["/wazuh/cluster/name"_json_pointer].get<std::string>());
    EXPECT_EQ("node-03", document["/wazuh/cluster/node"_json_pointer].get<std::string>());
}

/**
 * inventory_sync_server_config_t documents an empty cluster_name/node_name buffer as "no opinion",
 * not as "omit the field" -- so an unconfigured identity is stamped as an explicit empty string,
 * exactly like buildClusterIdentity() reads it. Silently dropping the field on empty would leave an
 * unclustered manager's documents impossible to tell apart from a stamping bug.
 */
TEST(ConfigEndpointTest, AnEmptyClusterIdentityIsStampedAsEmptyStringsNotOmitted)
{
    auto connector = std::make_shared<FakeAsyncConnector>();

    ASSERT_EQ(200, run(makeRequest("[]", "001"), connector, invsync::common::ClusterIdentity {}).status);

    const auto document = soleIndexedDocument(*connector);
    ASSERT_TRUE(document.contains("wazuh"));
    EXPECT_EQ("", document["/wazuh/cluster/name"_json_pointer].get<std::string>());
    EXPECT_EQ("", document["/wazuh/cluster/node"_json_pointer].get<std::string>());
}
