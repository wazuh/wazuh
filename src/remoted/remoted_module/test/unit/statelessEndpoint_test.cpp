/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Unit-tests the /stateless endpoint policy: the downstream target it builds, how it maps a
// downstream result to the agent response, and the pre-forward identity check + full handler.
// Pure functions where possible -- no sockets, no async -- except the makeHandler() glue tests,
// which need a (fake) downstream client + a real DeferredForwarder to prove the short-circuit.
#include "endpoints/statelessEndpoint.hpp"

#include "common/requestOutcomeMetrics.hpp"
#include "downstream/IDownstreamClient.hpp"
#include "downstream/deferredWorkLimiter.hpp"

#include <wazuh_metrics/manager.hpp>

#include <gtest/gtest.h>

#include <rapidjson/document.h>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

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
    const auto target = stateless::target("queue/sockets/engine-ingest-http.sock");
    EXPECT_EQ(target.socketPath, "queue/sockets/engine-ingest-http.sock");
    EXPECT_EQ(target.method, Method::Post);
    EXPECT_EQ(target.path, "/events/enriched");
    EXPECT_EQ(target.contentType, "application/x-ndjson");
    // /stateless deliberately does NOT override the response deadline: event ingestion is fast, so
    // it stays on the global remoted.downstream_response_timeout. The 0 sentinel is what expresses
    // that -- a future slow endpoint is the one that sets a value here.
    EXPECT_EQ(target.responseTimeoutMs, 0);
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

TEST(ValidatePayloadIdentity, MatchingNumericAgentIdSucceeds)
{
    const auto fixture = makeAuthReq("H {\"wazuh\":{\"agent\":{\"id\":\"1001\"}}}\nE some event\n", "1001");
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::None);
}

TEST(ValidatePayloadIdentity, ZeroPaddingThatDiffersFromTheTokenIsRejected)
{
    // Header says "001", the token proves "1". Same number, different string -- and it is the
    // string that travels: the body is forwarded verbatim and the engine both keys its
    // agent-metadata cache on that raw id and writes it into every event. Accepting this would let
    // one agent file events under an id no agent has, and mint a cache entry per spelling.
    const auto fixture = makeAuthReq("H {\"wazuh\":{\"agent\":{\"id\":\"001\"}}}\nE some event\n", "1");
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::PayloadAgentMismatch);
}

TEST(ValidatePayloadIdentity, ExtraZeroPaddingOnACanonicalIdIsRejected)
{
    // The same in the other direction, against a canonical token id.
    const auto fixture = makeAuthReq("H {\"wazuh\":{\"agent\":{\"id\":\"0001\"}}}\nE some event\n", "001");
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::PayloadAgentMismatch);
}

TEST(ValidatePayloadIdentity, CanonicalZeroPaddedIdMatchesItself)
{
    // A conforming agent stamps the H line from the same string its token carries, so the canonical
    // zero-padded form matches exactly and is unaffected by the byte-for-byte comparison.
    const auto fixture = makeAuthReq("H {\"wazuh\":{\"agent\":{\"id\":\"001\"}}}\nE some event\n", "001");
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::None);
}

TEST(ValidatePayloadIdentity, HeaderOnlyBodyWithNoTrailingNewlineStillMatches)
{
    // No '\n' at all -- an H-line-only body (no events) is still a valid slice.
    const auto fixture = makeAuthReq("H {\"wazuh\":{\"agent\":{\"id\":\"7\"}}}", "7");
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::None);
}

TEST(ValidatePayloadIdentity, NumericMismatchIsRejected)
{
    const auto fixture = makeAuthReq("H {\"wazuh\":{\"agent\":{\"id\":\"1001\"}}}\nE some event\n", "1002");
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::PayloadAgentMismatch);
}

TEST(ValidatePayloadIdentity, NonNumericAgentIdInPayloadIsRejected)
{
    const auto fixture = makeAuthReq("H {\"wazuh\":{\"agent\":{\"id\":\"abc\"}}}\nE some event\n", "1001");
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::PayloadAgentMismatch);
}

TEST(ValidatePayloadIdentity, NonNumericAuthenticatedAgentIdIsRejected)
{
    // Defensive: with the tightened Authorization charset this shouldn't reach the endpoint in the
    // full pipeline, but validatePayloadIdentity() must still be robust to it on its own contract.
    const auto fixture = makeAuthReq("H {\"wazuh\":{\"agent\":{\"id\":\"1001\"}}}\nE some event\n", "agent-one");
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::PayloadAgentMismatch);
}

TEST(ValidatePayloadIdentity, NegativeAgentIdIsRejected)
{
    const auto fixture = makeAuthReq("H {\"wazuh\":{\"agent\":{\"id\":\"-1\"}}}\nE some event\n", "1");
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::PayloadAgentMismatch);
}

TEST(ValidatePayloadIdentity, PartiallyNumericAgentIdIsRejected)
{
    const auto fixture = makeAuthReq("H {\"wazuh\":{\"agent\":{\"id\":\"12x\"}}}\nE some event\n", "12");
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::PayloadAgentMismatch);
}

TEST(ValidatePayloadIdentity, MissingHeaderLineIsRejected)
{
    const auto fixture = makeAuthReq("E some event\n", "1001"); // no "H " line at all
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::PayloadAgentMismatch);
}

TEST(ValidatePayloadIdentity, EmptyBodyIsRejected)
{
    const auto fixture = makeAuthReq("", "1001");
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::PayloadAgentMismatch);
}

TEST(ValidatePayloadIdentity, MalformedJsonIsRejected)
{
    const auto fixture = makeAuthReq("H {not json}\nE some event\n", "1001");
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::PayloadAgentMismatch);
}

TEST(ValidatePayloadIdentity, MissingAgentIdKeyIsRejected)
{
    const auto fixture = makeAuthReq("H {\"wazuh\":{\"agent\":{}}}\nE some event\n", "1001");
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::PayloadAgentMismatch);
}

TEST(ValidatePayloadIdentity, NonStringAgentIdIsRejected)
{
    const auto fixture = makeAuthReq("H {\"wazuh\":{\"agent\":{\"id\":1001}}}\nE some event\n", "1001");
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::PayloadAgentMismatch);
}

TEST(ValidatePayloadIdentity, OversizedHeaderLineIsRejectedWithoutParsing)
{
    // Larger than the 8 KiB defensive cap (headerLineJson()) -- rejected before any JSON parsing is
    // even attempted, same bucket as any other malformed/oversized header.
    const std::string hugeAgentId(16U * 1024U, '1');
    const std::string body = "H {\"wazuh\":{\"agent\":{\"id\":\"" + hugeAgentId + "\"}}}\nE some event\n";
    const auto fixture = makeAuthReq(body, "1001");
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::PayloadAgentMismatch);
}

// --- Repeated identity members -----------------------------------------------------------------
//
// A lookup here takes the FIRST member of a duplicated name, the engine's merge keeps the LAST, and
// the body travels between them byte for byte. Each rejection below is a header whose FIRST
// identity is the authenticated agent's own -- so the pre-fix check accepted it -- while a repeated
// step of /wazuh/agent/id carries another agent's.
//
// The acceptance cases pin the SCOPE: repetitions off the identity path are allowed through,
// because they cannot move the identity once the engine escapes member names when building the
// pointer it recurses with. That half is tested in the engine (base_utest, Merge* cases).

TEST(ValidatePayloadIdentity, RepeatedWazuhMemberIsRejected)
{
    const auto fixture = makeAuthReq(R"(H {"wazuh":{"agent":{"id":"1"}},"wazuh":{"agent":{"id":"2"}}})"
                                     "\nE some event\n",
                                     "1");
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::PayloadAgentMismatch);
}

TEST(ValidatePayloadIdentity, RepeatedAgentMemberIsRejected)
{
    // One level down. A check that only inspected the root object would accept this.
    const auto fixture = makeAuthReq(R"(H {"wazuh":{"agent":{"id":"1"},"agent":{"id":"2"}}})"
                                     "\nE some event\n",
                                     "1");
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::PayloadAgentMismatch);
}

TEST(ValidatePayloadIdentity, RepeatedAgentIdIsRejected)
{
    const auto fixture = makeAuthReq(R"(H {"wazuh":{"agent":{"id":"1","id":"2"}}})"
                                     "\nE some event\n",
                                     "1");
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::PayloadAgentMismatch);
}

TEST(ValidatePayloadIdentity, RepeatedAgentIdWithIdenticalValuesIsRejected)
{
    // Both copies agree, so nothing is spoofed -- but the document is still ambiguous about a key
    // this endpoint's decision depends on. The rule is "exactly once", which is checkable; "once,
    // or more if they happen to agree" is not.
    const auto fixture = makeAuthReq(R"(H {"wazuh":{"agent":{"id":"1","id":"1"}}})"
                                     "\nE some event\n",
                                     "1");
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::PayloadAgentMismatch);
}

TEST(ValidatePayloadIdentity, EscapedDuplicateIdentityMemberIsRejected)
{
    // "\u0077azuh" decodes to "wazuh": after parsing there are two members of that name. The
    // repetition is only visible once names are compared DECODED -- comparing the raw source bytes
    // would miss it and leave the flaw reachable behind an escape.
    const auto fixture =
        makeAuthReq("H {\"wazuh\":{\"agent\":{\"id\":\"1\"}},\"\\u0077azuh\":{\"agent\":{\"id\":\"2\"}}}"
                    "\nE some event\n",
                    "1");
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::PayloadAgentMismatch);
}

TEST(ValidatePayloadIdentity, EscapedIdentityMemberNameIsAccepted)
{
    // The same escaping without a repetition names one agent perfectly legally.
    const auto fixture = makeAuthReq("H {\"\\u0077azuh\":{\"agent\":{\"id\":\"1\"}}}"
                                     "\nE some event\n",
                                     "1");
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::None);
}

TEST(ValidatePayloadIdentity, MemberNameWithEmbeddedNulIsNotConfusedWithAnIdentityKey)
{
    // "wazuh\u0000x" is a 7-character name, distinct from the 5-character "wazuh". Comparing by length
    // keeps them apart; a C-string comparison would stop at the NUL, see two "wazuh" members and
    // reject a conforming header.
    const auto fixture = makeAuthReq("H {\"wazuh\":{\"agent\":{\"id\":\"1\"}},\"wazuh\\u0000x\":1}"
                                     "\nE some event\n",
                                     "1");
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::None);
}

TEST(ValidatePayloadIdentity, NonObjectIdentityContainerIsRejected)
{
    // Each step of the path must be an object before it can be searched for the next one.
    const auto scalarWazuh = makeAuthReq(R"(H {"wazuh":"nope"})"
                                         "\nE some event\n",
                                         "1");
    EXPECT_EQ(stateless::validatePayloadIdentity(*scalarWazuh.req), AuthError::PayloadAgentMismatch);

    const auto arrayAgent = makeAuthReq(R"(H {"wazuh":{"agent":[{"id":"1"}]}})"
                                        "\nE some event\n",
                                        "1");
    EXPECT_EQ(stateless::validatePayloadIdentity(*arrayAgent.req), AuthError::PayloadAgentMismatch);

    const auto arrayRoot = makeAuthReq(R"(H [{"wazuh":{"agent":{"id":"1"}}}])"
                                       "\nE some event\n",
                                       "1");
    EXPECT_EQ(stateless::validatePayloadIdentity(*arrayRoot.req), AuthError::PayloadAgentMismatch);
}

TEST(ValidatePayloadIdentity, KeyContainingASlashIsAcceptedAndLeftToTheEngine)
{
    // "wazuh/agent" is ONE literal member name, not a path. It used to be an injection vector,
    // because the engine pasted member names into a JSON Pointer unescaped and this one resolved
    // onto the real /wazuh/agent. That is fixed where the pointer is built (base/src/json.cpp), so
    // this endpoint has no reason to reject it: the identity it validates is unambiguous, and the
    // stray member is inert. Flipping this to a rejection means the split of responsibility moved.
    const auto fixture = makeAuthReq(R"(H {"wazuh":{"agent":{"id":"1"}},"wazuh/agent":{},"wazuh/agent":{"id":"2"}})"
                                     "\nE some event\n",
                                     "1");
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::None);
}

TEST(ValidatePayloadIdentity, RepeatedMemberOutsideTheIdentityPathIsAccepted)
{
    // "cluster" is repeated, the identity path is not. Nothing here validates wazuh.cluster.*
    // against an authoritative source, so a repetition there cannot move the identity and is not
    // this check's business -- keeping it out is what keeps the check proportional to the path.
    const auto fixture = makeAuthReq(R"(H {"wazuh":{"agent":{"id":"1"},"cluster":{"name":"a"},"cluster":{"name":"b"}}})"
                                     "\nE some event\n",
                                     "1");
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::None);
}

TEST(ValidatePayloadIdentity, DeeplyNestedMetadataOffTheIdentityPathIsAccepted)
{
    // ~3000 nested arrays hung off a member that is not on the identity path, under the 8 KiB
    // kMaxHeaderLineJsonSize cap. The identity lookup visits three objects and never descends this,
    // so depth costs nothing; the parse survives it because of kParseIterativeFlag.
    constexpr int kDepth = 3000;
    const std::string body = "H {\"wazuh\":{\"agent\":{\"id\":\"7\"}},\"x\":" + std::string(kDepth, '[') +
                             std::string(kDepth, ']') + "}\nE some event\n";
    ASSERT_LT(body.size(), 8U * 1024U);

    const auto fixture = makeAuthReq(body, "7");
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::None);
}

TEST(ValidatePayloadIdentity, FullConformingHeaderWithUniqueNamesSucceeds)
{
    // The complete documented H line, with the token carrying the same canonical id the header
    // stamps. The same key NAME in DIFFERENT objects ("name" under agent,
    // host.os and cluster) is legal and must not read as a repetition: the rule is per-object, and
    // only on the identity path.
    const auto fixture =
        makeAuthReq(R"(H {"wazuh":{"agent":{"id":"001","name":"web-server-01","version":"v5.0.0",)"
                    R"("groups":["web","production"],"host":{"architecture":"x86_64","hostname":"web-server-01",)"
                    R"("os":{"name":"Ubuntu","version":"22.04","platform":"ubuntu","type":"linux"}}},)"
                    R"("cluster":{"name":"production","node":"master-node"}}})"
                    "\nE 1:/var/log/syslog:hello\n",
                    "001");
    EXPECT_EQ(stateless::validatePayloadIdentity(*fixture.req), AuthError::None);
}

TEST(RapidJsonIterativeParse, SurvivesPathologicalNestingWithoutCrashing)
{
    // ~500 KB of unterminated nested arrays -- deliberately larger than statelessEndpoint's 8 KiB
    // H-line cap, so this exercises the iterative parser directly (kParseIterativeFlag), not the
    // size guard. Without the iterative flag, RapidJSON's default recursive-descent parse would
    // recurse once per '[' and can overflow the calling thread's stack on input like this.
    const std::string json(500'000, '[');

    rapidjson::Document doc;
    doc.Parse<rapidjson::kParseIterativeFlag>(json.data(), json.size());

    // The process survived (no stack overflow); the document is simply invalid (unterminated).
    EXPECT_TRUE(doc.HasParseError());
}

// --- makeHandler() ----------------------------------------------------------------------------

namespace
{
    // Records whether sendAsync() was called; never fires the callback (not needed by these tests --
    // they only assert whether the forwarder was reached at all).
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
    auto client = std::make_shared<FakeDownstreamClient>();
    auto limiter = std::make_shared<DeferredWorkLimiter>(4);
    DeferredForwarder forwarder {client, limiter, 1};

    auto handler = stateless::makeHandler(forwarder, "queue/sockets/engine-ingest-http.sock");
    auto fixture = makeAuthReq("H {\"wazuh\":{\"agent\":{\"id\":\"1002\"}}}\nE some event\n", "1001");
    auto responder = std::make_shared<CapturingResponder>();
    auto fut = responder->future();

    handler(fixture.req, responder);

    ASSERT_EQ(fut.wait_for(std::chrono::seconds {2}), std::future_status::ready);
    const auto response = fut.get();
    EXPECT_EQ(response.status, 400);
    EXPECT_EQ(response.body, R"({"error":"Invalid event batch","code":400})");
    EXPECT_FALSE(client->called()); // forward() must never run once validation fails
}

TEST(StatelessMakeHandler, RepeatedIdentityShortCircuitsBeforeForward)
{
    // End to end through the handler: a header whose FIRST /wazuh/agent/id is the authenticated
    // agent's own -- so it passed the identity comparison before the fix -- must now be refused
    // with the same neutral 400 as any other mismatch, and must never reach the forwarder. This is
    // the assertion that matters for the vulnerability: not the status code, but that the ambiguous
    // batch never crosses into the engine.
    auto client = std::make_shared<FakeDownstreamClient>();
    auto limiter = std::make_shared<DeferredWorkLimiter>(4);
    DeferredForwarder forwarder {client, limiter, 1};

    auto handler = stateless::makeHandler(forwarder, "queue/sockets/engine-ingest-http.sock");
    auto fixture = makeAuthReq(R"(H {"wazuh":{"agent":{"id":"1001"}},"wazuh":{"agent":{"id":"1002"}}})"
                               "\nE some event\n",
                               "1001");
    auto responder = std::make_shared<CapturingResponder>();
    auto fut = responder->future();

    handler(fixture.req, responder);

    ASSERT_EQ(fut.wait_for(std::chrono::seconds {2}), std::future_status::ready);
    const auto response = fut.get();
    EXPECT_EQ(response.status, 400);
    EXPECT_EQ(response.body, R"({"error":"Invalid event batch","code":400})");
    EXPECT_FALSE(client->called());
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

// With a metric set wired in, the handler's own pre-forward 400 (payload identity) and the
// forwarder-delivered 202 each land in the endpoint's responses family -- the family reads as
// "every response this endpoint sent", whichever code path sent it.
TEST(StatelessMakeHandler, MetricsCountBothTheLocal400AndTheDeliveredStatus)
{
    wazuh::metrics::Manager manager;
    const auto metrics = remoted::metrics::makeEndpointHttpMetrics(manager, "stateless", /*withLatency=*/true);

    auto client = std::make_shared<FakeDownstreamClient>();
    auto limiter = std::make_shared<DeferredWorkLimiter>(4);
    DeferredForwarder forwarder {client, limiter, 1};
    auto handler = stateless::makeHandler(forwarder, "queue/sockets/engine-ingest-http.sock", &metrics);

    // Payload identity mismatch: answered 400 by the handler itself, before any forward.
    {
        auto fixture = makeAuthReq("H {\"wazuh\":{\"agent\":{\"id\":\"1002\"}}}\nE some event\n", "1001");
        auto responder = std::make_shared<CapturingResponder>();
        auto fut = responder->future();
        handler(fixture.req, responder);
        ASSERT_EQ(fut.wait_for(std::chrono::seconds {2}), std::future_status::ready);
        EXPECT_EQ(fut.get().status, 400);
    }
    EXPECT_EQ(metrics.responses.c400->get(), 1U);
    EXPECT_FALSE(client->called());

    // Valid request: the forwarder counts the delivered 202 through the target's metric pointer.
    {
        auto fixture = makeAuthReq("H {\"wazuh\":{\"agent\":{\"id\":\"1001\"}}}\nE some event\n", "1001");
        auto responder = std::make_shared<CapturingResponder>();
        auto fut = responder->future();
        handler(fixture.req, responder);
        ASSERT_TRUE(client->called());
        client->fire(DownstreamError::None, DownstreamResponse {200, ""});
        ASSERT_EQ(fut.wait_for(std::chrono::seconds {2}), std::future_status::ready);
        EXPECT_EQ(fut.get().status, 202);
    }
    EXPECT_EQ(metrics.responses.c2xx->get(), 1U);
    EXPECT_EQ(metrics.responses.c400->get(), 1U); // untouched by the success
}
