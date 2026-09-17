/*
 * Wazuh remoted module - POST /enroll/secret endpoint unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * September 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Exercises the handler of `POST /enroll/secret` with a real AuthdClient wired to FakeUdsServer
 * instances standing in for authd. Authentication itself is NOT re-tested here -- the route is
 * registered through AuthGateway, so the middleware has already run by the time this handler is
 * called and its own matrix lives in authMiddleware_test.cpp; what these cases pin is the request
 * the handler SENDS (its id comes from the verified identity, never from the body) and the status
 * each authd answer maps to. The rate limit is the gateway's (authGateway_test.cpp), not the
 * handler's: it refuses before this code ever runs.
 */

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "endpoints/reenrollSecretEndpoint.hpp"
#include "fakeUdsServer.hpp"
#include "json.hpp"

#include <wazuh_metrics/manager.hpp>

using remoted::enrollment::AuthdClient;
using remoted::enrollment::makeReenrollSecretMetrics;
using remoted::enrollment::ReenrollSecretMetrics;
using remoted::http::HttpResponse;
using remoted::http::IHttpResponder;
using remoted::test::FakeUdsServer;
using remoted::test::makeUniqueSocketPath;
using namespace std::chrono_literals;

namespace
{
    constexpr auto kSecret {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"};

    class CapturingResponder : public IHttpResponder
    {
    public:
        void send(HttpResponse response) override
        {
            std::lock_guard<std::mutex> lock(m_mu);
            if (m_done)
            {
                return;
            }
            m_response = std::move(response);
            m_done = true;
            m_cv.notify_all();
        }

        HttpResponse wait(std::chrono::milliseconds timeout = 2s)
        {
            std::unique_lock<std::mutex> lock(m_mu);
            EXPECT_TRUE(m_cv.wait_for(lock, timeout, [&] { return m_done; })) << "responder never called";
            return m_response;
        }

    private:
        std::mutex m_mu;
        std::condition_variable m_cv;
        bool m_done {false};
        HttpResponse m_response;
    };

    /// The fingerprint AuthMiddleware would have attached: SHA-256 of the key that verified the
    /// bearer. Its VALUE is opaque to this layer -- the endpoint forwards it and authd judges it --
    /// so the tests only care that this exact string arrives at authd unchanged.
    constexpr auto kKeyFingerprint {"3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea"};

    // What AuthGateway hands the handler: an already-verified identity. The body is deliberately
    // free-form in these tests, because the handler must never read it.
    std::shared_ptr<const remoted::auth::AuthenticatedRequest> verifiedRequest(const std::string& agentId,
                                                                               const std::string& body = "{}")
    {
        remoted::auth::AuthenticatedRequest request;
        request.agentId = agentId;
        request.keyFingerprint = kKeyFingerprint;
        request.protocolVersion = "1";
        request.method = "POST";
        request.requestTarget = "/enroll/secret";
        request.receivedAt = std::chrono::steady_clock::now();
        // A real keep-alive, not a null one: the body must genuinely be READABLE here, or "the
        // handler does not read it" would be a property of the fixture rather than of the code.
        auto owned = std::make_shared<const std::string>(body);
        request.payload = remoted::auth::Payload {std::string_view {*owned}, owned};
        return std::make_shared<const remoted::auth::AuthenticatedRequest>(std::move(request));
    }

    // What the responder callback writes and the test reads. Its own object, owned jointly by the
    // stub and the callback, for the reason AuthdStub below does NOT own it: the callback outlives
    // nothing and owns nothing else, so releasing the stub is enough to stop and destroy the server.
    struct RequestRecord
    {
        std::mutex mutex;
        std::string lastRequest;
    };

    // An authd stand-in that records the request it was sent and answers a fixed response.
    //
    // The server is destroyed (and therefore stopped and joined) by ~AuthdStub, which runs when the
    // last caller reference goes away. That only holds because the responder captures `record` and
    // NOT the stub: a callback holding a shared_ptr to its own owner is a cycle, and the socket,
    // the accept thread and every retained connection thread would then survive the case that
    // created them -- accumulating across the 100+ tests that share this process.
    struct AuthdStub
    {
        std::string path;
        std::shared_ptr<RequestRecord> record {std::make_shared<RequestRecord>()};
        std::unique_ptr<FakeUdsServer> server;

        std::string request()
        {
            std::lock_guard<std::mutex> lock(record->mutex);
            return record->lastRequest;
        }
    };

    std::shared_ptr<AuthdStub> authdAnswering(const std::string& response)
    {
        auto stub = std::make_shared<AuthdStub>();
        stub->path = makeUniqueSocketPath("reenroll_secret_endpoint");
        stub->server = std::make_unique<FakeUdsServer>(stub->path,
                                                       [record = stub->record, response](const std::string& request)
                                                       {
                                                           std::lock_guard<std::mutex> lock(record->mutex);
                                                           record->lastRequest = request;
                                                           return response;
                                                       });
        return stub;
    }

    struct Fixture
    {
        wazuh::metrics::Manager manager;
        ReenrollSecretMetrics metrics {makeReenrollSecretMetrics(manager)};
        remoted::metrics::EndpointHttpMetrics http {remoted::metrics::makeEndpointHttpMetrics(
            manager, "enroll.secret", /*withLatency=*/false, "POST", "/enroll/secret")};

        // A fresh AuthdClient per dispatch: its worker threads must not be shared across cases.
        // `authdPath` need not have a server bound at all -- that is how "authd unreachable" is
        // expressed.
        HttpResponse
        dispatch(const std::string& authdPath, const std::string& agentId = "001", const std::string& body = "{}")
        {
            AuthdClient client(authdPath,
                               /*isWorkerNode=*/false,
                               /*connectTimeoutMs=*/0,
                               /*responseTimeoutMs=*/500,
                               /*maxQueueSize=*/0);
            auto handler = remoted::endpoints::reenrollsecret::makeHandler(client, metrics, http);
            auto responder = std::make_shared<CapturingResponder>();
            handler(verifiedRequest(agentId, body), responder);
            return responder->wait();
        }
    };

    nlohmann::json parseBody(const HttpResponse& response)
    {
        return nlohmann::json::parse(response.body, nullptr, false);
    }

    std::string successResponse(const std::string& id, const std::string& secret)
    {
        nlohmann::json data;
        data["id"] = id;
        data["reenroll_secret"] = secret;
        nlohmann::json response;
        response["error"] = 0;
        response["data"] = std::move(data);
        return response.dump();
    }

    std::string errorResponse(int code, const std::string& message)
    {
        nlohmann::json response;
        response["error"] = code;
        response["message"] = message;
        return response.dump();
    }
} // namespace

TEST(ReenrollSecretEndpointTest, IssuesTheSecretForTheVerifiedIdentity)
{
    auto authd = authdAnswering(successResponse("001", kSecret));
    Fixture f;

    const auto response = f.dispatch(authd->path, "001");

    EXPECT_EQ(response.status, 200);
    const auto body = parseBody(response);
    EXPECT_EQ(body["id"], "001");
    EXPECT_EQ(body["reenroll_secret"], kSecret);
    // The answer carries the credential and the id, and nothing else: no key -- this operation does
    // not rotate one, and saying otherwise would be a lie the agent might act on.
    EXPECT_FALSE(body.contains("key"));
    EXPECT_EQ(f.metrics.issued->get(), 1U);
    EXPECT_EQ(f.http.responses.c2xx->get(), 1U);
}

TEST(ReenrollSecretEndpointTest, TheIdSentToAuthdIsTheVerifiedOneNeverTheBody)
{
    // THE property of this route (RNF-1): there is no id field in the request, so no request shape
    // exists in which one agent asks about another. A body that tries anyway is simply not read.
    auto authd = authdAnswering(successResponse("007", kSecret));
    Fixture f;

    const auto response = f.dispatch(authd->path, "007", R"({"id":"001","agent_id":"001"})");
    ASSERT_EQ(response.status, 200);

    const auto sent = nlohmann::json::parse(authd->request(), nullptr, false);
    ASSERT_FALSE(sent.is_discarded());
    EXPECT_EQ(sent["function"], "issue_reenroll_secret");
    EXPECT_EQ(sent["arguments"]["id"], "007");
    // Nothing else travels: no credential, no name, no ip. authd reads those from its own keystore.
    // The one companion is the fingerprint of the key that authenticated -- see the test below.
    EXPECT_EQ(sent["arguments"].size(), 2U);
}

TEST(ReenrollSecretEndpointTest, TheAuthenticatedKeysFingerprintTravelsToAuthd)
{
    // #39315 F1. The id alone says WHO asked; it does not say WITH WHICH KEY, and on a worker whose
    // client.keys replica lags the master those are different statements: a key the master has
    // already rotated away from still authenticates here. authd is the only node that can tell,
    // so what it needs must reach it -- unchanged, and from the verified request rather than from
    // anything the caller sent.
    auto authd = authdAnswering(successResponse("001", kSecret));
    Fixture f;

    ASSERT_EQ(f.dispatch(authd->path).status, 200);

    const auto sent = nlohmann::json::parse(authd->request(), nullptr, false);
    ASSERT_FALSE(sent.is_discarded());
    EXPECT_EQ(sent["arguments"]["key_fingerprint"], kKeyFingerprint);
}

TEST(ReenrollSecretEndpointTest, AKeyThatIsNoLongerCurrentIs401)
{
    // 9032: authd compared the fingerprint with its own entry and they differ, so the caller proved
    // possession of a key this agent no longer has. Same 401 envelope as 9026 on purpose -- from
    // the agent's side both mean "the credential you presented is not current" -- and deliberately
    // not a distinct public code, which would tell a caller it is talking to a stale replica.
    auto authd = authdAnswering(errorResponse(9032, "Agent key changed since the request was authenticated"));
    Fixture f;

    const auto response = f.dispatch(authd->path);

    EXPECT_EQ(response.status, 401);
    // `code`, not `error`: in this envelope `error` is the human-readable message (which is
    // deliberately the same generic string for every credential failure) and `code` is the class.
    // Asserting on the message would pass for any 401 at all.
    EXPECT_EQ(parseBody(response)["code"], "unknown_agent");
    // Nothing was issued, and the in-progress counter is untouched: this is not a rotation racing
    // another one, it is a request that must never have been answered at all.
    EXPECT_EQ(f.metrics.issued->get(), 0U);
    EXPECT_EQ(f.metrics.rejectedInProgress->get(), 0U);
    // `other`, not a `401` cell: ResponseCounters is a closed set (2xx/400/403/409/413/429/500/503)
    // built when every 401 came from the AuthGateway, before any handler ran, and so belonged to
    // remoted.auth.reject.* alone. This route breaks that assumption -- it maps authd's 9026/9032
    // to a 401 from INSIDE the handler, through the MeteredResponder -- so the status is counted,
    // and it lands in the catch-all. The WHY is not lost: it is in remoted.enroll.secret.authd_error
    // and remoted.auth.reject.unknown_agent.
    EXPECT_EQ(f.http.responses.other->get(), 1U);
}

TEST(ReenrollSecretEndpointTest, AuthdRotationInFlightIs409)
{
    // 9030: a rotation for that agent is already accepted and not yet persisted. Not an
    // authentication failure -- the agent has to wait, not re-sign -- so 409, like the duplicate
    // states on /enroll.
    auto authd = authdAnswering(errorResponse(9030, "Re-enrollment already in progress"));
    Fixture f;

    const auto response = f.dispatch(authd->path);

    EXPECT_EQ(response.status, 409);
    EXPECT_EQ(parseBody(response)["error"], "reenroll_in_progress");
    EXPECT_EQ(f.metrics.rejectedInProgress->get(), 1U);
    EXPECT_EQ(f.metrics.authdError->get(), 0U);
    EXPECT_EQ(f.http.responses.c409->get(), 1U);
}

TEST(ReenrollSecretEndpointTest, UnknownAgentIs401InTheSharedAuthEnvelope)
{
    // 9026 folds "no such agent" and "no row in global.db yet" together. Both mean the identity the
    // bearer proved is not one authd can act on, which is an authentication outcome -- so it takes
    // the same 401, the same envelope and the same challenge the gateway itself would have produced
    // had client.keys lost the agent one moment earlier.
    auto authd = authdAnswering(errorResponse(9026, "Unknown agent or no re-enrollment credential"));
    Fixture f;

    const auto response = f.dispatch(authd->path);

    EXPECT_EQ(response.status, 401);
    EXPECT_EQ(parseBody(response)["code"], "unknown_agent");
    EXPECT_EQ(f.metrics.authdError->get(), 1U);
    EXPECT_EQ(f.metrics.issued->get(), 0U);

    bool challenged = false;
    for (const auto& [name, value] : response.headers)
    {
        if (name == "WWW-Authenticate")
        {
            challenged = true;
        }
    }
    EXPECT_TRUE(challenged);
}

TEST(ReenrollSecretEndpointTest, AnUnrecordableTransitionIs503)
{
    // 9031: authd could not journal the credential it was about to hand out, so it handed out none.
    // Nothing is wrong with the request -- this manager cannot record it right now.
    auto authd = authdAnswering(errorResponse(9031, "Identity transition could not be recorded"));
    Fixture f;

    const auto response = f.dispatch(authd->path);

    EXPECT_EQ(response.status, 503);
    EXPECT_EQ(parseBody(response)["error"], "identity_unrecorded");
    EXPECT_EQ(f.metrics.authdError->get(), 1U);
    EXPECT_EQ(f.http.responses.c503->get(), 1U);
}

TEST(ReenrollSecretEndpointTest, AFailedClusterForwardIs503)
{
    // 9016: the worker could not reach the master, which owns the row. Retryable, same as above.
    auto authd = authdAnswering(errorResponse(9016, "Cannot communicate with master node"));
    Fixture f;

    const auto response = f.dispatch(authd->path);

    EXPECT_EQ(response.status, 503);
    EXPECT_EQ(parseBody(response)["error"], "master_unreachable");
    EXPECT_EQ(f.metrics.authdError->get(), 1U);
}

TEST(ReenrollSecretEndpointTest, AnUnreachableAuthdIs503)
{
    // No server bound at all: the bridge gets no clean answer (errorCode -1), which is the same
    // condition a FULL AuthdClient queue produces -- both are "retry", neither is the agent's fault.
    Fixture f;

    const auto response = f.dispatch(makeUniqueSocketPath("reenroll_secret_absent"));

    EXPECT_EQ(response.status, 503);
    EXPECT_EQ(parseBody(response)["error"], "authd_unavailable");
    EXPECT_EQ(f.metrics.authdUnavailable->get(), 1U);
    EXPECT_EQ(f.metrics.authdError->get(), 0U);
}

TEST(ReenrollSecretEndpointTest, AFullQueueIs503WithoutTouchingAuthd)
{
    // The queue-full path explicitly: a client with capacity 1 and a hung authd. The second request
    // is refused by the client itself with errorCode -1 and must map to the same 503 -- if it ever
    // mapped to a 200 or a 4xx, a saturated manager would look like a broken agent.
    auto stub = std::make_shared<AuthdStub>();
    stub->path = makeUniqueSocketPath("reenroll_secret_hung");
    stub->server = std::make_unique<FakeUdsServer>(stub->path,
                                                   [](const std::string&)
                                                   {
                                                       std::this_thread::sleep_for(800ms);
                                                       return std::string {};
                                                   });

    Fixture f;
    AuthdClient client(stub->path,
                       /*isWorkerNode=*/false,
                       /*connectTimeoutMs=*/0,
                       /*responseTimeoutMs=*/300,
                       /*maxQueueSize=*/1,
                       /*workerThreads=*/1);
    auto handler = remoted::endpoints::reenrollsecret::makeHandler(client, f.metrics, f.http);

    // Fill the single worker and the single queue slot, then add one more.
    std::vector<std::shared_ptr<CapturingResponder>> responders;
    for (int i = 0; i < 4; ++i)
    {
        auto responder = std::make_shared<CapturingResponder>();
        responders.push_back(responder);
        handler(verifiedRequest("001"), responder);
    }

    bool sawUnavailable = false;
    for (const auto& responder : responders)
    {
        const auto response = responder->wait(3s);
        EXPECT_EQ(response.status, 503);
        if (parseBody(response)["error"] == "authd_unavailable")
        {
            sawUnavailable = true;
        }
    }
    EXPECT_TRUE(sawUnavailable);
    EXPECT_GT(f.metrics.authdUnavailable->get(), 0U);
}

TEST(ReenrollSecretEndpointTest, ASuccessWithoutASecretIsTreatedAsNoCleanAnswer)
{
    // This verb exists only to produce a secret, so there is no "an older authd sent none" case to
    // tolerate (unlike /enroll, where the field is genuinely optional). Answering 200 with nothing
    // would have the agent store an empty credential and believe it is recovered.
    auto authd = authdAnswering(R"({"error":0,"data":{"id":"001"}})");
    Fixture f;

    const auto response = f.dispatch(authd->path);

    EXPECT_EQ(response.status, 503);
    EXPECT_EQ(parseBody(response)["error"], "authd_unavailable");
    EXPECT_EQ(f.metrics.issued->get(), 0U);
    EXPECT_EQ(f.metrics.authdUnavailable->get(), 1U);
}

TEST(ReenrollSecretEndpointTest, AnUnexpectedAuthdCodeIs500)
{
    // Anything outside the mapped set means the two sides disagree about this verb, which is the
    // manager's fault and not the agent's -- a 500, not a retryable 503 the agent would keep asking
    // against for ever.
    auto authd = authdAnswering(errorResponse(9001, "Internal error"));
    Fixture f;

    const auto response = f.dispatch(authd->path);

    EXPECT_EQ(response.status, 500);
    EXPECT_EQ(parseBody(response)["error"], "authd_error");
    EXPECT_EQ(f.metrics.authdError->get(), 1U);
}

TEST(ReenrollSecretEndpointTest, TheRateLimitedBodyIsTheRoutesOwnFlatEnvelope)
{
    // Sent by the gateway's gate, but owned here: sharing /enroll's bucket is not sharing its
    // nested numeric envelope. Retry-After is the gate's to add, so it is not in this body.
    const auto response = remoted::endpoints::reenrollsecret::rateLimitedResponse();

    EXPECT_EQ(response.status, 429);
    EXPECT_EQ(response.body, R"({"error":"rate_limited"})");
}
