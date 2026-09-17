/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 21, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "decoding/bodyDecoder.hpp"
#include "endpoints/authGateway.hpp"
#include "fakeHttpServer.hpp"
#include "http_server/IHttpServer.hpp"
#include "jwt/canonicalAgentId.hpp"
#include "jwt/jwtRequestTokenSigner.hpp"
#include "jwt/secureBytes.hpp"
#include "zstdTestHelper.hpp"

#include <gtest/gtest.h>

#include <wazuh_metrics/manager.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

using namespace remoted::http;
using namespace remoted::endpoints;
using namespace remoted::decoding;

namespace
{
    using remoted::testutil::FakeHttpServer;

    // Keystore stub: knows one agent (numeric id 1, i.e. "001" on the wire); anything else is unknown.
    class FakeKeystore final : public remoted::auth::IAgentKeystore
    {
    public:
        // Registered as `any`: the known agent may connect from any address.
        std::optional<remoted::auth::AgentLookup> lookup(remoted::auth::AgentId agentId,
                                                         std::string_view) const override
        {
            if (agentId == 1)
            {
                return remoted::auth::AgentLookup {std::vector<std::uint8_t>(32, 0x0A), true};
            }
            return std::nullopt;
        }
    };

    // Keystore stub that always throws, simulating an unexpected failure (e.g. a corrupted on-disk
    // state) reached from INSIDE AuthMiddleware::authenticate() -- i.e. before the gateway's old,
    // too-narrow try/catch used to start.
    class ThrowingKeystore final : public remoted::auth::IAgentKeystore
    {
    public:
        std::optional<remoted::auth::AgentLookup> lookup(remoted::auth::AgentId, std::string_view) const override
        {
            throw std::runtime_error("simulated keystore I/O failure");
        }
    };

    class CapturingResponder final : public IHttpResponder
    {
    public:
        void send(HttpResponse response) override
        {
            if (!captured.has_value())
            {
                captured = std::move(response);
            }
        }
        std::optional<HttpResponse> captured;
    };

    // IBodyDecoder stub backed by a lambda, so each test states just the behavior it cares about
    // without declaring its own class. The gateway's contract is "run the step, map its result", so
    // these deliberately never compress anything -- the real decoder is tested in bodyDecoder_test.
    class StubBodyDecoder final : public IBodyDecoder
    {
    public:
        using Fn = std::function<remoted::auth::AuthError(ContentEncoding, remoted::auth::Payload&)>;

        explicit StubBodyDecoder(Fn fn)
            : m_fn {std::move(fn)}
        {
        }

        remoted::auth::AuthError decode(ContentEncoding encoding, remoted::auth::Payload& payload) const override
        {
            return m_fn(encoding, payload);
        }

    private:
        Fn m_fn;
    };

    std::shared_ptr<const IBodyDecoder> stubDecoder(StubBodyDecoder::Fn fn)
    {
        return std::make_shared<const StubBodyDecoder>(std::move(fn));
    }

    // For the tests that are about authentication itself: accepts whatever it is handed and leaves
    // the body alone, so the decoding step is present (it is a required dependency) but inert.
    std::shared_ptr<const IBodyDecoder> passthroughDecoder()
    {
        return stubDecoder([](ContentEncoding, remoted::auth::Payload&) { return remoted::auth::AuthError::None; });
    }

    AuthGateway makeGateway()
    {
        return AuthGateway {remoted::auth::AuthConfig {}, std::make_shared<FakeKeystore>(), passthroughDecoder()};
    }

    // A valid `Bearer <wazuh-agent+jwt>` Authorization for agent 001, minted with the key
    // FakeKeystore returns for it (a fresh token per call).
    std::string buildAuthorization()
    {
        const std::vector<std::uint8_t> key(32, 0x0A); // matches FakeKeystore::lookup(1) ("001" on the wire)
        const jwt_profile::v1::SecureBytes secret {key.data(), key.size()};
        const auto token = jwt_profile::v1::JwtRequestTokenSigner::sign(
            *jwt_profile::v1::CanonicalAgentId::parse("001"), secret, std::chrono::system_clock::now());
        return "Bearer " + (token ? *token : std::string {});
    }

    // A request that authenticates cleanly for agent 001 against makeGateway(). The token is
    // identity-only, so any body/target authenticates the same way.
    HttpRequest signedRequest(const std::string& body)
    {
        HttpRequest request;
        request.method = Method::Post;
        request.target = "/stateless";
        request.body = body;
        request.headers.emplace("protocol-version", "1");
        request.headers.emplace("authorization", buildAuthorization());
        return request;
    }

    // Same as signedRequest(), plus a Content-Encoding header. `body` is whatever the caller wants
    // on the wire, compressed or not -- authentication does not look at it.
    HttpRequest signedRequestWithContentEncoding(const std::string& body, const std::string& encoding)
    {
        auto request = signedRequest(body);
        request.headers.emplace("content-encoding", encoding);
        return request;
    }
} // namespace

TEST(AuthGatewayTest, RegistersRouteOnTheServer)
{
    FakeHttpServer server;
    auto gateway = makeGateway();

    gateway.addAuthenticatedRoute(
        server,
        Method::Post,
        "/stateless",
        [](std::shared_ptr<const remoted::auth::AuthenticatedRequest>, std::shared_ptr<IHttpResponder> responder)
        { responder->send(HttpResponse {200, "", {}}); });

    EXPECT_TRUE(server.hasRoute(Method::Post, "/stateless"));
}

TEST(AuthGatewayTest, ForwardsTheResponseModeToTheServer)
{
    // The mode cannot be chosen per response -- the transport fixes a builder's output mode when the
    // request is dispatched -- so a streaming endpoint depends on the gateway passing it through at
    // registration. A Buffered registration would make every /download answer 500.
    FakeHttpServer server;
    auto gateway = makeGateway();

    gateway.addAuthenticatedRoute(server, Method::Post, "/buffered", [](auto, auto) {});
    gateway.addAuthenticatedRoute(server, Method::Post, "/streamed", [](auto, auto) {}, ResponseMode::Streamable);

    EXPECT_EQ(server.modeOf(Method::Post, "/buffered"), ResponseMode::Buffered) << "default must stay buffered";
    EXPECT_EQ(server.modeOf(Method::Post, "/streamed"), ResponseMode::Streamable);
}

TEST(AuthGatewayTest, MissingProtocolVersionYields400AndSkipsHandler)
{
    FakeHttpServer server;
    auto gateway = makeGateway();

    bool handlerCalled = false;
    gateway.addAuthenticatedRoute(server,
                                  Method::Post,
                                  "/stateless",
                                  [&handlerCalled](std::shared_ptr<const remoted::auth::AuthenticatedRequest>,
                                                   std::shared_ptr<IHttpResponder> responder)
                                  {
                                      handlerCalled = true;
                                      responder->send(HttpResponse {200, "", {}});
                                  });

    HttpRequest request;
    request.method = Method::Post;
    request.target = "/stateless";
    // No protocol-version, no authorization.

    auto responder = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/stateless", request, responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(responder->captured->status, 400);
    EXPECT_FALSE(handlerCalled);
}

TEST(AuthGatewayTest, MissingAuthorizationYields401AndSkipsHandler)
{
    FakeHttpServer server;
    auto gateway = makeGateway();

    bool handlerCalled = false;
    gateway.addAuthenticatedRoute(server,
                                  Method::Post,
                                  "/stateless",
                                  [&handlerCalled](std::shared_ptr<const remoted::auth::AuthenticatedRequest>,
                                                   std::shared_ptr<IHttpResponder> responder)
                                  {
                                      handlerCalled = true;
                                      responder->send(HttpResponse {200, "", {}});
                                  });

    HttpRequest request;
    request.method = Method::Post;
    request.target = "/stateless";
    request.headers.emplace("protocol-version", "1"); // present, but no Authorization

    auto responder = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/stateless", request, responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(responder->captured->status, 401);
    EXPECT_FALSE(handlerCalled);
}

TEST(AuthGatewayTest, HeaderLookupIsCaseInsensitive)
{
    FakeHttpServer server;
    auto gateway = makeGateway();

    gateway.addAuthenticatedRoute(
        server,
        Method::Post,
        "/stateless",
        [](std::shared_ptr<const remoted::auth::AuthenticatedRequest>, std::shared_ptr<IHttpResponder> responder)
        { responder->send(HttpResponse {200, "", {}}); });

    HttpRequest request;
    request.method = Method::Post;
    request.target = "/stateless";
    // Mixed-case header name must still be found (so we reach the 401 auth path, not 400).
    request.headers.emplace("Protocol-Version", "1");

    auto responder = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/stateless", request, responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(responder->captured->status, 401); // missing Authorization, not missing protocol-version
}

TEST(AuthGatewayTest, ValidAuthReachesHandlerWithVerifiedRequest)
{
    FakeHttpServer server;
    auto gateway = makeGateway();

    std::string seenAgentId;
    std::string seenBody;
    std::chrono::steady_clock::time_point seenReceivedAt {};
    gateway.addAuthenticatedRoute(
        server,
        Method::Post,
        "/stateless",
        [&seenAgentId, &seenBody, &seenReceivedAt](std::shared_ptr<const remoted::auth::AuthenticatedRequest> authReq,
                                                   std::shared_ptr<IHttpResponder> responder)
        {
            seenAgentId = authReq->agentId;
            seenBody = std::string {authReq->payload.bytes()}; // zero-copy view of the verified body
            seenReceivedAt = authReq->receivedAt;
            responder->send(HttpResponse::json(200, R"({"ok":true})"));
        });

    const auto before = std::chrono::steady_clock::now();
    const auto request = signedRequest("some-body");
    auto responder = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/stateless", request, responder);
    const auto after = std::chrono::steady_clock::now();

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(responder->captured->status, 200);
    EXPECT_EQ(seenAgentId, "001");    // the handler received the authenticated identity
    EXPECT_EQ(seenBody, "some-body"); // ... and a valid view of the payload
    // ... stamped with a receipt time from within the dispatch window (the origin of the
    // remoted.http.<endpoint>.latency measurement), not the "never stamped" epoch default.
    EXPECT_GE(seenReceivedAt, before);
    EXPECT_LE(seenReceivedAt, after);
}

TEST(AuthGatewayTest, PayloadOutlivesDispatchAndReleaseKeepsMetadata)
{
    FakeHttpServer server;
    auto gateway = makeGateway();

    // Handler defers: it retains the authenticated request past the dispatch call.
    std::shared_ptr<const remoted::auth::AuthenticatedRequest> held;
    gateway.addAuthenticatedRoute(server,
                                  Method::Post,
                                  "/stateless",
                                  [&held](std::shared_ptr<const remoted::auth::AuthenticatedRequest> authReq,
                                          std::shared_ptr<IHttpResponder> responder)
                                  {
                                      held = std::move(authReq);
                                      responder->send(HttpResponse::json(200, "{}"));
                                  });

    {
        // The gateway keeps its OWN shared_ptr to the request alive via the payload
        // keep-alive, independent of this local HttpRequest value.
        const auto request = signedRequest("payload-bytes");
        auto responder = std::make_shared<CapturingResponder>();
        server.dispatch(Method::Post, "/stateless", request, responder);
    }

    ASSERT_NE(held, nullptr);
    EXPECT_EQ(held->payload.bytes(), "payload-bytes"); // still valid after dispatch returned

    held->payload.release();            // explicit early release
    EXPECT_TRUE(held->payload.empty()); // payload gone
    EXPECT_EQ(held->agentId, "001");    // ... but the small metadata survives release
}

TEST(AuthGatewayTest, HandlerExceptionYields500)
{
    FakeHttpServer server;
    auto gateway = makeGateway();

    bool handlerCalled = false;
    gateway.addAuthenticatedRoute(
        server,
        Method::Post,
        "/stateless",
        [&handlerCalled](std::shared_ptr<const remoted::auth::AuthenticatedRequest>, std::shared_ptr<IHttpResponder>)
        {
            handlerCalled = true;
            throw std::runtime_error("boom"); // handler fails after auth succeeded
        });

    const auto request = signedRequest("some-body");
    auto responder = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/stateless", request, responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_TRUE(handlerCalled);                  // auth passed, the handler ran
    EXPECT_EQ(responder->captured->status, 500); // ... then the gateway caught the throw
}

TEST(AuthGatewayTest, KeystoreThrowDuringAuthYields500)
{
    FakeHttpServer server;
    AuthGateway gateway {remoted::auth::AuthConfig {}, std::make_shared<ThrowingKeystore>(), passthroughDecoder()};

    bool handlerCalled = false;
    gateway.addAuthenticatedRoute(server,
                                  Method::Post,
                                  "/stateless",
                                  [&handlerCalled](std::shared_ptr<const remoted::auth::AuthenticatedRequest>,
                                                   std::shared_ptr<IHttpResponder>) { handlerCalled = true; });

    // lookup() is called from inside beginSession() -- exactly the code that used to run outside
    // the gateway's try/catch. This must not escape dispatch() (in production, it would otherwise
    // std::terminate() the whole process on the worker-pool thread).
    const auto request = signedRequest("some-body");
    auto responder = std::make_shared<CapturingResponder>();
    EXPECT_NO_THROW(server.dispatch(Method::Post, "/stateless", request, responder));

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(responder->captured->status, 500);
    EXPECT_FALSE(handlerCalled); // the throw happened during auth, before the handler ever ran
}

// ---------------------------------------------------------------------------
// Body decoding: the gateway's contract with an injected BodyDecoder
//
// These use a STUB decoder on purpose. The gateway's job is to run the step and map its result --
// it must not know what any encoding means, so nothing here compresses anything. The real zstd
// decoder has its own tests (bodyDecoder_test.cpp); the integration of the two is covered further
// below.
// ---------------------------------------------------------------------------

TEST(AuthGatewayTest, DecoderSeesTheParsedEncodingAndTheVerifiedBody)
{
    FakeHttpServer server;
    auto seenEncoding = ContentEncoding::Unsupported; // anything but what we expect
    std::string seenBytes;
    AuthGateway gateway {remoted::auth::AuthConfig {},
                         std::make_shared<FakeKeystore>(),
                         stubDecoder(
                             [&seenEncoding, &seenBytes](ContentEncoding encoding, remoted::auth::Payload& payload)
                             {
                                 seenEncoding = encoding;
                                 seenBytes = std::string {payload.bytes()};
                                 return remoted::auth::AuthError::None;
                             })};

    gateway.addAuthenticatedRoute(
        server,
        Method::Post,
        "/stateless",
        [](std::shared_ptr<const remoted::auth::AuthenticatedRequest>, std::shared_ptr<IHttpResponder> responder)
        { responder->send(HttpResponse::json(200, "{}")); });

    const auto request = signedRequestWithContentEncoding("the-wire-bytes", "zstd");
    auto responder = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/stateless", request, responder);

    // The gateway parses the header and hands over the enum, not the raw string.
    EXPECT_EQ(seenEncoding, ContentEncoding::Zstd);
    EXPECT_EQ(seenBytes, "the-wire-bytes"); // the exact wire bytes, untouched by authentication
}

TEST(AuthGatewayTest, DecoderIsStillRunWithNoEncodingSoItOwnsThePassthrough)
{
    // The gateway does not decide whether decoding applies -- it always defers to the decoder, which
    // is what lets "no Content-Encoding means passthrough" be the decoder's rule rather than a
    // second copy of that logic here.
    FakeHttpServer server;
    bool called = false;
    auto seenEncoding = ContentEncoding::Unsupported;
    AuthGateway gateway {remoted::auth::AuthConfig {},
                         std::make_shared<FakeKeystore>(),
                         stubDecoder(
                             [&called, &seenEncoding](ContentEncoding encoding, remoted::auth::Payload&)
                             {
                                 called = true;
                                 seenEncoding = encoding;
                                 return remoted::auth::AuthError::None;
                             })};

    gateway.addAuthenticatedRoute(
        server,
        Method::Post,
        "/stateless",
        [](std::shared_ptr<const remoted::auth::AuthenticatedRequest>, std::shared_ptr<IHttpResponder> responder)
        { responder->send(HttpResponse::json(200, "{}")); });

    const auto request = signedRequest("plain body"); // no Content-Encoding header at all
    auto responder = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/stateless", request, responder);

    EXPECT_TRUE(called);
    EXPECT_EQ(seenEncoding, ContentEncoding::None);
}

TEST(AuthGatewayTest, DecodedPayloadIsWhatTheHandlerReceives)
{
    FakeHttpServer server;
    auto replacement = std::make_shared<std::string>("decoded body");
    AuthGateway gateway {remoted::auth::AuthConfig {},
                         std::make_shared<FakeKeystore>(),
                         stubDecoder(
                             [replacement](ContentEncoding, remoted::auth::Payload& payload)
                             {
                                 payload = remoted::auth::Payload {*replacement, replacement};
                                 return remoted::auth::AuthError::None;
                             })};

    std::string seenBody;
    gateway.addAuthenticatedRoute(server,
                                  Method::Post,
                                  "/stateless",
                                  [&seenBody](std::shared_ptr<const remoted::auth::AuthenticatedRequest> authReq,
                                              std::shared_ptr<IHttpResponder> responder)
                                  {
                                      seenBody = std::string {authReq->payload.bytes()};
                                      responder->send(HttpResponse::json(200, "{}"));
                                  });

    const auto request = signedRequestWithContentEncoding("wire bytes", "some-encoding");
    auto responder = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/stateless", request, responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(responder->captured->status, 200);
    EXPECT_EQ(seenBody, "decoded body"); // not the wire bytes
}

// Each AuthError a decoder can return must reach the client as that error's own status, unchanged.
class AuthGatewayDecoderErrorTest : public ::testing::TestWithParam<std::pair<remoted::auth::AuthError, int>>
{
};

TEST_P(AuthGatewayDecoderErrorTest, DecoderErrorIsAnsweredAndTheHandlerIsSkipped)
{
    const auto [decoderError, expectedStatus] = GetParam();

    FakeHttpServer server;
    AuthGateway gateway {
        remoted::auth::AuthConfig {},
        std::make_shared<FakeKeystore>(),
        stubDecoder([decoderError = decoderError](ContentEncoding, remoted::auth::Payload&) { return decoderError; })};

    bool handlerCalled = false;
    gateway.addAuthenticatedRoute(server,
                                  Method::Post,
                                  "/stateless",
                                  [&handlerCalled](std::shared_ptr<const remoted::auth::AuthenticatedRequest>,
                                                   std::shared_ptr<IHttpResponder> responder)
                                  {
                                      handlerCalled = true;
                                      responder->send(HttpResponse {200, "", {}});
                                  });

    const auto request = signedRequestWithContentEncoding("body", "some-encoding");
    auto responder = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/stateless", request, responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(responder->captured->status, expectedStatus);
    EXPECT_FALSE(handlerCalled);
}

INSTANTIATE_TEST_SUITE_P(DecoderErrors,
                         AuthGatewayDecoderErrorTest,
                         ::testing::Values(std::make_pair(remoted::auth::AuthError::UnsupportedContentEncoding, 415),
                                           std::make_pair(remoted::auth::AuthError::MalformedContentEncoding, 400),
                                           std::make_pair(remoted::auth::AuthError::BodyTooLarge, 413)));

TEST(AuthGatewayTest, DecoderIsNotRunWhenAuthenticationFails)
{
    // The security property the auth-before-decode ordering exists for: an unauthenticated peer
    // must never reach a decoder, so it cannot spend our CPU or memory on one.
    FakeHttpServer server;
    bool decoderCalled = false;
    AuthGateway gateway {remoted::auth::AuthConfig {},
                         std::make_shared<FakeKeystore>(),
                         stubDecoder(
                             [&decoderCalled](ContentEncoding, remoted::auth::Payload&)
                             {
                                 decoderCalled = true;
                                 return remoted::auth::AuthError::None;
                             })};

    bool handlerCalled = false;
    gateway.addAuthenticatedRoute(server,
                                  Method::Post,
                                  "/stateless",
                                  [&handlerCalled](std::shared_ptr<const remoted::auth::AuthenticatedRequest>,
                                                   std::shared_ptr<IHttpResponder> responder)
                                  {
                                      handlerCalled = true;
                                      responder->send(HttpResponse {200, "", {}});
                                  });

    // A well-formed request whose token signature is corrupted -> 401 before any decoding. (The
    // body is deliberately left alone: it is not part of authentication under the bearer profile.)
    auto request = signedRequestWithContentEncoding("some body", "some-encoding");
    auto& authorization = request.headers["authorization"];
    authorization[authorization.size() - 2] = authorization[authorization.size() - 2] == 'A' ? 'B' : 'A';
    auto responder = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/stateless", request, responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(responder->captured->status, 401);
    EXPECT_FALSE(decoderCalled);
    EXPECT_FALSE(handlerCalled);
}

namespace
{
    std::optional<std::string> headerOf(const HttpResponse& response, std::string_view name)
    {
        for (const auto& [key, value] : response.headers)
        {
            if (key == name)
            {
                return value;
            }
        }
        return std::nullopt;
    }
} // namespace

// RFC 6750 §3: every 401 carries a `WWW-Authenticate: Bearer` challenge that names the failure CLASS
// (issue #38993: `error="invalid_request"` when no usable credential was presented,
// `error="invalid_token", error_description="<class>"` when one was judged and failed), with the same
// class as the body's `code`; the non-credential rejections (400/413/415) carry no challenge at all.
TEST(AuthGatewayTest, Every401CarriesItsClassInTheChallengeAndNothingElseDoes)
{
    FakeHttpServer server;
    auto gateway = makeGateway();
    gateway.addAuthenticatedRoute(
        server,
        Method::Post,
        "/stateless",
        [](std::shared_ptr<const remoted::auth::AuthenticatedRequest>, std::shared_ptr<IHttpResponder> responder)
        { responder->send(HttpResponse {200, "", {}}); });

    const auto dispatch = [&server](HttpRequest request) -> HttpResponse
    {
        auto responder = std::make_shared<CapturingResponder>();
        server.dispatch(Method::Post, "/stateless", request, responder);
        EXPECT_TRUE(responder->captured.has_value());
        return responder->captured.value_or(HttpResponse {});
    };

    const std::optional<std::string> invalidRequest {R"(Bearer error="invalid_request")"};
    const std::optional<std::string> invalidSignature {
        R"(Bearer error="invalid_token", error_description="invalid_signature")"};

    // Missing Authorization: nothing to judge.
    HttpRequest missing;
    missing.method = Method::Post;
    missing.target = "/stateless";
    missing.headers.emplace("protocol-version", "1");
    auto response = dispatch(missing);
    EXPECT_EQ(response.status, 401);
    EXPECT_EQ(headerOf(response, "WWW-Authenticate"), invalidRequest);
    EXPECT_EQ(response.body, R"({"error":"Invalid client authentication","code":"invalid_request"})");

    // A retired-scheme credential (not a bearer at all), and a well-formed token with a corrupted
    // signature (judged, and it does not work for that identity).
    auto legacy = signedRequest("body");
    legacy.headers["authorization"] = "Wazuh 001:1784238000:00112233445566778899aabbccddeeff";
    response = dispatch(legacy);
    EXPECT_EQ(response.status, 401);
    EXPECT_EQ(headerOf(response, "WWW-Authenticate"), invalidRequest);

    auto tampered = signedRequest("body");
    auto& authorization = tampered.headers["authorization"];
    authorization[authorization.size() - 2] = authorization[authorization.size() - 2] == 'A' ? 'B' : 'A';
    response = dispatch(tampered);
    EXPECT_EQ(response.status, 401);
    EXPECT_EQ(headerOf(response, "WWW-Authenticate"), invalidSignature);
    EXPECT_EQ(response.body, R"({"error":"Invalid client authentication","code":"invalid_signature"})");

    // Missing protocol-version is a 400 about the protocol, not a credential failure: no challenge.
    auto noVersion = signedRequest("body");
    noVersion.headers.erase("protocol-version");
    response = dispatch(noVersion);
    EXPECT_EQ(response.status, 400);
    EXPECT_FALSE(headerOf(response, "WWW-Authenticate").has_value());

    // The success path never carries one either.
    response = dispatch(signedRequest("body"));
    EXPECT_EQ(response.status, 200);
    EXPECT_FALSE(headerOf(response, "WWW-Authenticate").has_value());
}

// The two classes the agent acts on differently (issue #38993, §2.10 of the document): an id the
// keystore does not know tells it to re-enroll; a token outside the accepted window tells it to fix
// its clock and retry. Both were the same anonymous 401 before.
TEST(AuthGatewayTest, UnknownAgentAndStaleTokenAreDistinguishableOnTheWire)
{
    FakeHttpServer server;
    auto gateway = makeGateway();
    gateway.addAuthenticatedRoute(
        server,
        Method::Post,
        "/stateless",
        [](std::shared_ptr<const remoted::auth::AuthenticatedRequest>, std::shared_ptr<IHttpResponder> responder)
        { responder->send(HttpResponse {200, "", {}}); });

    const auto dispatchBearer = [&server](const std::string& bearer) -> HttpResponse
    {
        HttpRequest request;
        request.method = Method::Post;
        request.target = "/stateless";
        request.headers.emplace("protocol-version", "1");
        request.headers.emplace("authorization", bearer);
        request.body = "body";
        auto responder = std::make_shared<CapturingResponder>();
        server.dispatch(Method::Post, "/stateless", request, responder);
        EXPECT_TRUE(responder->captured.has_value());
        return responder->captured.value_or(HttpResponse {});
    };
    const auto bearerFor = [](const char* agentId, std::chrono::system_clock::time_point at)
    {
        const std::vector<std::uint8_t> key(32, 0x0A); // FakeKeystore's key for 001; 002 has none
        const jwt_profile::v1::SecureBytes secret {key.data(), key.size()};
        const auto token = jwt_profile::v1::JwtRequestTokenSigner::sign(
            *jwt_profile::v1::CanonicalAgentId::parse(agentId), secret, at);
        return "Bearer " + (token ? *token : std::string {});
    };

    // Agent 002 is not in the keystore: unknown_agent.
    auto response = dispatchBearer(bearerFor("002", std::chrono::system_clock::now()));
    EXPECT_EQ(response.status, 401);
    EXPECT_EQ(headerOf(response, "WWW-Authenticate"),
              std::optional<std::string> {R"(Bearer error="invalid_token", error_description="unknown_agent")"});
    EXPECT_EQ(response.body, R"({"error":"Invalid client authentication","code":"unknown_agent"})");

    // Agent 001 with a token issued ten minutes ago: stale_token.
    response = dispatchBearer(bearerFor("001", std::chrono::system_clock::now() - std::chrono::minutes(10)));
    EXPECT_EQ(response.status, 401);
    EXPECT_EQ(headerOf(response, "WWW-Authenticate"),
              std::optional<std::string> {R"(Bearer error="invalid_token", error_description="stale_token")"});
    EXPECT_EQ(response.body, R"({"error":"Invalid client authentication","code":"stale_token"})");

    // And the same request at the right time is a 200 with no challenge.
    response = dispatchBearer(bearerFor("001", std::chrono::system_clock::now()));
    EXPECT_EQ(response.status, 200);
    EXPECT_FALSE(headerOf(response, "WWW-Authenticate").has_value());
}

// The authenticated-body cap is the gateway's own check: an oversized body is a 413 -- no
// challenge -- and the decoder never runs on it.
TEST(AuthGatewayTest, BodyOverTheCapIs413BeforeTheDecoder)
{
    FakeHttpServer server;
    bool decoderCalled = false;
    remoted::auth::AuthConfig config;
    config.maxBodySize = 8;
    AuthGateway gateway {config,
                         std::make_shared<FakeKeystore>(),
                         stubDecoder(
                             [&decoderCalled](ContentEncoding, remoted::auth::Payload&)
                             {
                                 decoderCalled = true;
                                 return remoted::auth::AuthError::None;
                             })};
    bool handlerCalled = false;
    gateway.addAuthenticatedRoute(server,
                                  Method::Post,
                                  "/stateless",
                                  [&handlerCalled](std::shared_ptr<const remoted::auth::AuthenticatedRequest>,
                                                   std::shared_ptr<IHttpResponder> responder)
                                  {
                                      handlerCalled = true;
                                      responder->send(HttpResponse {200, "", {}});
                                  });

    auto responder = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/stateless", signedRequest("nine byte"), responder);
    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(responder->captured->status, 413);
    EXPECT_FALSE(headerOf(*responder->captured, "WWW-Authenticate").has_value());
    EXPECT_FALSE(decoderCalled);
    EXPECT_FALSE(handlerCalled);

    // Exactly at the cap is fine; the token is still checked first (a bad token is 401 regardless of size).
    auto atCap = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/stateless", signedRequest("8 bytes!"), atCap);
    ASSERT_TRUE(atCap->captured.has_value());
    EXPECT_EQ(atCap->captured->status, 200);

    auto badAndBig = signedRequest("nine byte");
    badAndBig.headers["authorization"] = "Bearer not-a-token";
    auto bad = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/stateless", badAndBig, bad);
    ASSERT_TRUE(bad->captured.has_value());
    EXPECT_EQ(bad->captured->status, 401);
}

// A duplicated credential header reaches the gateway as an EMPTY value (the transport's contract,
// see IHttpServer.hpp / RestinioHttpServer::makeHttpRequest) and is rejected as absent.
TEST(AuthGatewayTest, AnEmptyCredentialHeaderIsRejectedAsAbsent)
{
    FakeHttpServer server;
    auto gateway = makeGateway();
    gateway.addAuthenticatedRoute(
        server,
        Method::Post,
        "/stateless",
        [](std::shared_ptr<const remoted::auth::AuthenticatedRequest>, std::shared_ptr<IHttpResponder> responder)
        { responder->send(HttpResponse {200, "", {}}); });

    auto emptyAuth = signedRequest("body");
    emptyAuth.headers["authorization"] = "";
    auto responder = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/stateless", emptyAuth, responder);
    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(responder->captured->status, 401);

    auto emptyVersion = signedRequest("body");
    emptyVersion.headers["protocol-version"] = "";
    auto responder2 = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/stateless", emptyVersion, responder2);
    ASSERT_TRUE(responder2->captured.has_value());
    EXPECT_EQ(responder2->captured->status, 400);
}

TEST(AuthGatewayTest, AnUntouchedPayloadReachesTheHandlerAsSent)
{
    // The decoder's passthrough case, seen from the gateway: when the step returns without replacing
    // the payload, the handler must receive the wire bytes unchanged.
    FakeHttpServer server;
    auto gateway = makeGateway(); // passthrough decoder

    std::string seenBody;
    gateway.addAuthenticatedRoute(server,
                                  Method::Post,
                                  "/stateless",
                                  [&seenBody](std::shared_ptr<const remoted::auth::AuthenticatedRequest> authReq,
                                              std::shared_ptr<IHttpResponder> responder)
                                  {
                                      seenBody = std::string {authReq->payload.bytes()};
                                      responder->send(HttpResponse::json(200, "{}"));
                                  });

    const auto request = signedRequest("plain uncompressed body");
    auto responder = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/stateless", request, responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(responder->captured->status, 200);
    EXPECT_EQ(seenBody, "plain uncompressed body");
}

// ---------------------------------------------------------------------------
// Integration: the gateway wired to the real zstd decoder
// ---------------------------------------------------------------------------

TEST(AuthGatewayTest, RealZstdBodyReachesTheHandlerDecompressed)
{
    FakeHttpServer server;
    AuthGateway gateway {remoted::auth::AuthConfig {},
                         std::make_shared<FakeKeystore>(),
                         std::make_shared<const remoted::decoding::BodyDecoder>(server, /*enabled=*/true)};

    const std::string plain = R"(H {"wazuh":{"agent":{"id":"1"}}})";
    const auto compressed = remoted::testutil::zstdCompress(plain);

    std::string seenBody;
    gateway.addAuthenticatedRoute(server,
                                  Method::Post,
                                  "/stateless",
                                  [&seenBody](std::shared_ptr<const remoted::auth::AuthenticatedRequest> authReq,
                                              std::shared_ptr<IHttpResponder> responder)
                                  {
                                      seenBody = std::string {authReq->payload.bytes()};
                                      responder->send(HttpResponse::json(200, "{}"));
                                  });

    // The body travels compressed; authentication never looks at it, decoding happens after auth.
    const auto request = signedRequestWithContentEncoding(compressed, "zstd");
    auto responder = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/stateless", request, responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(responder->captured->status, 200);
    EXPECT_EQ(seenBody, plain);
}

TEST(AuthGatewayTest, ManyConcurrentZstdRequestsNeverOvershootTheBudget)
{
    // The scenario the reservations exist for: many agents posting compressed bodies at once, each
    // small on the wire but expensive to decompress. Were the budget merely CONSULTED (read a "free"
    // figure, then proceed), all N would read the same figure and all proceed, together using a
    // multiple of what the budget allows. Because the decoder's buffers and its growing output are
    // actually RESERVED, the ones that don't fit are turned away with 413 instead.
    constexpr int kRequests = 50;
    constexpr std::size_t kPayloadSize = 1024 * 1024; // 1 MiB decompressed per request
    constexpr std::size_t kBudget = 20 * 1024 * 1024; // room for well under all 50 at once
    FakeHttpServer server {kBudget};
    AuthGateway gateway {remoted::auth::AuthConfig {},
                         std::make_shared<FakeKeystore>(),
                         std::make_shared<const remoted::decoding::BodyDecoder>(server, /*enabled=*/true)};

    const std::string plain(kPayloadSize, 'q');
    const auto compressed = remoted::testutil::zstdCompress(plain);

    // Handlers HOLD their payloads (under a mutex) instead of letting them go, so the successful
    // reservations pile up and the budget is genuinely driven to exhaustion rather than each request
    // tidily freeing up before the next arrives.
    std::mutex mutex;
    std::vector<std::shared_ptr<const remoted::auth::AuthenticatedRequest>> held;
    std::atomic<int> handlerCalls {0};

    gateway.addAuthenticatedRoute(
        server,
        Method::Post,
        "/stateless",
        [&mutex, &held, &handlerCalls](std::shared_ptr<const remoted::auth::AuthenticatedRequest> authReq,
                                       std::shared_ptr<IHttpResponder> responder)
        {
            handlerCalls.fetch_add(1);
            {
                std::lock_guard<std::mutex> lock {mutex};
                held.push_back(std::move(authReq));
            }
            responder->send(HttpResponse::json(200, "{}"));
        });

    const auto request = signedRequestWithContentEncoding(compressed, "zstd");
    std::vector<std::shared_ptr<CapturingResponder>> responders(kRequests);
    std::vector<std::thread> threads;
    threads.reserve(kRequests);

    for (int i = 0; i < kRequests; ++i)
    {
        responders[static_cast<std::size_t>(i)] = std::make_shared<CapturingResponder>();
        threads.emplace_back(
            [&server, &request, &responders, i]
            { server.dispatch(Method::Post, "/stateless", request, responders[static_cast<std::size_t>(i)]); });
    }
    for (auto& thread : threads)
    {
        thread.join();
    }

    int accepted = 0;
    int shed = 0;
    for (const auto& responder : responders)
    {
        ASSERT_TRUE(responder->captured.has_value());
        const int status = responder->captured->status;
        if (status == 200)
        {
            ++accepted;
        }
        else
        {
            // 413 is the only other outcome allowed: no 500 (a crash/throw), no 400 (these frames
            // are all perfectly valid), no silent success past the budget.
            EXPECT_EQ(status, 413);
            ++shed;
        }
    }

    EXPECT_EQ(accepted + shed, kRequests);
    // Both sides must actually be exercised: some got through (so this isn't passing because
    // everything was rejected) and some were turned away (so the budget really did push back).
    EXPECT_GT(accepted, 0);
    EXPECT_GT(shed, 0);
    EXPECT_EQ(handlerCalls.load(), accepted); // only the accepted ones reached the handler
    // The decisive invariant: what got through fits in the budget. Without real reservations this
    // would exceed it (up to 50 MiB of payload against a 20 MiB budget).
    EXPECT_LE(static_cast<std::size_t>(accepted) * kPayloadSize, kBudget);

    {
        std::lock_guard<std::mutex> lock {mutex};
        EXPECT_EQ(server.m_budget.availableBytes(), kBudget - static_cast<std::size_t>(accepted) * kPayloadSize);
        held.clear();
    }
    // Releasing them restores the budget exactly, with nothing leaked by any thread.
    EXPECT_EQ(server.m_budget.availableBytes(), kBudget);
    EXPECT_EQ(server.m_budget.inFlightCount(), 0U);
}

/* --- The optional rate-limit gate (issue #39315) ---------------------------------------------
 *
 * POST /enroll/secret is the first AUTHENTICATED route in remoted to carry a rate limit, and it
 * carries one because it shares POST /enroll's bucket: a fleet-wide 4.x->5.0 upgrade wave hits it
 * all at once, and unthrottled that wave fills authd's identity journal and starts refusing real
 * enrollments. endpoints/rateLimitGate.hpp's wrap() cannot express it -- it composes with a
 * RouteHandler, and addAuthenticatedRoute() builds the RouteHandler itself with authenticate()
 * inside -- so the gate lives in the gateway and is charged BEFORE authentication.
 *
 * That ordering is the property these cases exist for. Everything else about the token bucket is
 * the limiter's own contract (endpointRateLimiter_test) and the gate's shared semantics are
 * rateLimitGate_test's; what cannot be seen anywhere else is that the refusal precedes
 * authenticate(), that an ungated route is untouched, and that a refusal never enters the latency
 * histogram.
 */

namespace
{
    // The gate's own fixture: a live bucket, the route's counters, and a handler that records
    // whether it ever ran.
    struct GateFixture
    {
        wazuh::metrics::Manager manager;
        remoted::metrics::EndpointHttpMetrics http {remoted::metrics::makeEndpointHttpMetrics(
            manager, "enroll.secret", /*withLatency=*/true, "POST", "/enroll/secret")};
        std::shared_ptr<wazuh::metrics::ICounter> rateLimited {
            manager.getOrCreateCounter("remoted.enroll.secret.rate_limited", "test", "count")};
        int handlerCalls {0};

        AuthenticatedRouteGate gate(double rate, double burst)
        {
            EndpointRateLimiter::Settings settings;
            settings.ratePerSecond = rate;
            settings.burst = burst;

            AuthenticatedRouteGate g;
            g.limiter = std::make_shared<EndpointRateLimiter>(settings);
            g.rejection = []
            {
                return HttpResponse::json(429, R"({"error":"rate_limited"})");
            };
            g.rejected = rateLimited;
            g.httpMetrics = &http;
            g.route = "POST /enroll/secret";
            return g;
        }

        AuthenticatedHandler handler()
        {
            return [this](std::shared_ptr<const remoted::auth::AuthenticatedRequest>,
                          std::shared_ptr<IHttpResponder> responder)
            {
                ++handlerCalls;
                responder->send(HttpResponse::json(200, R"({"ok":true})"));
            };
        }
    };
} // namespace

TEST(AuthGatewayTest, AnEmptyBucketRefusesBeforeAuthenticationRuns)
{
    // THE assertion that pins the ordering: a request carrying no bearer at all -- which the
    // gateway would answer 401 -- is answered 429 instead, because the bucket was consulted first.
    // Charging after authenticate() would put 401 before 429 and make every refusal pay a keystore
    // lookup and an HMAC, which is exactly the cost the limit exists to avoid spending.
    FakeHttpServer server;
    auto gateway = makeGateway();
    GateFixture f;

    gateway.addAuthenticatedRoute(
        server, Method::Post, "/enroll/secret", f.handler(), ResponseMode::Buffered, f.gate(1.0, 1.0));

    // Spend the single token with a request that does authenticate.
    auto first = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/enroll/secret", signedRequest("{}"), first);
    ASSERT_TRUE(first->captured.has_value());
    ASSERT_EQ(first->captured->status, 200);
    ASSERT_EQ(f.handlerCalls, 1);

    HttpRequest unauthenticated;
    unauthenticated.method = Method::Post;
    unauthenticated.target = "/enroll/secret";
    // No protocol-version and no authorization: a 400/401 on any other authenticated route.

    auto second = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/enroll/secret", unauthenticated, second);

    ASSERT_TRUE(second->captured.has_value());
    EXPECT_EQ(second->captured->status, 429);
    EXPECT_EQ(f.handlerCalls, 1);
}

TEST(AuthGatewayTest, AGatedRefusalCarriesTheRoutesBodyAndRetryAfter)
{
    FakeHttpServer server;
    auto gateway = makeGateway();
    GateFixture f;

    gateway.addAuthenticatedRoute(
        server, Method::Post, "/enroll/secret", f.handler(), ResponseMode::Buffered, f.gate(1.0, 1.0));

    auto first = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/enroll/secret", signedRequest("{}"), first);
    auto refused = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/enroll/secret", signedRequest("{}"), refused);

    ASSERT_TRUE(refused->captured.has_value());
    EXPECT_EQ(refused->captured->status, 429);
    // The ROUTE's envelope, not one the gateway invented: sharing a bucket is not sharing a body.
    EXPECT_EQ(refused->captured->body, R"({"error":"rate_limited"})");

    std::string retryAfter;
    for (const auto& [name, value] : refused->captured->headers)
    {
        if (name == "Retry-After")
        {
            retryAfter = value;
        }
    }
    // The gate owns this one: it is the limiter's refill time, not an envelope decision.
    EXPECT_EQ(retryAfter, "1");
}

TEST(AuthGatewayTest, AGatedRefusalMovesTheResponsesFamilyButNotTheLatencyHistogram)
{
    FakeHttpServer server;
    auto gateway = makeGateway();
    GateFixture f;

    gateway.addAuthenticatedRoute(
        server, Method::Post, "/enroll/secret", f.handler(), ResponseMode::Buffered, f.gate(1.0, 1.0));

    auto first = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/enroll/secret", signedRequest("{}"), first);
    auto refused = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/enroll/secret", signedRequest("{}"), refused);
    ASSERT_EQ(refused->captured->status, 429);

    EXPECT_EQ(f.rateLimited->get(), 1U);         // the WHY
    EXPECT_EQ(f.http.responses.c429->get(), 1U); // the WHAT
    EXPECT_EQ(f.http.responses.other->get(), 0U);
    // The refusal must NOT be timed: it never entered the handler, and during the very burst the
    // limit exists for those microsecond samples would dominate the distribution and hide the
    // latency of the requests actually served. The admitted request is not timed here either --
    // the endpoint's own MeteredResponder does that, and this fixture's stub handler has none.
    ASSERT_NE(f.http.latency, nullptr);
    EXPECT_EQ(f.http.latency->snapshot().count, 0U);
}

TEST(AuthGatewayTest, ARouteWithNoGateOrADisabledLimiterIsUnaffected)
{
    FakeHttpServer server;
    auto gateway = makeGateway();
    GateFixture ungated;
    GateFixture disabled;

    // The six existing authenticated routes: no gate argument at all.
    gateway.addAuthenticatedRoute(server, Method::Post, "/stateless", ungated.handler());
    // A gate whose limiter is disabled (rate 0, the operator's "no limit"): resolved once at
    // registration, so it costs one pointer test per request and refuses nothing.
    gateway.addAuthenticatedRoute(
        server, Method::Post, "/enroll/secret", disabled.handler(), ResponseMode::Buffered, disabled.gate(0.0, 0.0));

    for (int i = 0; i < 5; ++i)
    {
        auto plain = std::make_shared<CapturingResponder>();
        server.dispatch(Method::Post, "/stateless", signedRequest("{}"), plain);
        ASSERT_TRUE(plain->captured.has_value());
        EXPECT_EQ(plain->captured->status, 200);

        auto gated = std::make_shared<CapturingResponder>();
        server.dispatch(Method::Post, "/enroll/secret", signedRequest("{}"), gated);
        ASSERT_TRUE(gated->captured.has_value());
        EXPECT_EQ(gated->captured->status, 200);
    }

    EXPECT_EQ(ungated.handlerCalls, 5);
    EXPECT_EQ(disabled.handlerCalls, 5);
    EXPECT_EQ(ungated.rateLimited->get(), 0U);
    EXPECT_EQ(disabled.rateLimited->get(), 0U);
}

TEST(AuthGatewayTest, AGatedRouteStillAuthenticatesWhenTheBucketAdmits)
{
    // The gate is a ceiling, not a replacement for the credential check: an admitted request whose
    // bearer does not verify is still a 401, and the handler still never runs.
    FakeHttpServer server;
    auto gateway = makeGateway();
    GateFixture f;

    gateway.addAuthenticatedRoute(
        server, Method::Post, "/enroll/secret", f.handler(), ResponseMode::Buffered, f.gate(100.0, 100.0));

    auto request = signedRequest("{}");
    request.headers["authorization"] = "Bearer not.a.token";

    auto responder = std::make_shared<CapturingResponder>();
    server.dispatch(Method::Post, "/enroll/secret", request, responder);

    ASSERT_TRUE(responder->captured.has_value());
    EXPECT_EQ(responder->captured->status, 401);
    EXPECT_EQ(f.handlerCalls, 0);
    EXPECT_EQ(f.rateLimited->get(), 0U);
}
