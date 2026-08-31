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

// RFC 6750 §3: every 401 carries `WWW-Authenticate: Bearer`, uniformly -- it names the scheme, never
// the reason -- while the non-credential rejections (400/413/415) carry no challenge at all.
TEST(AuthGatewayTest, Every401CarriesTheBearerChallengeAndNothingElseDoes)
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

    // Missing Authorization.
    HttpRequest missing;
    missing.method = Method::Post;
    missing.target = "/stateless";
    missing.headers.emplace("protocol-version", "1");
    auto response = dispatch(missing);
    EXPECT_EQ(response.status, 401);
    EXPECT_EQ(headerOf(response, "WWW-Authenticate"), std::optional<std::string> {"Bearer"});

    // A retired-scheme credential, and a well-formed token with a corrupted signature.
    auto legacy = signedRequest("body");
    legacy.headers["authorization"] = "Wazuh 001:1784238000:00112233445566778899aabbccddeeff";
    response = dispatch(legacy);
    EXPECT_EQ(response.status, 401);
    EXPECT_EQ(headerOf(response, "WWW-Authenticate"), std::optional<std::string> {"Bearer"});

    auto tampered = signedRequest("body");
    auto& authorization = tampered.headers["authorization"];
    authorization[authorization.size() - 2] = authorization[authorization.size() - 2] == 'A' ? 'B' : 'A';
    response = dispatch(tampered);
    EXPECT_EQ(response.status, 401);
    EXPECT_EQ(headerOf(response, "WWW-Authenticate"), std::optional<std::string> {"Bearer"});

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
