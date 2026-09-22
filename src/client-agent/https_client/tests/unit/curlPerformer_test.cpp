/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/*
 * Pins the spec-to-options mapping (the http-request mocking idiom): every
 * TLS mode, the always-on hardening options, memory vs streamed bodies and
 * the abort wiring are asserted as exact option calls with zero network.
 */

#include "curlPerformer.hpp"
#include "fakeSysSeams.hpp"
#include "mockCurlHandle.hpp"
#include "mockFsProbe.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <future>
#include <mutex>
#include <thread>

using ::testing::_;
using ::testing::AllOf;
using ::testing::DoAll;
using ::testing::Field;
using ::testing::Invoke;
using ::testing::InvokeWithoutArgs;
using ::testing::NiceMock;
using ::testing::NotNull;
using ::testing::Return;
using ::testing::SaveArg;

namespace
{
    ModuleConfig makeConfig(hc_verify_mode_t mode)
    {
        hc_config_t config {};
        std::strncpy(config.server_host, "127.0.0.1", sizeof(config.server_host) - 1);
        config.server_port = 27840;
        std::strncpy(config.agent_id, "001", sizeof(config.agent_id) - 1);
        config.verify_mode = mode;
        auto typed = ModuleConfig::fromC(config);
        return typed;
    }

    /// Builds a performer whose factory hands out the given mock exactly once.
    CurlPerformer makePerformer(const ModuleConfig& config, std::unique_ptr<ICurlHandle> handle)
    {
        auto shared = std::make_shared<std::unique_ptr<ICurlHandle>>(std::move(handle));
        return CurlPerformer {config,
                              [shared]() -> std::unique_ptr<ICurlHandle>
        {
            return std::move(*shared);
        }};
    }

    /// Partial-expectation tests: absorb the option calls they do not assert
    /// (a method with any EXPECT_CALL treats non-matching calls as failures).
    void allowOtherOptions(MockCurlHandle& handle)
    {
        EXPECT_CALL(handle, setOptionLong(_, _)).Times(::testing::AnyNumber());
        EXPECT_CALL(handle, setOptionString(_, _)).Times(::testing::AnyNumber());
        EXPECT_CALL(handle, setOptionPtr(_, _)).Times(::testing::AnyNumber());
        EXPECT_CALL(handle, appendHeader(_)).Times(::testing::AnyNumber());
    }

    /// A genuine, unclassified chain/CA-trust failure: a certificate arrived (sawDepth0
    /// true), OpenSSL's own verification of it failed (depth0VerificationFailed true), and
    /// not for a reason #39062's classifier names (kind stays None). The one shape
    /// isUnclassifiedChainFailure() (curlPerformer.cpp) treats as eligible for the #39123
    /// local-anchor fallback -- distinct from BOTH a TlsFail that never reached certificate
    /// inspection at all (sawDepth0 false) AND a TlsFail where the certificate verified
    /// cleanly but the attempt still failed for an unrelated reason downstream (sawDepth0
    /// true, depth0VerificationFailed false -- see chainVerifiedButUnrelatedFailure()
    /// below), both of which stay on the ordinary Unreachable/retry path instead.
    /// MockCurlHandle's default tlsFailureDetail() answers with a value-initialized
    /// TlsFailureDetail (both flags false), so any test wanting to simulate an untrusted-CA
    /// failure must return this explicitly, not rely on the default.
    TlsFailureDetail chainTrustFailure()
    {
        TlsFailureDetail detail;
        detail.sawDepth0 = true;
        detail.depth0VerificationFailed = true;
        return detail;
    }

    /// The shape a contrarian-reviewer round found isUnclassifiedChainFailure() originally
    /// missed: the depth-0 certificate WAS inspected and verified cleanly (sawDepth0 true),
    /// but the overall attempt still ended in TlsFail for a reason unrelated to the
    /// certificate -- one of the non-CURLE_PEER_FAILED_VERIFICATION codes curlHandle.cpp's
    /// statusFromCurlCode() also buckets into TlsFail (a cipher or protocol failure after an
    /// already-accepted certificate, say). classifyTlsVerifyFailure() correctly leaves kind
    /// at None here too (see its own test table's X509_V_OK/peerVerificationFailed=false
    /// row) -- retrying against a different trust anchor could never fix this, since the
    /// certificate was never the problem.
    TlsFailureDetail chainVerifiedButUnrelatedFailure()
    {
        TlsFailureDetail detail;
        detail.sawDepth0 = true;
        detail.depth0VerificationFailed = false;
        return detail;
    }

    /// External review finding: classifyTlsVerifyFailure() (#39062) leaves kind at None for
    /// ANY depth0Error besides its own two classified causes -- not just genuine chain/CA-
    /// trust problems, but also X.509 outcomes that have nothing to do with which anchor is
    /// trusted (an unsupported certificate purpose, a policy/extension OpenSSL does not
    /// understand). sawDepth0 and depth0VerificationFailed are both true here (a certificate
    /// was inspected and its verification did fail), but depth0ErrorIsChainTrustRelated is
    /// false: a different trust anchor could never fix an X509_V_ERR_INVALID_PURPOSE-class
    /// rejection, so this must not be fallback-eligible either.
    TlsFailureDetail chainTrustUnrelatedDepth0Error()
    {
        TlsFailureDetail detail;
        detail.sawDepth0 = true;
        detail.depth0VerificationFailed = true;
        detail.depth0ErrorIsChainTrustRelated = false;
        return detail;
    }

    /// #39123 follow-up: the shape that used to be a KNOWN LIMITATION. OpenSSL's chain
    /// builder rejected an untrusted intermediate/root before internal_verify() ever reached
    /// depth 0, so sawDepth0 stays false here (there was no certificate at depth 0 to
    /// inspect) -- chainTrustRejectedAboveDepth0 is the only signal that distinguishes this
    /// from a pure transport failure.
    TlsFailureDetail chainTrustRejectedAboveDepth0()
    {
        TlsFailureDetail detail;
        detail.chainTrustRejectedAboveDepth0 = true;
        return detail;
    }
} // namespace

/* An in-memory response is bounded at the transport, not merely judged once it has all arrived.
 * Without the cap reaching the sink, a consumer that checks the finished body has already let the
 * peer decide how much of this agent's memory to take, on a schedule the peer controls. */
TEST(CurlPerformerTest, AnInMemoryResponseCarriesTheSpecsByteCapToTheSink)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);
    const auto config = makeConfig(HC_VERIFY_NONE);

    HttpRequestSpec spec;
    spec.target = "/cacerts";
    spec.maxResponseBytes = 8192;

    EXPECT_CALL(*handle, captureResponseBody(NotNull(), 8192u));
    EXPECT_CALL(*handle, perform()).WillOnce(Return(TransportStatus::Ok));
    EXPECT_CALL(*handle, responseCode()).WillOnce(Return(200));

    auto performer = makePerformer(config, std::move(mock));
    const auto response = performer.perform(spec);
    EXPECT_EQ(TransportStatus::Ok, response.status);
}

/* ...and a request that sets no cap is still unbounded, so this change is confined to the callers
 * that ask for one. */
TEST(CurlPerformerTest, AnInMemoryResponseWithoutACapStaysUnbounded)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);
    const auto config = makeConfig(HC_VERIFY_NONE);

    HttpRequestSpec spec;
    spec.target = "/stateless";

    EXPECT_CALL(*handle, captureResponseBody(NotNull(), 0u));
    EXPECT_CALL(*handle, perform()).WillOnce(Return(TransportStatus::Ok));
    EXPECT_CALL(*handle, responseCode()).WillOnce(Return(200));

    auto performer = makePerformer(config, std::move(mock));
    (void) performer.perform(spec);
}

TEST(CurlPerformerTest, MemoryBodyMapsToExactOptions)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);
    const auto config = makeConfig(HC_VERIFY_NONE);

    const uint8_t body[] = "H {}\nE 1:loc:msg\n";
    HttpRequestSpec spec;
    spec.target = "/stateless";
    spec.headers = {"protocol-version: 1", "Authorization: Wazuh 001:1:aa"};
    spec.body = body;
    spec.bodyLength = sizeof(body) - 1;
    spec.timeoutMs = 1234;

    EXPECT_CALL(*handle, setOptionString(CurlOption::Url, "https://127.0.0.1:27840/stateless"));
    EXPECT_CALL(*handle, setOptionLong(CurlOption::Post, 1L));
    EXPECT_CALL(*handle, setOptionPtr(CurlOption::PostFields, body));
    EXPECT_CALL(*handle, setOptionLong(CurlOption::PostFieldSize, static_cast<long>(sizeof(body) - 1)));
    EXPECT_CALL(*handle, appendHeader("protocol-version: 1"));
    EXPECT_CALL(*handle, appendHeader("Authorization: Wazuh 001:1:aa"));
    EXPECT_CALL(*handle, setOptionLong(CurlOption::TimeoutMs, 1234L));
    EXPECT_CALL(*handle, captureResponseBody(NotNull(), _));
    EXPECT_CALL(*handle,
                captureResponseHeaders(
                    AllOf(Field(&HeaderCapture::retryAfter, NotNull()), Field(&HeaderCapture::serverDate, NotNull()))));
    EXPECT_CALL(*handle, perform()).WillOnce(Return(TransportStatus::Ok));
    EXPECT_CALL(*handle, responseCode()).WillOnce(Return(200));

    auto performer = makePerformer(config, std::move(mock));
    const auto response = performer.perform(spec);
    EXPECT_EQ(TransportStatus::Ok, response.status);
    EXPECT_EQ(200, response.httpCode);
}

// #38492/#38491: CurlPerformer itself no longer knows about the endpoint --
// the manager routes on the literal wire request-target (prefix included),
// so the prefix must be folded into HttpRequestSpec::target upstream of this
// class (see RetrySender::attemptOnce and EnrollClient::performOnce, both of
// which fold it in via requestTarget.hpp's prefixedTarget()). configureRequest()'s
// baseUrl() + spec.target composition is deliberately unaware of it and
// stays exactly as it was before #38492 -- see MemoryBodyMapsToExactOptions
// above, which already pins that composition with a bare target.

TEST(CurlPerformerTest, ContentTypeEmittedWhenSet)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);
    const auto config = makeConfig(HC_VERIFY_NONE);

    const uint8_t body[] = R"({"type":"notify"})";
    HttpRequestSpec spec;
    spec.target = "/control";
    spec.contentType = "application/json";
    spec.body = body;
    spec.bodyLength = sizeof(body) - 1;

    EXPECT_CALL(*handle, appendHeader("Content-Type: application/json"));
    EXPECT_CALL(*handle, perform()).WillOnce(Return(TransportStatus::Ok));

    auto performer = makePerformer(config, std::move(mock));
    performer.perform(spec);
}

TEST(CurlPerformerTest, NoContentTypeWhenUnset)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);
    const auto config = makeConfig(HC_VERIFY_NONE);

    const uint8_t body[] = "H {}\n";
    HttpRequestSpec spec;
    spec.target = "/stateless"; // */* endpoint: keep libcurl's default.
    spec.body = body;
    spec.bodyLength = sizeof(body) - 1;

    EXPECT_CALL(*handle, appendHeader(::testing::StartsWith("Content-Type:"))).Times(0);
    EXPECT_CALL(*handle, perform()).WillOnce(Return(TransportStatus::Ok));

    auto performer = makePerformer(config, std::move(mock));
    performer.perform(spec);
}

// A GET spec must map to CURLOPT_HTTPGET and carry no body at all -- neither
// Post nor PostFields/PostFieldSize -- unlike every pre-existing spec, which
// defaults to Post (MemoryBodyMapsToExactOptions above already pins that
// default).
TEST(CurlPerformerTest, GetMethodMapsToHttpGetAndSendsNoBody)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);
    const auto config = makeConfig(HC_VERIFY_NONE);

    HttpRequestSpec spec;
    spec.target = "/cacerts";
    spec.method = HttpMethod::Get;
    spec.timeoutMs = 5000;

    EXPECT_CALL(*handle, setOptionString(CurlOption::Url, "https://127.0.0.1:27840/cacerts"));
    EXPECT_CALL(*handle, setOptionLong(CurlOption::Get, 1L));
    EXPECT_CALL(*handle, setOptionLong(CurlOption::Post, _)).Times(0);
    EXPECT_CALL(*handle, setOptionPtr(CurlOption::PostFields, _)).Times(0);
    EXPECT_CALL(*handle, setOptionLong(CurlOption::PostFieldSize, _)).Times(0);
    EXPECT_CALL(*handle, perform()).WillOnce(Return(TransportStatus::Ok));
    EXPECT_CALL(*handle, responseCode()).WillOnce(Return(200));

    auto performer = makePerformer(config, std::move(mock));
    const auto response = performer.perform(spec);
    EXPECT_EQ(TransportStatus::Ok, response.status);
    EXPECT_EQ(200, response.httpCode);
}

TEST(CurlPerformerTest, ResponseBodyAndRetryAfterFlowBack)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();

    std::string* bodyOut = nullptr;
    HeaderCapture captureOut {};
    EXPECT_CALL(*handle, captureResponseBody(_, _)).WillOnce(DoAll(SaveArg<0>(&bodyOut), Return(true)));
    EXPECT_CALL(*handle, captureResponseHeaders(_)).WillOnce(DoAll(SaveArg<0>(&captureOut), Return(true)));
    EXPECT_CALL(*handle, perform())
    .WillOnce(Invoke(
                  [&]() -> TransportStatus
    {
        *bodyOut = "{\"ok\":true}";
        *captureOut.retryAfter = 7;
        *captureOut.serverDate = 1755000000;
        *captureOut.caGeneration = 1789000012;
        return TransportStatus::Ok;
    }));
    EXPECT_CALL(*handle, responseCode()).WillOnce(Return(503));

    auto performer = makePerformer(makeConfig(HC_VERIFY_NONE), std::move(mock));
    HttpRequestSpec spec;
    spec.target = "/stateless";
    const auto response = performer.perform(spec);
    EXPECT_EQ("{\"ok\":true}", response.body);
    EXPECT_EQ(7, response.retryAfterSeconds);
    EXPECT_EQ(1755000000, response.serverDateSeconds);
    // Wazuh-CA-Generation rides the same single HEADERFUNCTION slot as the other two: libcurl
    // allows only one per handle, which is why HeaderCapture exists at all.
    EXPECT_EQ(1789000012, response.caGeneration);
    EXPECT_EQ(503, response.httpCode);
}

TEST(CurlPerformerTest, TlsFullMode)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);
    auto config = makeConfig(HC_VERIFY_FULL);
    config.caPath = "/etc/ca.pem";

    EXPECT_CALL(*handle, setOptionLong(CurlOption::VerifyPeer, 1L));
    EXPECT_CALL(*handle, setOptionLong(CurlOption::VerifyHost, 2L));
    EXPECT_CALL(*handle, setOptionString(CurlOption::CaInfo, "/etc/ca.pem"));
    EXPECT_CALL(*handle, setOptionLong(CurlOption::FollowLocation, 0L));
    EXPECT_CALL(*handle, setOptionLong(CurlOption::NoSignal, 1L));
    EXPECT_CALL(*handle, setOptionLong(CurlOption::SuppressConnectHeaders, 1L));

    auto performer = makePerformer(config, std::move(mock));
    performer.perform(HttpRequestSpec {});
}

TEST(CurlPerformerTest, RejectedSuppressConnectHeadersOptionAbortsBeforePerforming)
{
    // Fail-closed like every other hardening option in applyTls(): if this
    // curl build somehow can't honor it, refuse to send rather than risk a
    // forward-proxy's CONNECT Date being mistaken for the manager's.
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);

    EXPECT_CALL(*handle, setOptionLong(CurlOption::SuppressConnectHeaders, 1L)).WillOnce(Return(false));
    EXPECT_CALL(*handle, perform()).Times(0);

    auto performer = makePerformer(makeConfig(HC_VERIFY_FULL), std::move(mock));
    const auto response = performer.perform(HttpRequestSpec {});
    EXPECT_EQ(TransportStatus::TlsFail, response.status);
}

TEST(CurlPerformerTest, TlsCertModeDisablesHostnameOnly)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);
    auto config = makeConfig(HC_VERIFY_CERT);
    config.caPath = "/etc/ca.pem";

    EXPECT_CALL(*handle, setOptionLong(CurlOption::VerifyPeer, 1L));
    EXPECT_CALL(*handle, setOptionLong(CurlOption::VerifyHost, 0L));

    auto performer = makePerformer(config, std::move(mock));
    performer.perform(HttpRequestSpec {});
}

TEST(CurlPerformerTest, TlsNoneModeDisablesAllVerification)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);

    EXPECT_CALL(*handle, setOptionLong(CurlOption::VerifyPeer, 0L));
    EXPECT_CALL(*handle, setOptionLong(CurlOption::VerifyHost, 0L));
    EXPECT_CALL(*handle, setOptionString(CurlOption::CaInfo, _)).Times(0);
    EXPECT_CALL(*handle, setOptionString(CurlOption::SslCert, _)).Times(0);
    EXPECT_CALL(*handle, setOptionString(CurlOption::SslCiphers, _)).Times(0);

    auto performer = makePerformer(makeConfig(HC_VERIFY_NONE), std::move(mock));
    performer.perform(HttpRequestSpec {});
}

TEST(CurlPerformerTest, ClientCertAndCiphersApplied)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);
    auto config = makeConfig(HC_VERIFY_NONE);
    config.clientCert = "/etc/agent.pem";
    config.clientKey = "/etc/agent.key";
    config.ciphers = "HIGH:!aNULL";

    EXPECT_CALL(*handle, setOptionString(CurlOption::SslCert, "/etc/agent.pem"));
    EXPECT_CALL(*handle, setOptionString(CurlOption::SslKey, "/etc/agent.key"));
    EXPECT_CALL(*handle, setOptionString(CurlOption::SslCiphers, "HIGH:!aNULL"));

    auto performer = makePerformer(config, std::move(mock));
    performer.perform(HttpRequestSpec {});
}

TEST(CurlPerformerTest, RejectedTlsOptionAbortsBeforePerforming)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);

    // What a backend that does not implement the option answers.
    EXPECT_CALL(*handle, setOptionLong(CurlOption::SslVersion, _)).WillOnce(Return(false));
    EXPECT_CALL(*handle, perform()).Times(0);
    EXPECT_CALL(*handle, curlError()).Times(0);

    auto performer = makePerformer(makeConfig(HC_VERIFY_FULL), std::move(mock));
    const auto response = performer.perform(HttpRequestSpec {});
    EXPECT_EQ(TransportStatus::TlsFail, response.status);
    // Nothing ran, so there is no libcurl reason: the log sites must render a
    // bare outcome rather than a dangling separator.
    EXPECT_TRUE(response.curlError.empty());
}

TEST(CurlPerformerTest, RejectedCipherListAbortsBeforePerforming)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);
    auto config = makeConfig(HC_VERIFY_FULL);
    config.ciphers = "TLS_AES_128_GCM_SHA256";

    EXPECT_CALL(*handle, setOptionString(CurlOption::SslCiphers, _)).WillOnce(Return(false));
    EXPECT_CALL(*handle, perform()).Times(0);

    auto performer = makePerformer(config, std::move(mock));
    const auto response = performer.perform(HttpRequestSpec {});
    EXPECT_EQ(TransportStatus::TlsFail, response.status);
}

TEST(CurlPerformerTest, ConfiguredCaIsTheWholeTrustSet)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);
    auto config = makeConfig(HC_VERIFY_FULL);
    config.caPath = "/etc/ca.pem";

    EXPECT_CALL(*handle, setOptionString(CurlOption::CaInfo, "/etc/ca.pem"));
    // The machine's own stores are never added on top of it.
    EXPECT_CALL(*handle, setOptionLong(CurlOption::SslOptions, _)).Times(0);
    // A configured CA may be a self-signed root the peer echoes back in its own chain.
    EXPECT_CALL(*handle, trustSelfSignedRoot());

    auto performer = makePerformer(config, std::move(mock));
    performer.perform(HttpRequestSpec {});
}

TEST(CurlPerformerTest, TrustAnchorsWithoutConfiguredCa)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);

    EXPECT_CALL(*handle, setOptionString(CurlOption::CaInfo, _)).Times(0);
    // Only reached when caPath is actually set, which it is not here.
    EXPECT_CALL(*handle, trustSelfSignedRoot()).Times(0);
#if defined(WIN32) || defined(__APPLE__)
    // Our OpenSSL-backed Windows/macOS curl has no bundle of its own to fall back on.
    EXPECT_CALL(*handle, setOptionLong(CurlOption::SslOptions, TLS_NATIVE_CA_STORE));
#else
    EXPECT_CALL(*handle, setOptionLong(CurlOption::SslOptions, _)).Times(0);
#endif

    auto performer = makePerformer(makeConfig(HC_VERIFY_FULL), std::move(mock));
    performer.perform(HttpRequestSpec {});
}

TEST(CurlPerformerTest, RejectedTrustSelfSignedRootAbortsBeforePerforming)
{
    // Fail-closed like every other hardening option in applyTrustAnchors(): a
    // configured CA that curl can't be made to trust as a partial chain must not
    // silently fall back to the classic (rejecting) chain builder.
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);
    auto config = makeConfig(HC_VERIFY_FULL);
    config.caPath = "/etc/ca.pem";

    EXPECT_CALL(*handle, trustSelfSignedRoot()).WillOnce(Return(false));
    EXPECT_CALL(*handle, perform()).Times(0);

    auto performer = makePerformer(config, std::move(mock));
    const auto response = performer.perform(HttpRequestSpec {});
    EXPECT_EQ(TransportStatus::TlsFail, response.status);
}

TEST(CurlPerformerTest, TlsSystemModeVerifiesPeerAndHost)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);
    auto config = makeConfig(HC_VERIFY_SYSTEM);
    NiceMock<MockFsProbe> fsProbe;

    EXPECT_CALL(*handle, setOptionLong(CurlOption::VerifyPeer, 1L));
    EXPECT_CALL(*handle, setOptionLong(CurlOption::VerifyHost, 2L)); // Same strictness as full.

#if defined(WIN32) || defined(__APPLE__)
    EXPECT_CALL(*handle, setOptionLong(CurlOption::SslOptions, TLS_NATIVE_CA_STORE));
    EXPECT_CALL(*handle, setOptionString(CurlOption::CaInfo, _)).Times(0);
    EXPECT_CALL(*handle, trustSelfSignedRoot()).Times(0);
#else
    ON_CALL(fsProbe, findSystemCaBundle()).WillByDefault(Return("/etc/ssl/certs/ca-certificates.crt"));
    EXPECT_CALL(*handle, setOptionString(CurlOption::CaInfo, "/etc/ssl/certs/ca-certificates.crt"));
    EXPECT_CALL(*handle, setOptionLong(CurlOption::SslOptions, _)).Times(0);
    // caPath is the OS bundle here, not a configured CA: no partial-chain relaxation.
    EXPECT_CALL(*handle, trustSelfSignedRoot()).Times(0);
#endif

    auto shared = std::make_shared<std::unique_ptr<ICurlHandle>>(std::move(mock));
    CurlPerformer performer {config,
                             [shared]() -> std::unique_ptr<ICurlHandle> { return std::move(*shared); },
                             fsProbe};
    performer.perform(HttpRequestSpec {});
}

#if !defined(WIN32) && !defined(__APPLE__)
TEST(CurlPerformerTest, TlsSystemModeResolvesTrustAnchorOnceNotPerRequest)
{
    auto config = makeConfig(HC_VERIFY_SYSTEM);
    NiceMock<MockFsProbe> fsProbe;

    // Resolved once at construction; perform() below runs twice and must not
    // probe the filesystem again on the second request.
    EXPECT_CALL(fsProbe, findSystemCaBundle())
    .Times(1)
    .WillOnce(Return("/etc/ssl/certs/ca-certificates.crt"));

    CurlHandleFactory factory = [&]() -> std::unique_ptr<ICurlHandle>
    {
        auto handle = std::make_unique<NiceMock<MockCurlHandle>>();
        allowOtherOptions(*handle);
        ON_CALL(*handle, perform()).WillByDefault(Return(TransportStatus::Ok));
        EXPECT_CALL(*handle, setOptionString(CurlOption::CaInfo, "/etc/ssl/certs/ca-certificates.crt"));
        return handle;
    };

    CurlPerformer performer {config, factory, fsProbe};
    performer.perform(HttpRequestSpec {});
    performer.perform(HttpRequestSpec {});
}

// #39123: the OS bundle does not verify the manager, but a fallback anchor is configured --
// the same perform() call must retry against it before returning, with the partial-chain
// relaxation a pinned self-signed file needs (unlike the OS-bundle attempt above, which must
// not get it -- ConfiguredCaIsTheWholeTrustSet / TlsSystemModeVerifiesPeerAndHost already pin
// that half).
TEST(CurlPerformerTest, SystemModeFallsBackToLocalAnchorOnVerifyFailure)
{
    auto config = makeConfig(HC_VERIFY_SYSTEM);
    config.systemFallbackCaPath = "/var/ossec/etc/certs/root-ca.pem";
    NiceMock<MockFsProbe> fsProbe;
    ON_CALL(fsProbe, findSystemCaBundle()).WillByDefault(Return("/etc/ssl/certs/ca-certificates.crt"));

    int callCount = 0;
    CurlHandleFactory factory = [&]() -> std::unique_ptr<ICurlHandle>
    {
        auto handle = std::make_unique<NiceMock<MockCurlHandle>>();
        allowOtherOptions(*handle);
        ++callCount;

        if (callCount == 1)
        {
            EXPECT_CALL(*handle, setOptionString(CurlOption::CaInfo, "/etc/ssl/certs/ca-certificates.crt"));
            EXPECT_CALL(*handle, trustSelfSignedRoot()).Times(0);
            ON_CALL(*handle, perform()).WillByDefault(Return(TransportStatus::TlsFail));
            ON_CALL(*handle, tlsFailureDetail()).WillByDefault(Return(chainTrustFailure()));
        }
        else
        {
            EXPECT_CALL(*handle, setOptionString(CurlOption::CaInfo, "/var/ossec/etc/certs/root-ca.pem"));
            EXPECT_CALL(*handle, trustSelfSignedRoot()).WillOnce(Return(true));
            ON_CALL(*handle, perform()).WillByDefault(Return(TransportStatus::Ok));
        }

        return handle;
    };

    CurlPerformer performer {config, factory, fsProbe};
    const auto response = performer.perform(HttpRequestSpec {});

    EXPECT_EQ(TransportStatus::Ok, response.status);
    EXPECT_EQ(2, callCount);
}

// The mirror of the test above: the fallback anchor does not verify the manager either.
// Both trust sources are exhausted within the one call -- no third attempt, and the
// returned status is still a verification failure so the caller's normal fail-closed
// handling applies (the LOGFN_CRITICAL this path also emits is a no-op here: this test
// binary never assigns GLOBAL_LOG_FUNCTION, see tests/unit/main.cpp).
TEST(CurlPerformerTest, SystemModeReportsVerifyFailureWhenFallbackAlsoFails)
{
    auto config = makeConfig(HC_VERIFY_SYSTEM);
    config.systemFallbackCaPath = "/var/ossec/etc/certs/root-ca.pem";
    NiceMock<MockFsProbe> fsProbe;
    ON_CALL(fsProbe, findSystemCaBundle()).WillByDefault(Return("/etc/ssl/certs/ca-certificates.crt"));

    int callCount = 0;
    CurlHandleFactory factory = [&]() -> std::unique_ptr<ICurlHandle>
    {
        auto handle = std::make_unique<NiceMock<MockCurlHandle>>();
        allowOtherOptions(*handle);
        ++callCount;
        // Irrelevant on the first (OS-bundle) attempt -- not reached there -- and needed on
        // the second so applyTrustAnchors() lets the pinned fallback file's self-signed root
        // through to the perform() stub below, same as the success test above.
        ON_CALL(*handle, trustSelfSignedRoot()).WillByDefault(Return(true));
        ON_CALL(*handle, perform()).WillByDefault(Return(TransportStatus::TlsFail));
        // Both attempts see a certificate that fails to verify (sawDepth0 true) -- a genuine,
        // unclassified chain/CA-trust failure on the OS bundle AND the fallback anchor -- not
        // the sawDepth0-false shape a transport failure would leave.
        ON_CALL(*handle, tlsFailureDetail()).WillByDefault(Return(chainTrustFailure()));
        return handle;
    };

    CurlPerformer performer {config, factory, fsProbe};
    const auto response = performer.perform(HttpRequestSpec {});

    EXPECT_EQ(TransportStatus::TlsFail, response.status);
    EXPECT_EQ(TlsFailureKind::None, response.tlsFailure.kind);
    EXPECT_EQ(2, callCount); // OS bundle, then the fallback anchor -- never a third attempt.
}

// External review finding: a fallback anchor libcurl cannot even LOAD (missing, unreadable,
// not a certificate it can parse -- CURLE_SSL_CACERT_BADFILE) never reaches sawDepth0 (no
// chain to build without a loadable CA), so isUnclassifiedChainFailure() alone would never
// treat it as fallback-eligible-and-exhausted -- it would look exactly like a pure transport
// failure and just be retried forever with ordinary backoff, never reaching the fail-closed
// CRITICAL exit this module exists to reach. isCaFileLoadFailure() must catch this on its own,
// ahead of that gate, the very first time the fallback anchor is dialed and turns out unusable.
TEST(CurlPerformerTest, SystemModeFailsClosedWhenFallbackAnchorCannotBeLoaded)
{
    auto config = makeConfig(HC_VERIFY_SYSTEM);
    config.systemFallbackCaPath = "/var/ossec/etc/certs/root-ca.pem";
    NiceMock<MockFsProbe> fsProbe;
    ON_CALL(fsProbe, findSystemCaBundle()).WillByDefault(Return("/etc/ssl/certs/ca-certificates.crt"));

    int callCount = 0;
    CurlHandleFactory factory = [&]() -> std::unique_ptr<ICurlHandle>
    {
        auto handle = std::make_unique<NiceMock<MockCurlHandle>>();
        allowOtherOptions(*handle);
        ++callCount;

        if (callCount == 1)
        {
            // The OS bundle attempt: a genuine, unclassified chain-trust failure, exactly
            // like the fallback-succeeds test -- this is what makes perform() try the
            // fallback anchor at all.
            ON_CALL(*handle, perform()).WillByDefault(Return(TransportStatus::TlsFail));
            ON_CALL(*handle, tlsFailureDetail()).WillByDefault(Return(chainTrustFailure()));
        }
        else
        {
            // The fallback anchor itself cannot be loaded: sawDepth0 stays false (default
            // tlsFailureDetail()), but caFileLoadFailed is true.
            ON_CALL(*handle, perform()).WillByDefault(Return(TransportStatus::TlsFail));
            ON_CALL(*handle, caFileLoadFailed()).WillByDefault(Return(true));
        }

        return handle;
    };

    CurlPerformer performer {config, factory, fsProbe};
    const auto response = performer.perform(HttpRequestSpec {});

    EXPECT_EQ(TransportStatus::TlsFail, response.status);
    EXPECT_TRUE(response.caFileLoadFailed);
    EXPECT_FALSE(response.tlsFailure.sawDepth0); // Confirms isUnclassifiedChainFailure() alone
    // would not have caught this -- isCaFileLoadFailure() has to.
    EXPECT_EQ(2, callCount); // OS bundle, then the (unusable) fallback anchor -- never a third
    // attempt, and never silently retried as an ordinary Unreachable failure.
}

// The latched-call mirror of the test above: once a PREVIOUS call has already adopted the
// fallback anchor (m_usingSystemFallbackAnchor already true), a call that finds it unusable
// must fail closed on its own single attempt -- not silently keep retrying it forever, which
// is exactly what would happen if only isUnclassifiedChainFailure() (sawDepth0-gated) were
// checked, since a load failure never sets sawDepth0.
TEST(CurlPerformerTest, SystemModeFailsClosedOnLatchedCallWhenFallbackAnchorCannotBeLoaded)
{
    auto config = makeConfig(HC_VERIFY_SYSTEM);
    config.systemFallbackCaPath = "/var/ossec/etc/certs/root-ca.pem";
    NiceMock<MockFsProbe> fsProbe;
    // No OS bundle at all: the constructor pre-latches m_usingSystemFallbackAnchor, so this
    // call's one and only attempt is already against the (unusable) fallback anchor.
    ON_CALL(fsProbe, findSystemCaBundle()).WillByDefault(Return(""));

    int callCount = 0;
    CurlHandleFactory factory = [&]() -> std::unique_ptr<ICurlHandle>
    {
        auto handle = std::make_unique<NiceMock<MockCurlHandle>>();
        allowOtherOptions(*handle);
        ++callCount;
        ON_CALL(*handle, perform()).WillByDefault(Return(TransportStatus::TlsFail));
        ON_CALL(*handle, caFileLoadFailed()).WillByDefault(Return(true));
        return handle;
    };

    CurlPerformer performer {config, factory, fsProbe};
    const auto response = performer.perform(HttpRequestSpec {});

    EXPECT_EQ(TransportStatus::TlsFail, response.status);
    EXPECT_TRUE(response.caFileLoadFailed);
    EXPECT_EQ(1, callCount); // One attempt, fails closed immediately -- never retried.
}

// The merge with #39062 (isUnclassifiedChainFailure()): a hostname mismatch against the OS
// store must NOT trigger the fallback, warn, or retry -- trying a different trust anchor can
// never fix a name mismatch, only a chain/CA-trust problem. One attempt, and the classified
// TlsFail is returned exactly as #39062's own classifier reported it.
TEST(CurlPerformerTest, SystemModeDoesNotFallBackOnAClassifiedFailure)
{
    auto config = makeConfig(HC_VERIFY_SYSTEM);
    config.systemFallbackCaPath = "/var/ossec/etc/certs/root-ca.pem";
    NiceMock<MockFsProbe> fsProbe;
    ON_CALL(fsProbe, findSystemCaBundle()).WillByDefault(Return("/etc/ssl/certs/ca-certificates.crt"));

    TlsFailureDetail hostnameMismatch;
    hostnameMismatch.kind = TlsFailureKind::HostnameMismatch;

    int callCount = 0;
    CurlHandleFactory factory = [&]() -> std::unique_ptr<ICurlHandle>
    {
        auto handle = std::make_unique<NiceMock<MockCurlHandle>>();
        allowOtherOptions(*handle);
        ++callCount;
        ON_CALL(*handle, perform()).WillByDefault(Return(TransportStatus::TlsFail));
        ON_CALL(*handle, tlsFailureDetail()).WillByDefault(Return(hostnameMismatch));
        return handle;
    };

    CurlPerformer performer {config, factory, fsProbe};
    const auto response = performer.perform(HttpRequestSpec {});

    EXPECT_EQ(TransportStatus::TlsFail, response.status);
    EXPECT_EQ(TlsFailureKind::HostnameMismatch, response.tlsFailure.kind);
    EXPECT_EQ(1, callCount); // Never retried against the fallback anchor.
}

// Without a fallback path configured, an unclassified TlsFail is exactly today's final
// result: one attempt, no retry, whatever failed the OS bundle check is what the caller sees.
TEST(CurlPerformerTest, SystemModeDoesNotRetryWithoutAFallbackPathConfigured)
{
    auto config = makeConfig(HC_VERIFY_SYSTEM); // systemFallbackCaPath left empty.
    NiceMock<MockFsProbe> fsProbe;
    ON_CALL(fsProbe, findSystemCaBundle()).WillByDefault(Return("/etc/ssl/certs/ca-certificates.crt"));

    int callCount = 0;
    CurlHandleFactory factory = [&]() -> std::unique_ptr<ICurlHandle>
    {
        auto handle = std::make_unique<NiceMock<MockCurlHandle>>();
        allowOtherOptions(*handle);
        ++callCount;
        ON_CALL(*handle, perform()).WillByDefault(Return(TransportStatus::TlsFail));
        // A genuine unclassified chain/CA-trust failure (isUnclassifiedChainFailure() would
        // otherwise be eligible): this test's point is that systemFallbackCaPath being empty
        // is what stops the retry, not that the failure itself was ineligible.
        ON_CALL(*handle, tlsFailureDetail()).WillByDefault(Return(chainTrustFailure()));
        return handle;
    };

    CurlPerformer performer {config, factory, fsProbe};
    const auto response = performer.perform(HttpRequestSpec {});

    EXPECT_EQ(TransportStatus::TlsFail, response.status);
    EXPECT_EQ(TlsFailureKind::None, response.tlsFailure.kind);
    EXPECT_EQ(1, callCount);
}

// A TlsFail that never reached certificate inspection at all (sawDepth0 false -- a
// cipher-negotiation failure, a mid-handshake reset, a corrupt local CA file: none of them a
// chain/CA-trust problem) must NOT trigger the fallback, the WARN, or the eventual
// LOGFN_CRITICAL: retrying against a different anchor cannot fix a failure that has nothing to
// do with which anchor was configured, and treating two such transient failures as "neither
// trust source works" would kill the agent over what any other verify_mode leaves as an
// ordinary Unreachable/retry-with-backoff outcome. One attempt, whatever the OS bundle attempt
// returned is what the caller sees -- exactly like SystemModeDoesNotFallBackOnAClassifiedFailure,
// but for the OTHER situation that also leaves tlsFailure.kind == None.
TEST(CurlPerformerTest, SystemModeDoesNotFallBackOnATransportFailureThatNeverReachedTheCertificate)
{
    auto config = makeConfig(HC_VERIFY_SYSTEM);
    config.systemFallbackCaPath = "/var/ossec/etc/certs/root-ca.pem";
    NiceMock<MockFsProbe> fsProbe;
    ON_CALL(fsProbe, findSystemCaBundle()).WillByDefault(Return("/etc/ssl/certs/ca-certificates.crt"));

    int callCount = 0;
    CurlHandleFactory factory = [&]() -> std::unique_ptr<ICurlHandle>
    {
        auto handle = std::make_unique<NiceMock<MockCurlHandle>>();
        allowOtherOptions(*handle);
        ++callCount;
        ON_CALL(*handle, perform()).WillByDefault(Return(TransportStatus::TlsFail));
        // Default tlsFailureDetail(): kind None AND sawDepth0 false -- a certificate was
        // never even seen, unlike chainTrustFailure() above.
        return handle;
    };

    CurlPerformer performer {config, factory, fsProbe};
    const auto response = performer.perform(HttpRequestSpec {});

    EXPECT_EQ(TransportStatus::TlsFail, response.status);
    EXPECT_EQ(TlsFailureKind::None, response.tlsFailure.kind);
    EXPECT_FALSE(response.tlsFailure.sawDepth0);
    EXPECT_EQ(1, callCount); // Never retried against the fallback anchor.
}

// contrarian-reviewer round: sawDepth0 alone is not enough. A certificate CAN be inspected
// and verify cleanly (depth0VerificationFailed false) while the overall attempt still ends in
// TlsFail for a reason unrelated to the certificate -- one of the non-PEER_FAILED_VERIFICATION
// codes statusFromCurlCode() also buckets into TlsFail (a cipher/protocol failure after an
// already-accepted certificate, say). Retrying against a different trust anchor could never
// fix that, since the certificate was never the problem -- this must stay on the ordinary
// Unreachable/retry path, exactly like the sawDepth0-false and classified-kind cases above.
TEST(CurlPerformerTest, SystemModeDoesNotFallBackWhenTheCertificateVerifiedButSomethingElseFailed)
{
    auto config = makeConfig(HC_VERIFY_SYSTEM);
    config.systemFallbackCaPath = "/var/ossec/etc/certs/root-ca.pem";
    NiceMock<MockFsProbe> fsProbe;
    ON_CALL(fsProbe, findSystemCaBundle()).WillByDefault(Return("/etc/ssl/certs/ca-certificates.crt"));

    int callCount = 0;
    CurlHandleFactory factory = [&]() -> std::unique_ptr<ICurlHandle>
    {
        auto handle = std::make_unique<NiceMock<MockCurlHandle>>();
        allowOtherOptions(*handle);
        ++callCount;
        ON_CALL(*handle, perform()).WillByDefault(Return(TransportStatus::TlsFail));
        ON_CALL(*handle, tlsFailureDetail()).WillByDefault(Return(chainVerifiedButUnrelatedFailure()));
        return handle;
    };

    CurlPerformer performer {config, factory, fsProbe};
    const auto response = performer.perform(HttpRequestSpec {});

    EXPECT_EQ(TransportStatus::TlsFail, response.status);
    EXPECT_EQ(TlsFailureKind::None, response.tlsFailure.kind);
    EXPECT_TRUE(response.tlsFailure.sawDepth0);
    EXPECT_FALSE(response.tlsFailure.depth0VerificationFailed);
    EXPECT_EQ(1, callCount); // Never retried against the fallback anchor.
}

// External review finding: sawDepth0 + depth0VerificationFailed alone still let through any
// depth0Error besides the two #39062 explicitly classifies -- including X.509 outcomes that
// are not chain/CA-trust problems at all (an unsupported certificate purpose, a policy/
// extension issue). A different trust anchor could never fix those, so they must stay off the
// fallback path exactly like a hostname mismatch or a certificate-date problem do.
TEST(CurlPerformerTest, SystemModeDoesNotFallBackOnADepth0ErrorUnrelatedToChainTrust)
{
    auto config = makeConfig(HC_VERIFY_SYSTEM);
    config.systemFallbackCaPath = "/var/ossec/etc/certs/root-ca.pem";
    NiceMock<MockFsProbe> fsProbe;
    ON_CALL(fsProbe, findSystemCaBundle()).WillByDefault(Return("/etc/ssl/certs/ca-certificates.crt"));

    int callCount = 0;
    CurlHandleFactory factory = [&]() -> std::unique_ptr<ICurlHandle>
    {
        auto handle = std::make_unique<NiceMock<MockCurlHandle>>();
        allowOtherOptions(*handle);
        ++callCount;
        ON_CALL(*handle, perform()).WillByDefault(Return(TransportStatus::TlsFail));
        ON_CALL(*handle, tlsFailureDetail()).WillByDefault(Return(chainTrustUnrelatedDepth0Error()));
        return handle;
    };

    CurlPerformer performer {config, factory, fsProbe};
    const auto response = performer.perform(HttpRequestSpec {});

    EXPECT_EQ(TransportStatus::TlsFail, response.status);
    EXPECT_EQ(TlsFailureKind::None, response.tlsFailure.kind);
    EXPECT_TRUE(response.tlsFailure.sawDepth0);
    EXPECT_TRUE(response.tlsFailure.depth0VerificationFailed);
    EXPECT_FALSE(response.tlsFailure.depth0ErrorIsChainTrustRelated);
    EXPECT_EQ(1, callCount); // Never retried against the fallback anchor.
}

// #39123 follow-up: closes the former KNOWN LIMITATION -- a chain-trust rejection above depth
// 0 (an untrusted intermediate/root, discovered before OpenSSL's verify callback ever reaches
// the leaf) must still trigger the fallback, exactly like a depth-0 rejection does.
TEST(CurlPerformerTest, SystemModeFallsBackOnAChainTrustRejectionAboveDepth0)
{
    auto config = makeConfig(HC_VERIFY_SYSTEM);
    config.systemFallbackCaPath = "/var/ossec/etc/certs/root-ca.pem";
    NiceMock<MockFsProbe> fsProbe;
    ON_CALL(fsProbe, findSystemCaBundle()).WillByDefault(Return("/etc/ssl/certs/ca-certificates.crt"));

    int callCount = 0;
    CurlHandleFactory factory = [&]() -> std::unique_ptr<ICurlHandle>
    {
        auto handle = std::make_unique<NiceMock<MockCurlHandle>>();
        allowOtherOptions(*handle);
        ++callCount;

        if (callCount == 1)
        {
            // The OS bundle attempt: OpenSSL's chain builder rejects an untrusted
            // intermediate/root before ever reaching depth 0 -- sawDepth0 stays false.
            ON_CALL(*handle, perform()).WillByDefault(Return(TransportStatus::TlsFail));
            ON_CALL(*handle, tlsFailureDetail()).WillByDefault(Return(chainTrustRejectedAboveDepth0()));
        }
        else
        {
            ON_CALL(*handle, perform()).WillByDefault(Return(TransportStatus::Ok));
        }

        return handle;
    };

    CurlPerformer performer {config, factory, fsProbe};
    const auto response = performer.perform(HttpRequestSpec {});

    EXPECT_EQ(TransportStatus::Ok, response.status);
    EXPECT_EQ(2, callCount); // OS bundle, then the fallback anchor -- the retry engaged.
}

// #39123 follow-up: the fallback retry must not silently double a caller's timeout budget.
// ControlStream::sendShutdown() passes drain_timeout_ms as spec.timeoutMs specifically so an
// unreachable manager cannot stall shutdown -- a hidden second full-length attempt against the
// fallback anchor would defeat that. The second attemptOnce() must be timed against what is
// LEFT of spec.timeoutMs once the first attempt is done, not a fresh copy of it.
TEST(CurlPerformerTest, SystemModeShrinksTheFallbackAttemptsTimeoutByWhatTheFirstAttemptSpent)
{
    auto config = makeConfig(HC_VERIFY_SYSTEM);
    config.systemFallbackCaPath = "/var/ossec/etc/certs/root-ca.pem";
    NiceMock<MockFsProbe> fsProbe;
    ON_CALL(fsProbe, findSystemCaBundle()).WillByDefault(Return("/etc/ssl/certs/ca-certificates.crt"));

    FakeClock clock;
    int callCount = 0;
    CurlHandleFactory factory = [&]() -> std::unique_ptr<ICurlHandle>
    {
        auto handle = std::make_unique<NiceMock<MockCurlHandle>>();
        allowOtherOptions(*handle);
        ++callCount;

        if (callCount == 1)
        {
            // The OS bundle attempt: a genuine chain-trust failure (what makes perform() try
            // the fallback at all), simulated as having spent 600 ms of the 5000 ms budget.
            EXPECT_CALL(*handle, setOptionLong(CurlOption::TimeoutMs, 5000L));
            ON_CALL(*handle, perform())
            .WillByDefault(DoAll(InvokeWithoutArgs([&clock] { clock.advance(std::chrono::milliseconds {600}); }),
            Return(TransportStatus::TlsFail)));
            ON_CALL(*handle, tlsFailureDetail()).WillByDefault(Return(chainTrustFailure()));
        }
        else
        {
            // The fallback attempt: only 4400 ms of the original 5000 ms budget remain.
            EXPECT_CALL(*handle, setOptionLong(CurlOption::TimeoutMs, 4400L));
            ON_CALL(*handle, perform()).WillByDefault(Return(TransportStatus::Ok));
        }

        return handle;
    };

    CurlPerformer performer {config, factory, fsProbe, clock};
    HttpRequestSpec spec;
    spec.timeoutMs = 5000;
    const auto response = performer.perform(spec);

    EXPECT_EQ(TransportStatus::Ok, response.status);
    EXPECT_EQ(2, callCount);
}

// The budget can also run out entirely: a first attempt that alone consumes the whole
// spec.timeoutMs leaves nothing for a second real network attempt. Passing the leftover (0)
// through unmodified would hit CURLOPT_TIMEOUT_MS's documented "0 = never time out" default --
// trading a bounded doubled wait for an unbounded one -- so the fallback attempt must be
// skipped entirely and the OS-store failure returned as-is.
TEST(CurlPerformerTest, SystemModeSkipsTheFallbackAttemptWhenNoBudgetRemains)
{
    auto config = makeConfig(HC_VERIFY_SYSTEM);
    config.systemFallbackCaPath = "/var/ossec/etc/certs/root-ca.pem";
    NiceMock<MockFsProbe> fsProbe;
    ON_CALL(fsProbe, findSystemCaBundle()).WillByDefault(Return("/etc/ssl/certs/ca-certificates.crt"));

    FakeClock clock;
    int callCount = 0;
    CurlHandleFactory factory = [&]() -> std::unique_ptr<ICurlHandle>
    {
        auto handle = std::make_unique<NiceMock<MockCurlHandle>>();
        allowOtherOptions(*handle);
        ++callCount;
        // The OS bundle attempt alone consumes the entire 5000 ms budget.
        ON_CALL(*handle, perform())
        .WillByDefault(DoAll(InvokeWithoutArgs([&clock] { clock.advance(std::chrono::milliseconds {5000}); }),
        Return(TransportStatus::TlsFail)));
        ON_CALL(*handle, tlsFailureDetail()).WillByDefault(Return(chainTrustFailure()));
        return handle;
    };

    CurlPerformer performer {config, factory, fsProbe, clock};
    HttpRequestSpec spec;
    spec.timeoutMs = 5000;
    const auto response = performer.perform(spec);

    EXPECT_EQ(TransportStatus::TlsFail, response.status);
    EXPECT_TRUE(response.tlsFailure.sawDepth0);
    EXPECT_EQ(1, callCount); // The fallback anchor is never dialed: no budget left for it.
}

// Code-review finding: when a call returns early because no timeout budget remains (as
// above), it must not latch m_usingSystemFallbackAnchor either -- that call never actually
// dialed the fallback anchor, so it has zero evidence the anchor can verify anything.
// Latching here anyway would permanently commit every later call/thread on this object to
// the fallback anchor based on nothing but this call's own timing, risking a spurious
// "neither trust source works" exit on some later, unrelated request whose OS-store attempt
// would otherwise have succeeded fine. Proven by making a SECOND perform() call afterward and
// confirming its own first attempt still dials the OS bundle, not the fallback anchor.
TEST(CurlPerformerTest, SystemModeDoesNotLatchTheFallbackWhenNoBudgetRemains)
{
    auto config = makeConfig(HC_VERIFY_SYSTEM);
    config.systemFallbackCaPath = "/var/ossec/etc/certs/root-ca.pem";
    NiceMock<MockFsProbe> fsProbe;
    ON_CALL(fsProbe, findSystemCaBundle()).WillByDefault(Return("/etc/ssl/certs/ca-certificates.crt"));

    FakeClock clock;
    int callCount = 0;
    CurlHandleFactory factory = [&]() -> std::unique_ptr<ICurlHandle>
    {
        auto handle = std::make_unique<NiceMock<MockCurlHandle>>();
        allowOtherOptions(*handle);
        ++callCount;

        if (callCount == 1)
        {
            // First perform() call: the OS bundle attempt alone consumes the entire budget,
            // so this call returns without ever dialing the fallback anchor.
            EXPECT_CALL(*handle, setOptionString(CurlOption::CaInfo, "/etc/ssl/certs/ca-certificates.crt"));
            ON_CALL(*handle, perform())
            .WillByDefault(DoAll(InvokeWithoutArgs([&clock] { clock.advance(std::chrono::milliseconds {5000}); }),
            Return(TransportStatus::TlsFail)));
            ON_CALL(*handle, tlsFailureDetail()).WillByDefault(Return(chainTrustFailure()));
        }
        else
        {
            // Second perform() call, a separate request entirely: if the latch had been set
            // by the first call despite never trying the fallback, this attempt would dial
            // systemFallbackCaPath instead -- asserting the OS bundle path here is what
            // actually catches that.
            EXPECT_CALL(*handle, setOptionString(CurlOption::CaInfo, "/etc/ssl/certs/ca-certificates.crt"));
            ON_CALL(*handle, perform()).WillByDefault(Return(TransportStatus::Ok));
        }

        return handle;
    };

    CurlPerformer performer {config, factory, fsProbe, clock};
    HttpRequestSpec spec;
    spec.timeoutMs = 5000;

    const auto firstResponse = performer.perform(spec);
    EXPECT_EQ(TransportStatus::TlsFail, firstResponse.status);
    EXPECT_EQ(1, callCount);

    const auto secondResponse = performer.perform(spec);
    EXPECT_EQ(TransportStatus::Ok, secondResponse.status);
    EXPECT_EQ(2, callCount); // A single attempt against the OS bundle -- not the fallback.
}

// #39123: when no OS bundle exists on this system at all, there is nothing for a first
// attempt to dial "against the OS store" -- the constructor seeds caPath with the fallback
// anchor directly and starts already latched onto it, rather than leaving caPath empty (which
// would silently fall back to libcurl/OpenSSL's own default trust store, undocumented and not
// what the fallback log line describes -- see the constructor's comment). So this is ONE
// attempt, using the fallback anchor's CaInfo and its self-signed-root relaxation from the
// start, not a WARN-then-retry dance.
TEST(CurlPerformerTest, SystemModeUsesFallbackAnchorDirectlyWhenNoOsBundleExists)
{
    auto config = makeConfig(HC_VERIFY_SYSTEM);
    config.systemFallbackCaPath = "/var/ossec/etc/certs/root-ca.pem";
    NiceMock<MockFsProbe> fsProbe;
    ON_CALL(fsProbe, findSystemCaBundle()).WillByDefault(Return("")); // No OS bundle found.

    int callCount = 0;
    CurlHandleFactory factory = [&]() -> std::unique_ptr<ICurlHandle>
    {
        auto handle = std::make_unique<NiceMock<MockCurlHandle>>();
        allowOtherOptions(*handle);
        ++callCount;
        EXPECT_CALL(*handle, setOptionString(CurlOption::CaInfo, "/var/ossec/etc/certs/root-ca.pem"));
        EXPECT_CALL(*handle, trustSelfSignedRoot()).WillOnce(Return(true));
        ON_CALL(*handle, perform()).WillByDefault(Return(TransportStatus::Ok));
        return handle;
    };

    CurlPerformer performer {config, factory, fsProbe};
    const auto response = performer.perform(HttpRequestSpec {});

    EXPECT_EQ(TransportStatus::Ok, response.status);
    EXPECT_EQ(1, callCount); // No OS store to try first -- one attempt, not two.
}

// The failure mirror of the test above (code-config-reviewer, round 5): with no OS bundle at
// all, the one and only attempt is already against the fallback anchor -- if THAT fails too,
// perform() must still reach the LOGFN_CRITICAL/exit(1) path (never retry a second time, since
// there was never a second trust source to try), and it must do so with wording that does not
// claim an OS trust store was consulted (noOsStoreToTry() in curlPerformer.hpp) -- this test
// pins the observable half of that (one attempt, TlsFail out); the log text itself is not
// capturable from this mock-based suite, see the component test for the real-TLS coverage.
TEST(CurlPerformerTest, SystemModeReportsVerifyFailureDirectlyWhenNoOsBundleExists)
{
    auto config = makeConfig(HC_VERIFY_SYSTEM);
    config.systemFallbackCaPath = "/var/ossec/etc/certs/root-ca.pem";
    NiceMock<MockFsProbe> fsProbe;
    ON_CALL(fsProbe, findSystemCaBundle()).WillByDefault(Return("")); // No OS bundle found.

    int callCount = 0;
    CurlHandleFactory factory = [&]() -> std::unique_ptr<ICurlHandle>
    {
        auto handle = std::make_unique<NiceMock<MockCurlHandle>>();
        allowOtherOptions(*handle);
        ++callCount;
        EXPECT_CALL(*handle, setOptionString(CurlOption::CaInfo, "/var/ossec/etc/certs/root-ca.pem"));
        ON_CALL(*handle, trustSelfSignedRoot()).WillByDefault(Return(true));
        ON_CALL(*handle, perform()).WillByDefault(Return(TransportStatus::TlsFail));
        ON_CALL(*handle, tlsFailureDetail()).WillByDefault(Return(chainTrustFailure()));
        return handle;
    };

    CurlPerformer performer {config, factory, fsProbe};
    const auto response = performer.perform(HttpRequestSpec {});

    EXPECT_EQ(TransportStatus::TlsFail, response.status);
    EXPECT_EQ(TlsFailureKind::None, response.tlsFailure.kind);
    EXPECT_EQ(1, callCount); // Never a second attempt -- there was only ever one trust source.
}

// #39123, second review round: one perform() call must judge its OWN attempt against the
// trust anchor IT actually dialed, never against whatever m_usingSystemFallbackAnchor says by
// the time it gets around to interpreting the response -- another thread can flip that flag
// while this call's first attempt is still in flight (HttpsClientFacade's four streams share
// one CurlPerformer). An earlier version of the fix re-read the flag after the fact and could
// send a call straight to LOGFN_CRITICAL on a fallback it had never itself tried, just because
// a concurrent call had already adopted it. Reproduced deterministically (not via timing, per
// this module's own lesson from #38440/SkewCorrectedClock: races this narrow are not reliably
// hit by chance, real or stress-tested) by blocking "thread B"'s first handle mid-flight until
// "thread A" has completed an entire fail -> flip -> retry-succeeds cycle on its own.
TEST(CurlPerformerTest, SystemModeConcurrentCallerJudgesItsOwnAttemptNotAnotherThreadsFlag)
{
    auto config = makeConfig(HC_VERIFY_SYSTEM);
    config.systemFallbackCaPath = "/var/ossec/etc/certs/root-ca.pem";
    NiceMock<MockFsProbe> fsProbe;
    ON_CALL(fsProbe, findSystemCaBundle()).WillByDefault(Return("/etc/ssl/certs/ca-certificates.crt"));

    std::promise<void> bEnteredPromise;
    std::future<void> bEntered = bEnteredPromise.get_future();
    std::promise<void> aFinishedPromise;
    std::shared_future<void> aFinished = aFinishedPromise.get_future();

    const std::thread::id mainThreadId = std::this_thread::get_id();
    std::atomic<int> bCallCount {0};
    int aCallCount = 0; // Only ever touched from mainThreadId, and never concurrently with
    // itself -- B's calls take the other branch below.
    std::mutex handleConstructionMutex; // MockCurlHandle/gmock bookkeeping isn't thread-safe.

    CurlHandleFactory factory = [&]() -> std::unique_ptr<ICurlHandle>
    {
        std::unique_ptr<NiceMock<MockCurlHandle>> handle;
        {
            const std::lock_guard<std::mutex> lock(handleConstructionMutex);
            handle = std::make_unique<NiceMock<MockCurlHandle>>();
            allowOtherOptions(*handle);
        }

        if (std::this_thread::get_id() != mainThreadId)
        {
            // Thread B.
            if (bCallCount.fetch_add(1) == 0)
            {
                // B's first attempt: exists, but must not resolve until A has completely
                // finished adopting the fallback -- this is the exact window the bug lived
                // in. B is paused here, before applyTls()/applyTrustAnchors() ever run for
                // this attempt, so nothing of B's has touched shared state yet. By the time
                // it wakes up (below), the shared flag already reads true -- so this is the
                // one EXPECT_CALL in the whole test that actually distinguishes "read the
                // parameter" from "read the flag": a regression to the latter would dial the
                // fallback path here instead, failing this expectation, even though the
                // final Ok/call-count shape would otherwise look identical either way.
                bEnteredPromise.set_value();
                aFinished.wait();
                EXPECT_CALL(*handle, setOptionString(CurlOption::CaInfo, "/etc/ssl/certs/ca-certificates.crt"));
                ON_CALL(*handle, perform()).WillByDefault(Return(TransportStatus::TlsFail));
                ON_CALL(*handle, tlsFailureDetail()).WillByDefault(Return(chainTrustFailure()));
                return handle;
            }

            // B's own retry, once it wakes up and judges its own (just-returned) TlsFail
            // on its own captured snapshot rather than the now-flipped flag.
            EXPECT_CALL(*handle, setOptionString(CurlOption::CaInfo, "/var/ossec/etc/certs/root-ca.pem"));
            ON_CALL(*handle, trustSelfSignedRoot()).WillByDefault(Return(true));
            ON_CALL(*handle, perform()).WillByDefault(Return(TransportStatus::Ok));
            return handle;
        }

        // Thread A (this runs on the main thread, synchronously, only after B has confirmed
        // it is blocked inside its first attempt -- see bEntered.wait() below).
        if (aCallCount++ == 0)
        {
            EXPECT_CALL(*handle, setOptionString(CurlOption::CaInfo, "/etc/ssl/certs/ca-certificates.crt"));
            ON_CALL(*handle, perform()).WillByDefault(Return(TransportStatus::TlsFail));
            ON_CALL(*handle, tlsFailureDetail()).WillByDefault(Return(chainTrustFailure()));
        }
        else
        {
            EXPECT_CALL(*handle, setOptionString(CurlOption::CaInfo, "/var/ossec/etc/certs/root-ca.pem"));
            ON_CALL(*handle, trustSelfSignedRoot()).WillByDefault(Return(true));
            ON_CALL(*handle, perform()).WillByDefault(Return(TransportStatus::Ok));
        }

        return handle;
    };

    CurlPerformer performer {config, factory, fsProbe};

    std::thread threadB(
        [&]()
    {
        const auto response = performer.perform(HttpRequestSpec {});
        EXPECT_EQ(TransportStatus::Ok, response.status)
                << "Thread B must retry against the fallback on its OWN evidence, not skip "
                "straight to critical because thread A already flipped the flag mid-flight.";
    });

    bEntered.wait(); // Do not start "thread A" until B is confirmed blocked inside its first
    // attempt -- otherwise which thread's factory call lands first is a race
    // in the test itself, not just in the code under test.
    const auto responseA = performer.perform(HttpRequestSpec {});
    EXPECT_EQ(TransportStatus::Ok, responseA.status);
    aFinishedPromise.set_value(); // Let B's first attempt resolve, now that the flag is true.

    threadB.join();
}
#endif

// #39123 follow-up (coverage gap): every SystemMode* test above is guarded to Linux only,
// because each relies on the CONSTRUCTOR's OS-bundle auto-resolution (resolveSystemCaBundle(),
// itself Linux-only -- Windows/macOS ask OpenSSL to consult the native store instead, via
// TLS_NATIVE_CA_STORE, never a CAINFO file; see applyTrustAnchors()). But the retry mechanism
// itself -- perform()'s isUnclassifiedChainFailure() gate, the WARN-then-retry branch, and
// applyTrustAnchors()'s CAINFO branch for the fallback anchor -- carries no #ifdef at all and
// runs identically on every platform once caPath already names a trust source, however it got
// there (an explicit bundle path on Linux, or the same fallback triggering after a native-store
// verification failure elsewhere). This test exercises that mechanism directly, setting
// config.caPath by hand -- the same platform-agnostic pattern TrustAnchorsWithConfiguredCa
// above already uses -- rather than through the Linux-only auto-resolution, so it compiles and
// runs on every platform and closes the coverage gap for the part of #39123 that is not
// actually platform-specific.
TEST(CurlPerformerTest, SystemModeFallsBackRegardlessOfPlatform)
{
    auto config = makeConfig(HC_VERIFY_SYSTEM);
    // Stands in for whatever trust source the first attempt actually used (an explicit OS
    // bundle path on Linux; on Windows/macOS the first attempt would instead go through
    // TLS_NATIVE_CA_STORE, but the resulting isUnclassifiedChainFailure() classification and
    // the retry branch below are exactly the same either way) -- applyTrustAnchors() does not
    // care how caPath came to be non-empty, only that it is.
    config.caPath = "/etc/ssl/certs/ca-certificates.crt";
    config.systemFallbackCaPath = "/var/ossec/etc/certs/root-ca.pem";

    int callCount = 0;
    CurlHandleFactory factory = [&]() -> std::unique_ptr<ICurlHandle>
    {
        auto handle = std::make_unique<NiceMock<MockCurlHandle>>();
        allowOtherOptions(*handle);
        ++callCount;

        if (callCount == 1)
        {
            EXPECT_CALL(*handle, setOptionString(CurlOption::CaInfo, "/etc/ssl/certs/ca-certificates.crt"));
            ON_CALL(*handle, perform()).WillByDefault(Return(TransportStatus::TlsFail));
            ON_CALL(*handle, tlsFailureDetail()).WillByDefault(Return(chainTrustFailure()));
        }
        else
        {
            EXPECT_CALL(*handle, setOptionString(CurlOption::CaInfo, "/var/ossec/etc/certs/root-ca.pem"));
            ON_CALL(*handle, perform()).WillByDefault(Return(TransportStatus::Ok));
        }

        return handle;
    };

    CurlPerformer performer {config, factory}; // 2-arg: no fsProbe, no platform-gated ctor path.
    const auto response = performer.perform(HttpRequestSpec {});

    EXPECT_EQ(TransportStatus::Ok, response.status);
    EXPECT_EQ(2, callCount);
}

// Platform-agnostic counterpart of SystemModeDoesNotLatchTheFallbackWhenNoBudgetRemains above
// (CI coverage finding): that test is Linux-only-guarded because it relies on the
// constructor's fsProbe-driven auto-resolution of caPath, but the actual behavior under test
// -- perform()'s latch/budget-check ordering -- carries no platform #ifdef at all. Same
// platform-agnostic pattern as SystemModeFallsBackRegardlessOfPlatform just above: caPath is
// set by hand, bypassing the Linux-only auto-resolution entirely.
//
// Exhausts the budget TWICE in a row before succeeding (a second contrarian-reviewer finding
// on this same test): a single exhausted call only exercises m_budgetExhaustedWarned's WARN
// branch (exchange() sees false the first time) -- the DEBUG1 branch (exchange() seeing true
// on a second, still-exhausted call) was otherwise never covered by any test in this file,
// guarded or not, leaving the actual "warn once, then debug" behavior round 12 of this same
// fix chain introduced completely unverified.
TEST(CurlPerformerTest, SystemModeDoesNotLatchTheFallbackWhenNoBudgetRemainsRegardlessOfPlatform)
{
    auto config = makeConfig(HC_VERIFY_SYSTEM);
    config.caPath = "/etc/ssl/certs/ca-certificates.crt";
    config.systemFallbackCaPath = "/var/ossec/etc/certs/root-ca.pem";

    FakeClock clock;
    int callCount = 0;
    CurlHandleFactory factory = [&]() -> std::unique_ptr<ICurlHandle>
    {
        auto handle = std::make_unique<NiceMock<MockCurlHandle>>();
        allowOtherOptions(*handle);
        ++callCount;

        if (callCount <= 2)
        {
            // First AND second perform() calls: the OS bundle attempt alone consumes the
            // entire budget both times, so neither ever dials the fallback anchor. The first
            // exercises m_budgetExhaustedWarned's WARN branch, the second its DEBUG1 branch.
            EXPECT_CALL(*handle, setOptionString(CurlOption::CaInfo, "/etc/ssl/certs/ca-certificates.crt"));
            ON_CALL(*handle, perform())
            .WillByDefault(DoAll(InvokeWithoutArgs([&clock] { clock.advance(std::chrono::milliseconds {5000}); }),
            Return(TransportStatus::TlsFail)));
            ON_CALL(*handle, tlsFailureDetail()).WillByDefault(Return(chainTrustFailure()));
        }
        else
        {
            // Third perform() call, a separate request entirely: if the latch had been set by
            // either of the first two calls despite neither ever trying the fallback, this
            // attempt would dial systemFallbackCaPath instead -- asserting the OS bundle path
            // here is what actually catches that.
            EXPECT_CALL(*handle, setOptionString(CurlOption::CaInfo, "/etc/ssl/certs/ca-certificates.crt"));
            ON_CALL(*handle, perform()).WillByDefault(Return(TransportStatus::Ok));
        }

        return handle;
    };

    NiceMock<MockFsProbe> fsProbe; // Unused: caPath is already non-empty, so the Linux-only
    // auto-resolution never calls findSystemCaBundle() -- required only because this is the
    // one constructor overload that also takes an injectable clock.
    CurlPerformer performer {config, factory, fsProbe, clock};
    HttpRequestSpec spec;
    spec.timeoutMs = 5000;

    const auto firstResponse = performer.perform(spec);
    EXPECT_EQ(TransportStatus::TlsFail, firstResponse.status);
    EXPECT_EQ(1, callCount);

    const auto secondResponse = performer.perform(spec);
    EXPECT_EQ(TransportStatus::TlsFail, secondResponse.status);
    EXPECT_EQ(2, callCount);

    const auto thirdResponse = performer.perform(spec);
    EXPECT_EQ(TransportStatus::Ok, thirdResponse.status);
    EXPECT_EQ(3, callCount); // A single attempt against the OS bundle -- not the fallback.
}

// m_noFallbackAnchorWarned gates the WARN only, never the outcome: a later call still makes its
// own single attempt and returns the same failure. The WARN itself is not assertable here --
// main.cpp leaves Log::GLOBAL_LOG_FUNCTION unset, so every LOGFN_* is a no-op in this binary.
TEST(CurlPerformerTest, SystemModeStillDoesNotRetryOnLaterCallsWithoutAFallbackPathConfigured)
{
    auto config = makeConfig(HC_VERIFY_SYSTEM); // systemFallbackCaPath left empty.
    // Set by hand, bypassing the Linux-only constructor auto-resolution: the branch under test
    // carries no platform #ifdef.
    config.caPath = "/etc/ssl/certs/ca-certificates.crt";

    int callCount = 0;
    CurlHandleFactory factory = [&]() -> std::unique_ptr<ICurlHandle>
    {
        auto handle = std::make_unique<NiceMock<MockCurlHandle>>();
        allowOtherOptions(*handle);
        ++callCount;
        ON_CALL(*handle, perform()).WillByDefault(Return(TransportStatus::TlsFail));
        ON_CALL(*handle, tlsFailureDetail()).WillByDefault(Return(chainTrustFailure()));
        return handle;
    };

    CurlPerformer performer {config, factory};

    const auto firstResponse = performer.perform(HttpRequestSpec {});
    EXPECT_EQ(TransportStatus::TlsFail, firstResponse.status);
    EXPECT_EQ(1, callCount);

    // The call that finds the latch already set.
    const auto secondResponse = performer.perform(HttpRequestSpec {});
    EXPECT_EQ(TransportStatus::TlsFail, secondResponse.status);
    EXPECT_EQ(TlsFailureKind::None, secondResponse.tlsFailure.kind);
    EXPECT_EQ(2, callCount);
}

TEST(CurlPerformerTest, FileBodyStreamsInsteadOfPostFields)
{
    const std::string path = ::testing::TempDir() + "hc_curl_performer_body.tmp";
    {
        std::ofstream file {path, std::ios::binary};
        file << "SESSION-BYTES";
    }

    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);

    HttpRequestSpec spec;
    spec.target = "/stateful";
    spec.bodyFilePath = path;
    spec.bodyFileSize = 13;

    EXPECT_CALL(*handle, streamBodyFromFile(NotNull(), 13u));
    EXPECT_CALL(*handle, setOptionPtr(CurlOption::PostFields, _)).Times(0);
    EXPECT_CALL(*handle, perform()).WillOnce(Return(TransportStatus::Ok));

    auto performer = makePerformer(makeConfig(HC_VERIFY_NONE), std::move(mock));
    const auto response = performer.perform(spec);
    EXPECT_EQ(TransportStatus::Ok, response.status);
    std::remove(path.c_str());
}

TEST(CurlPerformerTest, MissingBodyFileFailsWithoutPerforming)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    EXPECT_CALL(*handle, perform()).Times(0);

    HttpRequestSpec spec;
    spec.target = "/stateful";
    spec.bodyFilePath = "/nonexistent/hc-spool/session.bin";

    auto performer = makePerformer(makeConfig(HC_VERIFY_NONE), std::move(mock));
    const auto response = performer.perform(spec);
    EXPECT_EQ(TransportStatus::OtherError, response.status);
    EXPECT_EQ(0, response.httpCode);
}

TEST(CurlPerformerTest, FactoryFailureYieldsOtherError)
{
    CurlPerformer performer {makeConfig(HC_VERIFY_NONE),
                             []() -> std::unique_ptr<ICurlHandle>
    {
        return nullptr;
    }};
    const auto response = performer.perform(HttpRequestSpec {});
    EXPECT_EQ(TransportStatus::OtherError, response.status);
    EXPECT_EQ(0, response.httpCode);
}

TEST(CurlPerformerTest, ResponseFilePathStreamsToTheFileNotMemory)
{
    const std::string path = ::testing::TempDir() + "hc_curl_performer_response.tmp";
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);

    std::FILE* sink = nullptr;
    EXPECT_CALL(*handle, captureResponseToFile(NotNull(), _))
    .WillOnce(Invoke(
                  [&](std::FILE * file, uint64_t) -> bool
    {
        sink = file;
        return true;
    }));
    EXPECT_CALL(*handle, captureResponseBody(_, _)).Times(0);
    EXPECT_CALL(*handle, perform())
    .WillOnce(Invoke(
                  [&]() -> TransportStatus
    {
        std::fwrite("CONFIG-BYTES", 1, 12, sink);
        return TransportStatus::Ok;
    }));
    EXPECT_CALL(*handle, responseCode()).WillOnce(Return(200));

    HttpRequestSpec spec;
    spec.target = "/download";
    spec.responseFilePath = path;

    auto performer = makePerformer(makeConfig(HC_VERIFY_NONE), std::move(mock));
    const auto response = performer.perform(spec);
    EXPECT_EQ(TransportStatus::Ok, response.status);
    EXPECT_TRUE(response.body.empty()); // Bytes went to the file, not memory.

    std::ifstream file {path, std::ios::binary};
    std::string content {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
    EXPECT_EQ("CONFIG-BYTES", content);
    std::remove(path.c_str());
}

TEST(CurlPerformerTest, UnopenableResponseFileFailsWithoutPerforming)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    EXPECT_CALL(*handle, perform()).Times(0);

    HttpRequestSpec spec;
    spec.target = "/download";
    spec.responseFilePath = "/nonexistent/hc-download/config.tmp";

    auto performer = makePerformer(makeConfig(HC_VERIFY_NONE), std::move(mock));
    const auto response = performer.perform(spec);
    EXPECT_EQ(TransportStatus::OtherError, response.status);
    EXPECT_EQ(0, response.httpCode);
}

TEST(CurlPerformerTest, RetryTruncatesThePreviousAttemptsPartialBody)
{
    // Load-bearing for retry correctness: the response file is opened "wb"
    // per attempt, so a retry never mixes bytes with a failed attempt's
    // partial body.
    const std::string path = ::testing::TempDir() + "hc_curl_performer_retry.tmp";
    std::FILE* sink = nullptr;
    int attempt = 0;

    CurlHandleFactory factory = [&]() -> std::unique_ptr<ICurlHandle>
    {
        auto handle = std::make_unique<NiceMock<MockCurlHandle>>();
        ON_CALL(*handle, captureResponseToFile(_, _))
        .WillByDefault(Invoke(
                           [&](std::FILE * file, uint64_t) -> bool
        {
            sink = file;
            return true;
        }));
        ON_CALL(*handle, perform())
        .WillByDefault(Invoke(
                           [&]() -> TransportStatus
        {
            attempt++;
            const char* bytes = (attempt == 1) ? "PARTIAL-GARBAGE" : "FULL";
            std::fwrite(bytes, 1, std::strlen(bytes), sink);
            return (attempt == 1) ? TransportStatus::Timeout : TransportStatus::Ok;
        }));
        ON_CALL(*handle, responseCode()).WillByDefault(Return(attempt == 1 ? 0 : 200));
        return handle;
    };

    const auto config = makeConfig(HC_VERIFY_NONE);
    CurlPerformer performer {config, factory};
    HttpRequestSpec spec;
    spec.target = "/download";
    spec.responseFilePath = path;

    EXPECT_EQ(TransportStatus::Timeout, performer.perform(spec).status);
    EXPECT_EQ(TransportStatus::Ok, performer.perform(spec).status);

    std::ifstream file {path, std::ios::binary};
    std::string content {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
    EXPECT_EQ("FULL", content); // The second attempt truncated the first.
    std::remove(path.c_str());
}

TEST(CurlPerformerTest, AbortFlagIsWiredOnlyWhenPresent)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);
    std::atomic<bool> abortFlag {false};

    HttpRequestSpec spec;
    spec.abortFlag = &abortFlag;
    EXPECT_CALL(*handle, wireAbort(&abortFlag)).Times(1);
    auto performer = makePerformer(makeConfig(HC_VERIFY_NONE), std::move(mock));
    performer.perform(spec);

    auto second = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* secondHandle = second.get();
    allowOtherOptions(*secondHandle);
    EXPECT_CALL(*secondHandle, wireAbort(_)).Times(0);
    auto secondPerformer = makePerformer(makeConfig(HC_VERIFY_NONE), std::move(second));
    secondPerformer.perform(HttpRequestSpec {});
}

// The four tests below pin the failure-propagation path added for CIDs
// 562620/562607/562617/562614/562611/562618: a handle that rejects one of
// the option calls this class relies on must abort the request with
// TransportStatus::OtherError instead of silently calling perform() with the
// intended behavior (response capture, streaming, abort wiring) not actually
// in effect.

TEST(CurlPerformerTest, RejectedResponseCaptureAbortsBeforePerforming)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);

    EXPECT_CALL(*handle, captureResponseBody(_, _)).WillOnce(Return(false));
    EXPECT_CALL(*handle, perform()).Times(0);

    auto performer = makePerformer(makeConfig(HC_VERIFY_NONE), std::move(mock));
    const auto response = performer.perform(HttpRequestSpec {});
    EXPECT_EQ(TransportStatus::OtherError, response.status);
}

TEST(CurlPerformerTest, RejectedFileResponseCaptureAbortsBeforePerforming)
{
    const std::string path = ::testing::TempDir() + "hc_curl_performer_rejected_response.tmp";
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);

    EXPECT_CALL(*handle, captureResponseToFile(NotNull(), _)).WillOnce(Return(false));
    EXPECT_CALL(*handle, perform()).Times(0);

    HttpRequestSpec spec;
    spec.responseFilePath = path;
    auto performer = makePerformer(makeConfig(HC_VERIFY_NONE), std::move(mock));
    const auto response = performer.perform(spec);
    EXPECT_EQ(TransportStatus::OtherError, response.status);
    std::remove(path.c_str());
}

TEST(CurlPerformerTest, RejectedResponseHeadersCaptureAbortsBeforePerforming)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);

    EXPECT_CALL(*handle, captureResponseHeaders(_)).WillOnce(Return(false));
    EXPECT_CALL(*handle, perform()).Times(0);

    auto performer = makePerformer(makeConfig(HC_VERIFY_NONE), std::move(mock));
    const auto response = performer.perform(HttpRequestSpec {});
    EXPECT_EQ(TransportStatus::OtherError, response.status);
}

TEST(CurlPerformerTest, RejectedAbortWiringAbortsBeforePerforming)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);
    std::atomic<bool> abortFlag {false};

    EXPECT_CALL(*handle, wireAbort(&abortFlag)).WillOnce(Return(false));
    EXPECT_CALL(*handle, perform()).Times(0);

    HttpRequestSpec spec;
    spec.abortFlag = &abortFlag;
    auto performer = makePerformer(makeConfig(HC_VERIFY_NONE), std::move(mock));
    const auto response = performer.perform(spec);
    EXPECT_EQ(TransportStatus::OtherError, response.status);
}

TEST(CurlPerformerTest, RejectedStreamedBodyAbortsBeforePerforming)
{
    const std::string path = ::testing::TempDir() + "hc_curl_performer_rejected_body.tmp";
    {
        std::ofstream file {path, std::ios::binary};
        file << "SESSION-BYTES";
    }

    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);

    EXPECT_CALL(*handle, streamBodyFromFile(NotNull(), 13u)).WillOnce(Return(false));
    EXPECT_CALL(*handle, perform()).Times(0);

    HttpRequestSpec spec;
    spec.target = "/stateful";
    spec.bodyFilePath = path;
    spec.bodyFileSize = 13;

    auto performer = makePerformer(makeConfig(HC_VERIFY_NONE), std::move(mock));
    const auto response = performer.perform(spec);
    EXPECT_EQ(TransportStatus::OtherError, response.status);
    std::remove(path.c_str());
}
