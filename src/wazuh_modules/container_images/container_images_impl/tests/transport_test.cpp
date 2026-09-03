/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "auth_challenge.hpp"
#include "retry_policy.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>

using namespace containerimages;
using namespace std::chrono_literals;

/// @brief A certificate bundle that exists, owned by this suite.
///
/// The transport refuses to connect without one, and a system path is not portable: the
/// usual Linux location does not exist on macOS, where a test that meant to exercise the
/// protocol would instead exercise the missing-bundle branch.
static std::string existingBundle()
{
    static const std::string path {[]
    {
        const auto file {std::filesystem::temp_directory_path() / "ci_transport_ca.pem"};
        std::ofstream {file} << "not a real certificate, only a file that exists\n";

        return file.string();
    }()};

    return path;
}

class AuthChallengeTest : public ::testing::Test
{
};

TEST_F(AuthChallengeTest, TheChallengeGhcrActuallySendsIsParsed)
{
    // Verbatim from a live ghcr.io response.
    AuthChallenge challenge;

    ASSERT_TRUE(parseAuthChallenge(
        R"(Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:homebrew/core/hello:pull")",
        challenge));

    EXPECT_EQ(challenge.scheme, "bearer");
    EXPECT_EQ(challenge.realm(), "https://ghcr.io/token");
    EXPECT_EQ(challenge.service(), "ghcr.io");
    EXPECT_EQ(challenge.scope(), "repository:homebrew/core/hello:pull");
    EXPECT_TRUE(challenge.isBearer());
}

TEST_F(AuthChallengeTest, TheSchemeIsCaseInsensitive)
{
    AuthChallenge challenge;

    ASSERT_TRUE(parseAuthChallenge(R"(BEARER REALM="https://ghcr.io/token")", challenge));
    EXPECT_EQ(challenge.scheme, "bearer");
    EXPECT_EQ(challenge.realm(), "https://ghcr.io/token");
}

TEST_F(AuthChallengeTest, AQuotedValueMayContainACommaOrEquals)
{
    // A split on ',' would cut this scope in half and request the wrong one.
    AuthChallenge challenge;

    ASSERT_TRUE(parseAuthChallenge(
        R"(Bearer realm="https://ghcr.io/token",scope="repository:a/b:pull,repository:c/d:pull")", challenge));

    EXPECT_EQ(challenge.scope(), "repository:a/b:pull,repository:c/d:pull");
    EXPECT_EQ(challenge.realm(), "https://ghcr.io/token");
}

TEST_F(AuthChallengeTest, EscapedQuotesInAValueAreKept)
{
    AuthChallenge challenge;

    ASSERT_TRUE(parseAuthChallenge(R"(Bearer realm="https://ghcr.io/token",error="say \"no\"")", challenge));
    EXPECT_EQ(challenge.parameter("error"), R"(say "no")");
}

TEST_F(AuthChallengeTest, UnquotedValuesAreAccepted)
{
    AuthChallenge challenge;

    ASSERT_TRUE(parseAuthChallenge("Bearer realm=https://ghcr.io/token, service=ghcr.io", challenge));
    EXPECT_EQ(challenge.realm(), "https://ghcr.io/token");
    EXPECT_EQ(challenge.service(), "ghcr.io");
}

TEST_F(AuthChallengeTest, ASchemeWithNoParametersIsStillAScheme)
{
    AuthChallenge challenge;

    ASSERT_TRUE(parseAuthChallenge("Basic", challenge));
    EXPECT_EQ(challenge.scheme, "basic");
    EXPECT_TRUE(challenge.parameters.empty());
    EXPECT_FALSE(challenge.isBearer());
}

TEST_F(AuthChallengeTest, ANonBearerSchemeIsNotAnswerable)
{
    AuthChallenge challenge;

    ASSERT_TRUE(parseAuthChallenge(R"(Negotiate realm="https://ghcr.io/token")", challenge));
    EXPECT_FALSE(challenge.isBearer());
}

TEST_F(AuthChallengeTest, ABearerWithNoRealmIsNotAnswerable)
{
    AuthChallenge challenge;

    ASSERT_TRUE(parseAuthChallenge(R"(Bearer service="ghcr.io")", challenge));
    EXPECT_FALSE(challenge.isBearer());
}

TEST_F(AuthChallengeTest, AnEmptyHeaderIsRejected)
{
    AuthChallenge challenge;

    EXPECT_FALSE(parseAuthChallenge("", challenge));
    EXPECT_FALSE(parseAuthChallenge("   ", challenge));
}

class TokenUrlTest : public ::testing::Test
{
    protected:
        static AuthChallenge bearer(const std::string& realm, const std::string& service = "ghcr.io")
        {
            AuthChallenge challenge;
            challenge.scheme = "bearer";
            challenge.parameters["realm"] = realm;

            if (!service.empty())
            {
                challenge.parameters["service"] = service;
            }

            return challenge;
        }
};

TEST_F(TokenUrlTest, ServiceAndScopeAreAppended)
{
    const auto url {tokenRequestUrl(bearer("https://ghcr.io/token"), "repository:owner/app:pull")};

    EXPECT_EQ(url, "https://ghcr.io/token?service=ghcr.io&scope=repository%3Aowner%2Fapp%3Apull");
}

TEST_F(TokenUrlTest, AnExistingQueryStringIsExtended)
{
    const auto url {tokenRequestUrl(bearer("https://ghcr.io/token?x=1"), "repository:owner/app:pull")};

    EXPECT_NE(url.find("?x=1&service=ghcr.io"), std::string::npos) << url;
}

TEST_F(TokenUrlTest, APlainHttpRealmIsRefused)
{
    // The realm decides where a credential is sent. Over http it would go in clear.
    EXPECT_TRUE(tokenRequestUrl(bearer("http://ghcr.io/token"), "repository:owner/app:pull").empty());
}

TEST_F(TokenUrlTest, ANonUrlRealmIsRefused)
{
    EXPECT_TRUE(tokenRequestUrl(bearer("file:///etc/passwd"), "scope").empty());
    EXPECT_TRUE(tokenRequestUrl(bearer(""), "scope").empty());
    EXPECT_TRUE(tokenRequestUrl(bearer("https://"), "scope").empty());
}

TEST_F(TokenUrlTest, ARealmCarryingHeaderInjectionIsRefused)
{
    EXPECT_TRUE(tokenRequestUrl(bearer("https://ghcr.io/token\r\nX-Evil: 1"), "scope").empty());
}

TEST_F(TokenUrlTest, AScopeCannotInjectAnotherParameter)
{
    const auto url {tokenRequestUrl(bearer("https://ghcr.io/token"), "repository:a/b:pull&service=evil.example")};

    EXPECT_EQ(url.find("&service=evil.example"), std::string::npos) << url;
    EXPECT_NE(url.find("%26service%3Devil.example"), std::string::npos) << url;
}

TEST_F(TokenUrlTest, TheChallengeScopeIsUsedWhenNoneIsRequested)
{
    auto challenge {bearer("https://ghcr.io/token")};
    challenge.parameters["scope"] = "repository:from/challenge:pull";

    EXPECT_NE(tokenRequestUrl(challenge, {}).find("scope=repository%3Afrom%2Fchallenge%3Apull"), std::string::npos);
}

class PercentEncodeTest : public ::testing::Test
{
};

TEST_F(PercentEncodeTest, UnreservedCharactersAreLeftAlone)
{
    EXPECT_EQ(percentEncode("aZ09-_.~"), "aZ09-_.~");
}

TEST_F(PercentEncodeTest, EverythingElseIsEscaped)
{
    EXPECT_EQ(percentEncode("a/b:c"), "a%2Fb%3Ac");
    EXPECT_EQ(percentEncode("&=?#"), "%26%3D%3F%23");
    EXPECT_EQ(percentEncode(" "), "%20");
}

class RetryPolicyTest : public ::testing::Test
{
    protected:
        const RetryPolicy m_policy {4, 1000ms, 30000ms};
};

TEST_F(RetryPolicyTest, ThrottlingAndTransientServerErrorsAreRetryable)
{
    EXPECT_TRUE(RetryPolicy::isRetryable(429));
    EXPECT_TRUE(RetryPolicy::isRetryable(500));
    EXPECT_TRUE(RetryPolicy::isRetryable(502));
    EXPECT_TRUE(RetryPolicy::isRetryable(503));
    EXPECT_TRUE(RetryPolicy::isRetryable(504));
    EXPECT_TRUE(RetryPolicy::isRetryable(TRANSPORT_FAILURE));
}

TEST_F(RetryPolicyTest, RequestErrorsAreNotRetryable)
{
    // Repeating these changes nothing and still spends the scan's time budget.
    EXPECT_FALSE(RetryPolicy::isRetryable(400));
    EXPECT_FALSE(RetryPolicy::isRetryable(401));
    EXPECT_FALSE(RetryPolicy::isRetryable(403));
    EXPECT_FALSE(RetryPolicy::isRetryable(404));
    EXPECT_FALSE(RetryPolicy::isRetryable(501));
}

TEST_F(RetryPolicyTest, TheDelayDoublesAndIsCapped)
{
    EXPECT_EQ(m_policy.evaluate(503, {}, 1).delay, 1000ms);
    EXPECT_EQ(m_policy.evaluate(503, {}, 2).delay, 2000ms);
    EXPECT_EQ(m_policy.evaluate(503, {}, 3).delay, 4000ms);

    const RetryPolicy patient {40, 1000ms, 30000ms};
    EXPECT_EQ(patient.evaluate(503, {}, 30).delay, 30000ms);
}

TEST_F(RetryPolicyTest, GivingUpNamesWhy)
{
    const auto decision {m_policy.evaluate(503, {}, 4)};

    EXPECT_FALSE(decision.retry);
    EXPECT_FALSE(decision.reason.empty());
}

TEST_F(RetryPolicyTest, RetryAfterInSecondsWins)
{
    const auto decision {m_policy.evaluate(429, "5", 1)};

    EXPECT_TRUE(decision.retry);
    EXPECT_EQ(decision.delay, 5000ms);
}

TEST_F(RetryPolicyTest, RetryAfterIsClampedToTheCeiling)
{
    // A hostile or mistaken header must not stall the scan for an hour.
    EXPECT_EQ(m_policy.evaluate(429, "3600", 1).delay, 30000ms);
}

TEST_F(RetryPolicyTest, AnHttpDateRetryAfterFallsBackToTheComputedDelay)
{
    const auto decision {m_policy.evaluate(429, "Wed, 21 Oct 2026 07:28:00 GMT", 1)};

    EXPECT_TRUE(decision.retry);
    EXPECT_EQ(decision.delay, 1000ms);
}

TEST_F(RetryPolicyTest, RetryAfterParsing)
{
    EXPECT_EQ(RetryPolicy::parseRetryAfter("7"), 7000ms);
    EXPECT_EQ(RetryPolicy::parseRetryAfter(" 7 "), 7000ms);
    EXPECT_EQ(RetryPolicy::parseRetryAfter("0"), 0ms);
    EXPECT_FALSE(RetryPolicy::parseRetryAfter("").has_value());
    EXPECT_FALSE(RetryPolicy::parseRetryAfter("-5").has_value());
    EXPECT_FALSE(RetryPolicy::parseRetryAfter("soon").has_value());
    EXPECT_FALSE(RetryPolicy::parseRetryAfter("9999999999999").has_value());
}

TEST_F(RetryPolicyTest, ASinglePermittedAttemptNeverRetries)
{
    const RetryPolicy once {1};

    EXPECT_FALSE(once.evaluate(503, {}, 1).retry);
}

#include "registry_transport.hpp"

class RegistryTransportTest : public ::testing::Test
{
    protected:
        static TransportConfig verified()
        {
            TransportConfig config;
            config.caBundle = existingBundle();
            config.connectTimeoutMs = 1000;
            config.requestTimeoutMs = 2000;

            return config;
        }
};

TEST_F(RegistryTransportTest, WithoutACertificateBundleNothingIsRequested)
{
    // Reaching the transport with no bundle means the certificate resolution was
    // skipped. Connecting anyway would drop the guarantee that resolution exists for,
    // so the request is refused before a socket is opened.
    CurlRegistryTransport transport {TransportConfig {}};

    HttpResponse response;
    std::string error;

    EXPECT_FALSE(transport.get("https://ghcr.io/v2/", {}, response, error));
    EXPECT_EQ(response.status, 0);
    EXPECT_NE(error.find("certificate"), std::string::npos) << error;
}

TEST_F(RegistryTransportTest, PlainHttpIsRefusedBeforeConnecting)
{
    // CURLOPT_PROTOCOLS_STR is set to https only, so this fails on the protocol rather
    // than by attempting a cleartext request. No network is touched.
    CurlRegistryTransport transport {verified()};

    HttpResponse response;
    std::string error;

    EXPECT_FALSE(transport.get("http://ghcr.io/v2/", {}, response, error));
    EXPECT_EQ(response.status, 0);
    EXPECT_FALSE(error.empty());
}

TEST_F(RegistryTransportTest, NonHttpSchemesAreRefused)
{
    CurlRegistryTransport transport {verified()};

    HttpResponse response;
    std::string error;

    for (const auto* url : {"file:///etc/passwd", "ftp://example.com/x", "gopher://example.com/"})
    {
        EXPECT_FALSE(transport.get(url, {}, response, error)) << url;
        EXPECT_EQ(response.status, 0) << url;
    }
}

TEST_F(RegistryTransportTest, TheConfigurationIsKeptAsGiven)
{
    const CurlRegistryTransport transport {verified()};

    EXPECT_EQ(transport.config().caBundle, existingBundle());
    EXPECT_EQ(transport.config().requestTimeoutMs, 2000);
    EXPECT_GT(transport.config().maxResponseBytes, 0u);
}

TEST_F(RegistryTransportTest, HttpResponseHeaderLookupIsByLowerCasedName)
{
    HttpResponse response;
    response.headers["www-authenticate"] = "Bearer realm=\"https://ghcr.io/token\"";

    EXPECT_EQ(response.header("www-authenticate"), "Bearer realm=\"https://ghcr.io/token\"");
    EXPECT_TRUE(response.header("absent").empty());
}

TEST_F(RegistryTransportTest, InitializingCurlIsIdempotent)
{
    // Called from every transport construction; must be safe to call repeatedly.
    ensureCurlInitialized();
    ensureCurlInitialized();
}

#include "registry_byte_stream.hpp"

class RegistryByteStreamTest : public ::testing::Test
{
    protected:
        static TransportConfig verified()
        {
            TransportConfig config;
            config.caBundle = existingBundle();
            config.connectTimeoutMs = 1000;
            config.requestTimeoutMs = 2000;

            return config;
        }
};

TEST_F(RegistryByteStreamTest, WithoutACertificateBundleNothingIsStreamed)
{
    RegistryByteStream stream {TransportConfig {}, "https://ghcr.io/v2/x/blobs/sha256:aa", {}};

    char buffer[64] {};

    EXPECT_EQ(stream.read(buffer, sizeof(buffer)), 0u);
    EXPECT_TRUE(stream.failed());
    EXPECT_NE(stream.error().find("certificate"), std::string::npos) << stream.error();
}

TEST_F(RegistryByteStreamTest, PlainHttpIsRefused)
{
    RegistryByteStream stream {verified(), "http://ghcr.io/v2/x/blobs/sha256:aa", {}};

    char buffer[64] {};

    EXPECT_EQ(stream.read(buffer, sizeof(buffer)), 0u);
    EXPECT_TRUE(stream.failed());
}

TEST_F(RegistryByteStreamTest, AZeroSizedReadAsksForNothing)
{
    // Must not start a transfer, so a caller probing with a zero-length buffer does not
    // open a connection as a side effect.
    RegistryByteStream stream {verified(), "https://ghcr.io/v2/x/blobs/sha256:aa", {}};

    char buffer[1] {};

    EXPECT_EQ(stream.read(buffer, 0), 0u);
    EXPECT_FALSE(stream.failed());
    EXPECT_EQ(stream.bytesDelivered(), 0u);
}

TEST_F(RegistryByteStreamTest, ANullBufferIsRefused)
{
    RegistryByteStream stream {verified(), "https://ghcr.io/v2/x/blobs/sha256:aa", {}};

    EXPECT_EQ(stream.read(nullptr, 16), 0u);
}

TEST_F(RegistryByteStreamTest, NothingIsDeliveredBeforeAnythingIsRead)
{
    const RegistryByteStream stream {verified(), "https://ghcr.io/v2/x/blobs/sha256:aa", {}};

    EXPECT_EQ(stream.bytesDelivered(), 0u);
    EXPECT_EQ(stream.status(), 0);
    EXPECT_FALSE(stream.failed());
}

TEST_F(RegistryByteStreamTest, AFailedStreamReadsAsEmptyAndSaysWhy)
{
    // The layer chain sees only "no more bytes", which is why the reader has to ask
    // failed() before it treats an empty read as an empty layer.
    RegistryByteStream stream {TransportConfig {}, "https://ghcr.io/v2/x/blobs/sha256:aa", {}};

    char buffer[64] {};

    EXPECT_EQ(stream.read(buffer, sizeof(buffer)), 0u);
    EXPECT_EQ(stream.read(buffer, sizeof(buffer)), 0u);
    EXPECT_TRUE(stream.failed());
    EXPECT_FALSE(stream.error().empty());
}
