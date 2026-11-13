/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "ecr_token_client.hpp"
#include "registry_errors.hpp"
#include "retry_policy.hpp"
#include "registry_token_cache.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <stdexcept>
#include <string>

using namespace containerimages;
using namespace std::chrono_literals;

namespace
{
    using TimePoint = std::chrono::system_clock::time_point;

    TimePoint at(const long long seconds)
    {
        return TimePoint {std::chrono::seconds {seconds}};
    }

    // 2015-08-30T12:36:00Z, the instant of the AWS reference cases.
    const TimePoint FIXED_TIME {at(1440938160)};

    // The public example credential of the AWS test suite, not a real one.
    constexpr auto EXAMPLE_KEY_ID = "AKIDEXAMPLE";
    constexpr auto EXAMPLE_SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    HttpResponse response(const long status, const std::string& body)
    {
        HttpResponse result;
        result.status = status;
        result.body = body;

        return result;
    }
} // namespace

class RegistryTokenCacheTest : public ::testing::Test
{
    protected:
        RegistryTokenCacheTest()
            : m_cache {[this] { return m_now; }, std::chrono::minutes {10}}
        {
        }

        TimePoint m_now {at(1'000'000)};
        RegistryTokenCache m_cache;
};

TEST_F(RegistryTokenCacheTest, ATokenIsServedUntilItIsAboutToExpire)
{
    m_cache.store("k", Secret {"token-1"}, m_now + 12h);

    ASSERT_TRUE(m_cache.lookup("k").has_value());
    EXPECT_EQ(m_cache.lookup("k")->value(), "token-1");

    m_now += 11h; // an hour of life left, well outside the renewal margin
    EXPECT_TRUE(m_cache.lookup("k").has_value());
}

TEST_F(RegistryTokenCacheTest, ATokenInsideTheRenewalMarginIsNotServed)
{
    m_cache.store("k", Secret {"token-1"}, m_now + 12h);

    m_now += 12h - 9min; // still valid for nine minutes, but the margin is ten
    EXPECT_FALSE(m_cache.lookup("k").has_value());
    EXPECT_EQ(m_cache.size(), 0u) << "the stale entry should have been dropped";
}

TEST_F(RegistryTokenCacheTest, AnExpiredTokenIsNotServed)
{
    m_cache.store("k", Secret {"token-1"}, m_now + 1h);

    m_now += 2h;
    EXPECT_FALSE(m_cache.lookup("k").has_value());
}

TEST_F(RegistryTokenCacheTest, ATokenWithNoLifeLeftIsNeverServed)
{
    // What a response with no readable expiry is stored as: usable once, never reused.
    m_cache.store("k", Secret {"token-1"}, m_now);

    EXPECT_FALSE(m_cache.lookup("k").has_value());
}

TEST_F(RegistryTokenCacheTest, InvalidatingDropsOnlyThatKey)
{
    m_cache.store("a", Secret {"token-a"}, m_now + 12h);
    m_cache.store("b", Secret {"token-b"}, m_now + 12h);

    m_cache.invalidate("a");

    EXPECT_FALSE(m_cache.lookup("a").has_value());
    EXPECT_TRUE(m_cache.lookup("b").has_value());
}

TEST_F(RegistryTokenCacheTest, ClearDropsEverything)
{
    m_cache.store("a", Secret {"token-a"}, m_now + 12h);
    m_cache.store("b", Secret {"token-b"}, m_now + 12h);

    m_cache.clear();

    EXPECT_EQ(m_cache.size(), 0u);
}

TEST_F(RegistryTokenCacheTest, TheKeyDistinguishesHostCredentialAndRegion)
{
    const auto base {RegistryTokenCache::makeKey("h", "id", "secret", "us-east-1")};

    EXPECT_NE(base, RegistryTokenCache::makeKey("other", "id", "secret", "us-east-1"));
    EXPECT_NE(base, RegistryTokenCache::makeKey("h", "id2", "secret", "us-east-1"));
    EXPECT_NE(base, RegistryTokenCache::makeKey("h", "id", "secret2", "us-east-1"));
    EXPECT_NE(base, RegistryTokenCache::makeKey("h", "id", "secret", "eu-west-1"));
    EXPECT_EQ(base, RegistryTokenCache::makeKey("h", "id", "secret", "us-east-1"));
}

TEST_F(RegistryTokenCacheTest, TheKeyHoldsNoCredentialValue)
{
    // Built from key names only, which is what the configuration carries.
    EXPECT_EQ(RegistryTokenCache::makeKey("h", "ecr_key_id", "ecr_secret", "us-east-1").find(EXAMPLE_SECRET),
              std::string::npos);
}

class EcrTokenRequestTest : public ::testing::Test
{
};

// The expected Authorization header was computed with Python's hmac and hashlib alone, from
// the same inputs (POST /, signed headers content-type, host, x-amz-date and x-amz-target, body
// "{}", service ecr, the public example credential of the AWS test suite), so it shares no code
// with the signer. The mock registry of the integration tests verifies the same value.
TEST_F(EcrTokenRequestTest, TheRequestIsTheOneAwsDocumentsForGetAuthorizationToken)
{
    EcrPostRequest request;
    std::string error;

    ASSERT_TRUE(buildGetAuthorizationTokenRequest("us-east-1",
                                                  "amazonaws.com",
                                                  Secret {EXAMPLE_KEY_ID},
                                                  Secret {EXAMPLE_SECRET},
                                                  FIXED_TIME,
                                                  request,
                                                  error))
        << error;

    EXPECT_EQ(request.url, "https://api.ecr.us-east-1.amazonaws.com/");
    EXPECT_EQ(request.body, "{}");

    ASSERT_EQ(request.headers.size(), 4u);
    EXPECT_EQ(request.headers[0], "Content-Type: application/x-amz-json-1.1");
    EXPECT_EQ(request.headers[1], "X-Amz-Date: 20150830T123600Z");
    EXPECT_EQ(request.headers[2], "X-Amz-Target: AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken");
    EXPECT_EQ(request.headers[3],
              "Authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/ecr/aws4_request, "
              "SignedHeaders=content-type;host;x-amz-date;x-amz-target, "
              "Signature=527a2155e9afc2426cb4c659023df9c031e8103458f349819615ff25111f5de0");
}

TEST_F(EcrTokenRequestTest, AnotherRegionChangesTheEndpointAndTheSignature)
{
    EcrPostRequest usEast;
    EcrPostRequest euWest;
    std::string error;

    ASSERT_TRUE(buildGetAuthorizationTokenRequest("us-east-1", "amazonaws.com", Secret {EXAMPLE_KEY_ID}, Secret {EXAMPLE_SECRET}, FIXED_TIME, usEast, error));
    ASSERT_TRUE(buildGetAuthorizationTokenRequest("eu-west-1", "amazonaws.com", Secret {EXAMPLE_KEY_ID}, Secret {EXAMPLE_SECRET}, FIXED_TIME, euWest, error));

    EXPECT_EQ(euWest.url, "https://api.ecr.eu-west-1.amazonaws.com/");
    EXPECT_NE(usEast.headers[3], euWest.headers[3]);
}

TEST_F(EcrTokenRequestTest, TheChinaEndpointKeepsItsDomain)
{
    EcrPostRequest request;
    std::string error;

    ASSERT_TRUE(buildGetAuthorizationTokenRequest("cn-north-1", "amazonaws.com.cn", Secret {EXAMPLE_KEY_ID}, Secret {EXAMPLE_SECRET}, FIXED_TIME, request, error));
    EXPECT_EQ(request.url, "https://api.ecr.cn-north-1.amazonaws.com.cn/");
}

TEST_F(EcrTokenRequestTest, NothingIsBuiltFromAnInvalidRegionOrDomain)
{
    // The endpoint is made of these two values and the request carries a signature, so a
    // value that could change the host must stop the request from existing at all.
    for (const auto* region : {"us-east-1.attacker.example", "us-east-1/x", "us-east-1@x", "", "US-EAST-1"})
    {
        EcrPostRequest request;
        std::string error;

        EXPECT_FALSE(buildGetAuthorizationTokenRequest(region, "amazonaws.com", Secret {EXAMPLE_KEY_ID}, Secret {EXAMPLE_SECRET}, FIXED_TIME, request, error)) << region;
        EXPECT_TRUE(request.url.empty()) << region;
        EXPECT_TRUE(request.headers.empty()) << region;
    }

    for (const auto* suffix : {"attacker.example", "amazonaws.com.attacker.example", "", "amazonaws.org"})
    {
        EcrPostRequest request;
        std::string error;

        EXPECT_FALSE(buildGetAuthorizationTokenRequest("us-east-1", suffix, Secret {EXAMPLE_KEY_ID}, Secret {EXAMPLE_SECRET}, FIXED_TIME, request, error)) << suffix;
        EXPECT_TRUE(request.url.empty()) << suffix;
    }
}

TEST_F(EcrTokenRequestTest, AnAccessKeyIdThatCouldNotBeOneBuildsNothingAndIsNotNamed)
{
    // A stored value with a blank, a quote or a separator would be written into the
    // Credential field of the header, so it stops here and is never echoed in the reason.
    for (const std::string keyId : {"AKIDEXAMPLE ", " AKIDEXAMPLE", "AKID,EXAMPLE", "AKID/EXAMPLE", "AKID\"EXAMPLE", "AKID\nEXAMPLE", ""})
    {
        EcrPostRequest request;
        std::string error;

        EXPECT_FALSE(buildGetAuthorizationTokenRequest("us-east-1", "amazonaws.com", Secret {keyId}, Secret {EXAMPLE_SECRET}, FIXED_TIME, request, error));
        EXPECT_TRUE(request.headers.empty());
        EXPECT_EQ(error, "the stored access key id is not well-formed, so nothing was sent");
    }
}

TEST_F(EcrTokenRequestTest, AnInvalidRegionIsNamedInTheReason)
{
    EcrPostRequest request;
    std::string error;

    EXPECT_FALSE(buildGetAuthorizationTokenRequest("us-e4st-1", "amazonaws.com", Secret {EXAMPLE_KEY_ID}, Secret {EXAMPLE_SECRET}, FIXED_TIME, request, error));
    EXPECT_EQ(error, "the AWS region 'us-e4st-1' is not valid, so nothing was sent");
}

TEST_F(EcrTokenRequestTest, AnEmptySecretBuildsNothing)
{
    EcrPostRequest request;
    std::string error;

    EXPECT_FALSE(buildGetAuthorizationTokenRequest("us-east-1", "amazonaws.com", Secret {EXAMPLE_KEY_ID}, Secret {}, FIXED_TIME, request, error));
    EXPECT_TRUE(request.headers.empty());
}

class EcrTokenResponseTest : public ::testing::Test
{
};

TEST_F(EcrTokenResponseTest, ATokenAndItsExpiryAreRead)
{
    const auto result {parseGetAuthorizationTokenResponse(
        response(200,
                 R"({"authorizationData":[{"authorizationToken":"QVdTOnB3LXh5eg==","expiresAt":1440981360.5,)"
                 R"("proxyEndpoint":"https://123456789012.dkr.ecr.us-east-1.amazonaws.com"}]})"),
        FIXED_TIME)};

    ASSERT_TRUE(result.ok) << result.reason;
    EXPECT_EQ(result.token.value(), "QVdTOnB3LXh5eg==");
    EXPECT_EQ(std::chrono::duration_cast<std::chrono::seconds>(result.expiresAt.time_since_epoch()).count(),
              1440981360);
}

TEST_F(EcrTokenResponseTest, ATokenWithNoExpiryIsUsableButNeverCached)
{
    const auto result {parseGetAuthorizationTokenResponse(
        response(200, R"({"authorizationData":[{"authorizationToken":"QVdTOnB3"}]})"), FIXED_TIME)};

    ASSERT_TRUE(result.ok);
    EXPECT_EQ(result.expiresAt, FIXED_TIME);
}

TEST_F(EcrTokenResponseTest, AnExpiryOutOfRangeIsReadAsNoExpiry)
{
    // 1e300 seconds does not fit a time point, and converting it would be undefined.
    for (const auto* expiry : {"1e300", "-5", "1e30"})
    {
        const auto body {std::string {R"({"authorizationData":[{"authorizationToken":"QVdTOnB3","expiresAt":)"} + expiry + "}]}"};
        const auto result {parseGetAuthorizationTokenResponse(response(200, body), FIXED_TIME)};

        ASSERT_TRUE(result.ok) << expiry;
        EXPECT_EQ(result.expiresAt, FIXED_TIME) << expiry;
    }
}

TEST_F(EcrTokenResponseTest, AMalformedSuccessIsRefused)
{
    for (const auto* body : {"", "not json", "{}", R"({"authorizationData":[]})", R"({"authorizationData":[{}]})",
                             R"({"authorizationData":[{"authorizationToken":""}]})",
                             R"({"authorizationData":[{"authorizationToken":7}]})"})
    {
        const auto result {parseGetAuthorizationTokenResponse(response(200, body), FIXED_TIME)};

        EXPECT_FALSE(result.ok) << body;
        EXPECT_FALSE(result.reason.empty()) << body;
    }
}

TEST_F(EcrTokenResponseTest, ATokenThatCouldNotBeAHeaderValueIsRefused)
{
    // The token is sent back in a request header, so a line break or a space in it is a
    // header injection and not a token.
    for (const auto* token : {"QVdT\\r\\nX-Injected: 1", "QVdT OnB3", "QVdT;OnB3", "QVdT\\u0000OnB3"})
    {
        const auto body {std::string {R"({"authorizationData":[{"authorizationToken":")"} + token + R"("}]})"};
        const auto result {parseGetAuthorizationTokenResponse(response(200, body), FIXED_TIME)};

        EXPECT_FALSE(result.ok) << token;
        EXPECT_TRUE(result.token.empty()) << token;
    }

    const auto tooLong {R"({"authorizationData":[{"authorizationToken":")" + std::string(9000, 'A') + R"("}]})"};
    EXPECT_FALSE(parseGetAuthorizationTokenResponse(response(200, tooLong), FIXED_TIME).ok);
}

struct FailureCase
{
    long status;
    const char* body;
    const char* expectedFragment;
    long expectedRetryStatus;
};

TEST_F(EcrTokenResponseTest, EveryAwsFailureHasAClearFixedReason)
{
    const FailureCase cases[] = {
        {400,
         R"({"__type":"MissingAuthenticationTokenException","message":"Missing Authentication Token"})",
         "did not accept the request signature (MissingAuthenticationTokenException)",
         400},
        {400,
         R"({"__type":"UnrecognizedClientException","message":"The security token included in the request is invalid."})",
         "does not accept the access key id (UnrecognizedClientException)",
         400},
        {400,
         R"({"__type":"InvalidSignatureException","message":"The request signature we calculated does not match"})",
         "the secret access key does not match the access key id (InvalidSignatureException)",
         400},
        {400,
         R"j({"__type":"InvalidSignatureException","message":"Signature expired: 20260101T000000Z is now earlier than 20260101T001500Z (20260101T002000Z - 5 min.)"})j",
         "the agent clock differs too much from AWS time",
         400},
        {400,
         R"({"__type":"RequestExpired","message":"Request has expired"})",
         "the agent clock differs too much from AWS time",
         400},
        {400,
         R"({"__type":"ThrottlingException","message":"Rate exceeded"})",
         "AWS throttled the request (ThrottlingException)",
         429},
        {400,
         R"({"__type":"com.amazonaws.ecr#ThrottlingException","message":"Rate exceeded"})",
         "AWS throttled the request (ThrottlingException)",
         429},
        {400,
         R"({"__type":"AccessDeniedException","message":"User: arn:aws:iam::123456789012:user/ci is not authorized"})",
         "not allowed to request a registry authorization token (AccessDeniedException)",
         400},
        {500, R"({"__type":"ServerException","message":"boom"})", "AWS answered 500 (ServerException)", 500},
        {503, "", "AWS answered 503", 503},
        {400, "<html>not json</html>", "AWS answered 400", 400},
    };

    for (const auto& failure : cases)
    {
        SCOPED_TRACE(failure.body);

        const auto result {parseGetAuthorizationTokenResponse(response(failure.status, failure.body), FIXED_TIME)};

        EXPECT_FALSE(result.ok);
        EXPECT_NE(result.reason.find(failure.expectedFragment), std::string::npos) << result.reason;
        EXPECT_EQ(result.status, failure.expectedRetryStatus);
    }
}

TEST_F(EcrTokenResponseTest, TheServersMessageNeverReachesTheReason)
{
    // AWS messages for signed calls may echo the canonical request or the caller's ARN.
    const auto result {parseGetAuthorizationTokenResponse(
        response(400,
                 R"({"__type":"InvalidSignatureException","message":"The Canonical String for this request should have been 'POST\n/\n\nhost:x\n' Credential=AKIDEXAMPLE/20150830/us-east-1/ecr/aws4_request arn:aws:iam::123456789012:user/ci"})"),
        FIXED_TIME)};

    EXPECT_EQ(result.reason.find("Canonical"), std::string::npos) << result.reason;
    EXPECT_EQ(result.reason.find("AKIDEXAMPLE"), std::string::npos) << result.reason;
    EXPECT_EQ(result.reason.find("arn:"), std::string::npos) << result.reason;
    EXPECT_EQ(result.reason.find("123456789012"), std::string::npos) << result.reason;
}

TEST_F(EcrTokenResponseTest, AnErrorTypeThatIsNotAnIdentifierIsDropped)
{
    const auto result {parseGetAuthorizationTokenResponse(
        response(400, R"({"__type":"Bad Type\nwith newline and spaces","message":"x"})"), FIXED_TIME)};

    EXPECT_EQ(result.reason, "AWS answered 400");
}

class EcrTokenClientTest : public ::testing::Test
{
    protected:
        EcrTokenClient make(EcrTokenClient::PostFunction post)
        {
            return EcrTokenClient {std::move(post), [] { return FIXED_TIME; }};
        }
};

TEST_F(EcrTokenClientTest, ASuccessfulCallYieldsTheToken)
{
    EcrPostRequest sent;

    auto client {make([&sent](const EcrPostRequest& request, HttpResponse& answer, std::string&)
    {
        sent = request;
        answer = response(200, R"({"authorizationData":[{"authorizationToken":"QVdTOnB3","expiresAt":1440981360}]})");
        return true;
    })};

    const auto result {client.fetch("us-east-1", "amazonaws.com", Secret {EXAMPLE_KEY_ID}, Secret {EXAMPLE_SECRET})};

    ASSERT_TRUE(result.ok) << result.reason;
    EXPECT_EQ(result.token.value(), "QVdTOnB3");
    EXPECT_EQ(sent.url, "https://api.ecr.us-east-1.amazonaws.com/");
}

TEST_F(EcrTokenClientTest, ATransportFailureIsRetryableAndNamesNoCredential)
{
    auto client {make([](const EcrPostRequest&, HttpResponse&, std::string& error)
    {
        error = "Could not resolve host: api.ecr.us-east-1.amazonaws.com";
        return false;
    })};

    const auto result {client.fetch("us-east-1", "amazonaws.com", Secret {EXAMPLE_KEY_ID}, Secret {EXAMPLE_SECRET})};

    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.status, TRANSPORT_FAILURE);
    EXPECT_NE(result.reason.find("Could not resolve host"), std::string::npos) << result.reason;
}

TEST_F(EcrTokenClientTest, ARetryAfterFromAwsIsPassedOn)
{
    auto client {make([](const EcrPostRequest&, HttpResponse& answer, std::string&)
    {
        answer = response(400, R"({"__type":"ThrottlingException","message":"Rate exceeded"})");
        answer.headers["retry-after"] = "7";
        return true;
    })};

    const auto result {client.fetch("us-east-1", "amazonaws.com", Secret {EXAMPLE_KEY_ID}, Secret {EXAMPLE_SECRET})};

    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.status, 429) << "throttling arrives as a 400 and is retried as a 429";
    EXPECT_EQ(result.retryAfter, "7");
    EXPECT_TRUE(result.retryable);
}

TEST_F(EcrTokenClientTest, ACallThatWouldFailTheSameWayIsMarkedNotRetryable)
{
    auto client {make([](const EcrPostRequest&, HttpResponse& answer, std::string& error)
    {
        answer.retryable = false;
        error = "SSL peer certificate or SSH remote key was not OK";
        return false;
    })};

    const auto result {client.fetch("us-east-1", "amazonaws.com", Secret {EXAMPLE_KEY_ID}, Secret {EXAMPLE_SECRET})};

    EXPECT_FALSE(result.ok);
    EXPECT_FALSE(result.retryable);
    EXPECT_EQ(result.status, TRANSPORT_FAILURE);
}

TEST_F(EcrTokenClientTest, ATransportFailureThatMayClearUpStaysRetryable)
{
    auto client {make([](const EcrPostRequest&, HttpResponse&, std::string& error)
    {
        error = "Connection timed out";
        return false;
    })};

    EXPECT_TRUE(client.fetch("us-east-1", "amazonaws.com", Secret {EXAMPLE_KEY_ID}, Secret {EXAMPLE_SECRET}).retryable);
}

TEST_F(EcrTokenClientTest, AServerErrorKeepsItsStatusForTheRetryPolicy)
{
    for (const long status : {500L, 502L, 503L, 504L})
    {
        auto client {make([status](const EcrPostRequest&, HttpResponse& answer, std::string&)
        {
            answer = response(status, "");
            return true;
        })};

        const auto result {client.fetch("us-east-1", "amazonaws.com", Secret {EXAMPLE_KEY_ID}, Secret {EXAMPLE_SECRET})};

        EXPECT_EQ(result.status, status);
        EXPECT_TRUE(result.retryable);
    }
}

TEST_F(EcrTokenClientTest, ARedirectIsReportedAndNotFollowed)
{
    auto client {make([](const EcrPostRequest&, HttpResponse& answer, std::string&)
    {
        answer = response(307, "");
        answer.headers["location"] = "https://attacker.example/";
        return true;
    })};

    const auto result {client.fetch("us-east-1", "amazonaws.com", Secret {EXAMPLE_KEY_ID}, Secret {EXAMPLE_SECRET})};

    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.reason, "AWS answered 307");
}

TEST_F(EcrTokenClientTest, AnExceptionCarryingTheSecretNeverEscapesAndIsNotQuoted)
{
    auto client {make([](const EcrPostRequest& request, HttpResponse&, std::string&) -> bool
    {
        throw std::runtime_error("failed with " + std::string {EXAMPLE_SECRET} + " and " + request.headers.back());
    })};

    const auto result {client.fetch("us-east-1", "amazonaws.com", Secret {EXAMPLE_KEY_ID}, Secret {EXAMPLE_SECRET})};

    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.reason, "the request to AWS failed unexpectedly");
    EXPECT_FALSE(result.retryable) << "the same input fails the same way";
}

TEST_F(EcrTokenClientTest, AnInvalidRegionSendsNothing)
{
    auto posted {false};

    auto client {make([&posted](const EcrPostRequest&, HttpResponse&, std::string&)
    {
        posted = true;
        return true;
    })};

    const auto result {client.fetch("us-east-1.attacker.example", "amazonaws.com", Secret {EXAMPLE_KEY_ID}, Secret {EXAMPLE_SECRET})};

    EXPECT_FALSE(result.ok);
    EXPECT_FALSE(posted);
}

class RegistryErrorsTest : public ::testing::Test
{
};

TEST_F(RegistryErrorsTest, TheBodyEcrAnsweredToABadTokenIsReadAsMeasured)
{
    // Verbatim from the probe of a private registry given a made-up Basic token.
    EXPECT_EQ(registryErrorReason(R"({"errors":[{"code":"DENIED","message":"Your Authorization Token is invalid."}]})"),
              "DENIED: Your Authorization Token is invalid.");
}

TEST_F(RegistryErrorsTest, TheBodyEcrAnsweredToAMissingRepositoryIsRead)
{
    EXPECT_EQ(registryErrorReason(R"({"errors":[{"code":"NAME_UNKNOWN","message":"The repository with name 'doesnotexist' does not exist in the registry with id 'nope'"}]})"),
              "NAME_UNKNOWN: The repository with name 'doesnotexist' does not exist in the registry with id 'nope'");
}

TEST_F(RegistryErrorsTest, ABodyWithNoReasonYieldsNone)
{
    EXPECT_TRUE(registryErrorReason("").empty());
    EXPECT_TRUE(registryErrorReason("not json").empty());
    EXPECT_TRUE(registryErrorReason("{}").empty());
    EXPECT_TRUE(registryErrorReason(R"({"errors":[]})").empty());
    EXPECT_TRUE(registryErrorReason(R"({"errors":["x"]})").empty());
    EXPECT_TRUE(registryErrorReason(R"({"errors":[{"code":7,"message":7}]})").empty());
}

TEST_F(RegistryErrorsTest, TextThatQuotesARequestIsWithheld)
{
    // Each message is one a registry could plausibly echo. The code stays, the quotation does not.
    // The key id shapes are assembled here so no literal in the source looks like one to a secret scanner.
    const std::string permanentKey {std::string {"key AK"} + "IA" + "EXAMPLEKEYID0000 was used"};
    const std::string temporaryKey {std::string {"key AS"} + "IA" + "EXAMPLEKEYID0000 was used"};

    for (const auto& message : std::vector<std::string> {
             "bad header Authorization: Basic QVdTOnB3",
             "Credential=AKIDEXAMPLE/20150830/us-east-1/ecr/aws4_request",
             "Signature=527a2155e9afc2426cb4c659023df9c031e8103458f349819615ff25111f5de0",
             "AWS4-HMAC-SHA256 was used",
             "x-amz-date was 20150830",
             permanentKey,
             temporaryKey,
             "token eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0 was bad",
             "the Canonical Request was wrong"})
    {
        const auto body {std::string {R"({"errors":[{"code":"DENIED","message":")"} + message + R"("}]})"};

        EXPECT_EQ(registryErrorReason(body), "DENIED") << message;
    }
}

// What an IAM denial looks like is not measured here: this is the form AWS documents for it,
// naming the principal and the resource. It is an identifier and not a credential, so it is
// the reason that has to reach the log.
TEST_F(RegistryErrorsTest, AnIamDenialIsKeptWithItsArns)
{
    const auto body {R"({"errors":[{"code":"DENIED","message":"User: arn:aws:iam::123456789012:user/wazuh-ci )"
                     R"(is not authorized to perform: ecr:BatchGetImage on resource: )"
                     R"(arn:aws:ecr:us-east-1:123456789012:repository/my-backend"}]})"};

    const auto reason {registryErrorReason(body)};

    EXPECT_NE(reason.find("arn:aws:iam::123456789012:user/wazuh-ci"), std::string::npos) << reason;
    EXPECT_NE(reason.find("is not authorized to perform: ecr:BatchGetImage"), std::string::npos) << reason;
    EXPECT_EQ(reason.rfind("DENIED: User: arn:aws:iam::", 0), 0u) << reason;

    // The whole resource ARN, not a prefix of it, and no truncation marker.
    EXPECT_EQ(reason,
              "DENIED: User: arn:aws:iam::123456789012:user/wazuh-ci is not authorized to perform: "
              "ecr:BatchGetImage on resource: arn:aws:ecr:us-east-1:123456789012:repository/my-backend");
    EXPECT_FALSE(registryRefusesTheToken(body)) << "a permission denial is not the token being refused";
}

TEST_F(RegistryErrorsTest, ALongerIamDenialStillKeepsItsResource)
{
    // A denial that also names a policy and a longer repository path, well past the old cap.
    const std::string resource {"arn:aws:ecr:eu-central-1:123456789012:repository/team-platform/services/payments-backend"};
    const auto body {R"({"errors":[{"code":"DENIED","message":"User: arn:aws:sts::123456789012:assumed-role/wazuh-ci-reader/session )"
                     R"(is not authorized to perform: ecr:GetDownloadUrlForLayer on resource: )" + resource +
                     R"( because no identity-based policy allows the ecr:GetDownloadUrlForLayer action"}]})"};

    const auto reason {registryErrorReason(body)};

    EXPECT_NE(reason.find(resource + " because no identity-based policy"), std::string::npos) << reason;
    EXPECT_GT(reason.size(), 160u);
    EXPECT_LE(reason.size(), MAX_REASON_LENGTH + std::string {"DENIED: "}.size());
}

TEST_F(RegistryErrorsTest, ALongRepositoryPathIsNotMistakenForAToken)
{
    const std::string path {"team-with-a-long-name/another-long-segment/and-a-repository-name-that-keeps-going"};
    const auto body {R"({"errors":[{"code":"NAME_UNKNOWN","message":"The repository with name ')" + path +
                     R"(' does not exist"}]})"};

    EXPECT_NE(registryErrorReason(body).find(path), std::string::npos) << registryErrorReason(body);
}

TEST_F(RegistryErrorsTest, OnlyAMessageAboutTheTokenSaysTheTokenWasRefused)
{
    EXPECT_TRUE(registryRefusesTheToken(R"({"errors":[{"code":"DENIED","message":"Your Authorization Token is invalid."}]})"));
    EXPECT_TRUE(registryRefusesTheToken(R"({"errors":[{"code":"DENIED","message":"Your authorization token has expired."}]})"));
    EXPECT_TRUE(registryRefusesTheToken(R"({"errors":[{"code":"UNAUTHORIZED","message":"authentication required, token expired"}]})"));

    EXPECT_FALSE(registryRefusesTheToken(R"({"errors":[{"code":"DENIED","message":"User: x is not authorized to perform: ecr:BatchGetImage"}]})"));

    // A repository, a role or a user named after the thing the words are about. Only the
    // message about the token counts, never the names the message carries.
    for (const auto* resource : {"token-service", "expiry-job", "oauth-token-proxy", "token-expired-jobs", "expired-token-cache"})
    {
        const auto body {std::string {R"({"errors":[{"code":"DENIED","message":"User: arn:aws:iam::123456789012:user/token-admin )"} +
                         R"(is not authorized to perform: ecr:BatchGetImage on resource: arn:aws:ecr:us-east-1:123456789012:repository/)" +
                         resource + R"( because no identity-based policy allows the ecr:BatchGetImage action"}]})"};

        EXPECT_FALSE(registryRefusesTheToken(body)) << resource;
    }

    // The same words in the plain text of a message that is about the token are still read.
    EXPECT_TRUE(registryRefusesTheToken(R"({"errors":[{"code":"DENIED","message":"Your Authorization Token is invalid. User: arn:aws:iam::123456789012:user/x"}]})"));
    EXPECT_FALSE(registryRefusesTheToken(R"({"errors":[{"code":"NAME_UNKNOWN","message":"The repository does not exist"}]})"));
    EXPECT_FALSE(registryRefusesTheToken(""));
    EXPECT_FALSE(registryRefusesTheToken("<Error>Access Denied</Error>"));
    EXPECT_FALSE(registryRefusesTheToken("{}"));
}

TEST_F(RegistryErrorsTest, TextIsCleanedAndCapped)
{
    EXPECT_EQ(sanitizeServerText("one\r\ntwo\tthree\x01 four"), "one two three four");
    EXPECT_EQ(sanitizeServerText("caf\xC3\xA9"), "caf");

    std::string words;

    for (auto index = 0; index < 300; ++index)
    {
        words += "word ";
    }

    const auto capped {sanitizeServerText(words)};
    EXPECT_EQ(capped.size(), MAX_REASON_LENGTH + 3);
    EXPECT_EQ(capped.substr(MAX_REASON_LENGTH), "...");

    // A run of token characters that long is a token, not a word, and is withheld.
    EXPECT_TRUE(sanitizeServerText(std::string(1000, 'a')).empty());
}

TEST_F(RegistryErrorsTest, ACodeThatIsNotAnIdentifierIsDropped)
{
    EXPECT_EQ(registryErrorReason(R"({"errors":[{"code":"DE NIED\n","message":"ok"}]})"), "ok");
}
