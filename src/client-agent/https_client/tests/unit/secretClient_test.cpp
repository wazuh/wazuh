/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * September 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "secretClient.hpp"

#include "fakeSysSeams.hpp"
#include "jwtTestSupport.hpp"
#include "mockFsProbe.hpp"
#include "mockHttpPerformer.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <string>

using ::testing::_;
using ::testing::Invoke;
using ::testing::NiceMock;

namespace
{
    const LogFn TEST_LOG {"https-client-test"}; // Sink unset: LOGFN_* are no-ops.

    ModuleConfig baseConfig()
    {
        ModuleConfig config;
        config.serverHost = "manager.example";
        config.serverPort = 1517;
        config.verifyMode = HC_VERIFY_NONE;
        config.requestTimeoutMs = 5000;
        config.agentId = "001";
        config.agentKeyHex = testAgentKeyHex();
        return config;
    }

    HttpResponse okResponse(const std::string& body)
    {
        HttpResponse response;
        response.status = TransportStatus::Ok;
        response.httpCode = 200;
        response.body = body;
        return response;
    }

    std::string headerValue(const HttpRequestSpec& spec, const std::string& prefix)
    {
        for (const auto& header : spec.headers)
        {
            if (header.rfind(prefix, 0) == 0)
            {
                return header;
            }
        }

        return {};
    }
} // namespace

TEST(SecretClientTest, PostsAnEmptyJsonObjectToTheLiteralTarget)
{
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    FakeClock clock; // default wall: 1700000000
    SecretClient client {baseConfig(), performer, fsProbe, clock, TEST_LOG};

    EXPECT_CALL(performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        EXPECT_EQ("/enroll/secret", spec.target);
        EXPECT_EQ(HttpMethod::Post, spec.method);
        EXPECT_EQ("application/json", spec.contentType);
        // `{}`, not an empty body: the request HAS no arguments -- the agent id comes from the
        // bearer -- and `{}` is what the manager documents as acceptable.
        // EXPECT_ rather than ASSERT_: the action must return an HttpResponse on every path, and
        // ASSERT_ expands to a bare `return;`.
        EXPECT_NE(nullptr, spec.body);

        if (spec.body != nullptr)
        {
            EXPECT_EQ("{}", std::string(reinterpret_cast<const char*>(spec.body), spec.bodyLength));
        }

        return okResponse(R"({"id":"001","reenroll_secret":"aa"})");
    }));

    const auto response = client.fetch();
    EXPECT_EQ(TransportStatus::Ok, response.status);
    EXPECT_EQ(200, response.httpCode);
}

TEST(SecretClientTest, SignsWithTheAgentRequestProfileNotTheEnrollProfile)
{
    // The distinction this route depends on: a `wazuh-enroll+jwt` whose kid is an agent id already
    // means "re-enrollment bearer", and the manager's AuthMiddleware -- which is what guards this
    // route -- would reject it. The credential here is the same one the control stream presents.
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    FakeClock clock; // default wall: 1700000000
    SecretClient client {baseConfig(), performer, fsProbe, clock, TEST_LOG};

    EXPECT_CALL(performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        EXPECT_EQ("protocol-version: 1", headerValue(spec, "protocol-version"));

        const auto authorization = headerValue(spec, "Authorization");
        const auto decoded = decodeBearer(authorization, testAgentKeyHex());
        EXPECT_TRUE(decoded.has_value());
        EXPECT_TRUE(decoded->signatureValid);
        EXPECT_EQ("wazuh-agent+jwt", decoded->header.at("typ"));
        EXPECT_EQ("001", decoded->header.at("kid"));
        EXPECT_EQ("001", decoded->claims.at("sub"));
        EXPECT_EQ(1700000000, decoded->claims.at("iat"));
        return okResponse("{}");
    }));

    client.fetch();
}

TEST(SecretClientTest, ConfiguredEndpointPrefixIsFoldedIntoTheTarget)
{
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    auto config = baseConfig();
    config.serverEndpoint = "wazuh-manager";
    FakeClock clock; // default wall: 1700000000
    SecretClient client {config, performer, fsProbe, clock, TEST_LOG};

    EXPECT_CALL(performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        // Routing only: the bearer binds the agent's identity, not the target, so a prefix
        // mismatch with the manager surfaces as 404 and never as 401.
        EXPECT_EQ("/wazuh-manager/enroll/secret", spec.target);
        return okResponse("{}");
    }));

    client.fetch();
}

TEST(SecretClientTest, AnUnusableKeySendsNothingAtAll)
{
    // Fail closed: an unsigned request would simply be answered 401, and reporting "nothing reached
    // the manager" (httpCode 0) is both truthful and what the caller's retry logic reads.
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    auto config = baseConfig();
    config.agentKeyHex = "not-hex";
    FakeClock clock; // default wall: 1700000000
    SecretClient client {config, performer, fsProbe, clock, TEST_LOG};

    EXPECT_CALL(performer, perform(_)).Times(0);

    const auto response = client.fetch();
    EXPECT_EQ(TransportStatus::OtherError, response.status);
    EXPECT_EQ(0, response.httpCode);
}

TEST(SecretClientTest, AnInvalidTransportConfigSendsNothingAtAll)
{
    // The fail-closed TLS policy, same as EnrollClient/CacertsClient: a verifying mode with no CA
    // never reaches libcurl.
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    auto config = baseConfig();
    config.verifyMode = HC_VERIFY_FULL;
    config.caPath.clear();
    FakeClock clock; // default wall: 1700000000
    SecretClient client {config, performer, fsProbe, clock, TEST_LOG};

    EXPECT_CALL(performer, perform(_)).Times(0);

    const auto response = client.fetch();
    EXPECT_EQ(TransportStatus::TlsFail, response.status);
    EXPECT_EQ(0, response.httpCode);
}

TEST(SecretClientTest, TheManagersAnswerIsHandedBackUntouched)
{
    // No retry loop and no interpretation: 429 (the shared /enroll rate limit during a fleet-wide
    // bootstrap wave) and 503 both travel to the C caller as they are, with Retry-After intact.
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    FakeClock clock; // default wall: 1700000000
    SecretClient client {baseConfig(), performer, fsProbe, clock, TEST_LOG};

    HttpResponse throttled;
    throttled.status = TransportStatus::Ok;
    throttled.httpCode = 429;
    throttled.retryAfterSeconds = 7;
    throttled.body = R"({"error":"rate_limited"})";

    EXPECT_CALL(performer, perform(_)).WillOnce(::testing::Return(throttled));

    const auto response = client.fetch();
    EXPECT_EQ(429, response.httpCode);
    EXPECT_EQ(7, response.retryAfterSeconds);
    EXPECT_EQ(R"({"error":"rate_limited"})", response.body);
}
