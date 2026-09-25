/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * September 8, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "cacertsClient.hpp"

#include "mockFsProbe.hpp"
#include "mockHttpPerformer.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SaveArg;

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
} // namespace

TEST(CacertsClientTest, SendsAGetWithNoBodyToTheLiteralCacertsTarget)
{
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    CacertsClient client {baseConfig(), performer, fsProbe, TEST_LOG, true};

    EXPECT_CALL(performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        EXPECT_EQ("/cacerts", spec.target);
        EXPECT_EQ(HttpMethod::Get, spec.method);
        EXPECT_EQ(nullptr, spec.body);
        EXPECT_EQ(0u, spec.bodyLength);
        return okResponse("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n");
    }));

    const auto response = client.fetch();
    EXPECT_EQ(TransportStatus::Ok, response.status);
    EXPECT_EQ(200, response.httpCode);
    EXPECT_EQ("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n", response.body);
}

// Decided behavior under test (see cacertsClient.hpp's doc comment): /cacerts is
// folded through the configured prefix same as every other endpoint (EnrollClientTest's
// ConfiguredEndpointIsFoldedIntoTheTarget pins the identical behavior for /enroll).
TEST(CacertsClientTest, ConfiguredEndpointPrefixIsFoldedIntoTheTarget)
{
    NiceMock<MockFsProbe> fsProbe;
    NiceMock<MockHttpPerformer> performer;
    auto config = baseConfig();
    config.serverEndpoint = "wazuh-manager";
    CacertsClient client {config, performer, fsProbe, TEST_LOG, true};

    EXPECT_CALL(performer, perform(_))
    .WillOnce(Invoke(
                  [&](const HttpRequestSpec & spec)
    {
        EXPECT_EQ("/wazuh-manager/cacerts", spec.target);
        return okResponse("cert-body");
    }));

    client.fetch();
}

/* The refresh leg of #39321 uses this same class with the agent's real posture, because the
 * contract forbids ever fetching a replacement bundle over an unverified connection. What the
 * class must NOT do is re-derive the decision: a verifying config reaches the wire verified. */
TEST(CacertsClientTest, AVerifiedConfigIsSentVerified)
{
    MockHttpPerformer performer;
    MockFsProbe fsProbe;
    auto config = baseConfig();
    config.verifyMode = HC_VERIFY_FULL;
    config.caPath = "etc/certs/root-ca.pem";

    EXPECT_CALL(fsProbe, isReadableFile("etc/certs/root-ca.pem")).WillRepeatedly(Return(true));

    HttpRequestSpec sent;
    EXPECT_CALL(performer, perform(_)).WillOnce(DoAll(SaveArg<0>(&sent), Return(HttpResponse {})));

    CacertsClient client {config, performer, fsProbe, TEST_LOG, /*unverifiedByDesign=*/false};
    client.fetch();

    EXPECT_EQ(HttpMethod::Get, sent.method);
    EXPECT_EQ("/cacerts", sent.target);
}

TEST(CacertsClientTest, RejectsWithoutSendingWhenTransportConfigIsInvalid)
{
    ::testing::StrictMock<MockFsProbe> fsProbe;         // Must not even be asked.
    ::testing::StrictMock<MockHttpPerformer> performer; // Must never be called.

    auto config = baseConfig();
    config.clientCert = "/etc/agent.pem"; // Cert without a matching key: fails validateClientCert().
    CacertsClient client {config, performer, fsProbe, TEST_LOG, true};

    const auto response = client.fetch();
    EXPECT_EQ(TransportStatus::TlsFail, response.status);
    EXPECT_EQ(0, response.httpCode);
}
