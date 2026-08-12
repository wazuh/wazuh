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

#include "mockFsProbe.hpp"
#include "moduleConfig.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstring>

using ::testing::NiceMock;
using ::testing::Return;

namespace
{
    hc_config_t minimalConfig()
    {
        hc_config_t config {};
        std::strncpy(config.server_host, "manager.example", sizeof(config.server_host) - 1);
        std::strncpy(config.agent_id, "001", sizeof(config.agent_id) - 1);
        config.verify_mode = HC_VERIFY_NONE;
        return config;
    }

    const LogFn TEST_LOG {"https-client-test"}; // Sink unset: LOGFN_* are no-ops.
} // namespace

TEST(ModuleConfigTest, DefaultsAppliedOnZeroFields)
{
    const auto typed = ModuleConfig::fromC(minimalConfig());
    EXPECT_EQ(443, typed.serverPort);
    EXPECT_EQ(1024u * 1024u, typed.batchSizeBytes);
    EXPECT_EQ(10000u, typed.batchIntervalMs);
    EXPECT_EQ(4u, typed.bufferCapMultiplier);
    EXPECT_EQ(10u, typed.notifyIntervalS);
    EXPECT_EQ(60u, typed.rejectedRetryIntervalS);
    EXPECT_EQ(10000u, typed.requestTimeoutMs);
    EXPECT_EQ(120000u, typed.statefulTimeoutMs);
    EXPECT_EQ(1000u, typed.backoffBaseMs);
    EXPECT_EQ(60000u, typed.backoffCapMs);
    EXPECT_EQ(5000u, typed.drainTimeoutMs);
    EXPECT_EQ(200ULL * 1024 * 1024, typed.wpkMaxDownloadBytes);
    EXPECT_FALSE(typed.statsEnabled);
    EXPECT_EQ(60u, typed.statsIntervalS);
    EXPECT_FALSE(typed.configReportEnabled);
    EXPECT_EQ(3600u, typed.configReportIntervalS);
    EXPECT_FALSE(typed.httpsCompressionEnabled);
}

TEST(ModuleConfigTest, ZeroedVerifyModeIsFullFailClosed)
{
    hc_config_t config {};
    EXPECT_EQ(HC_VERIFY_FULL, ModuleConfig::fromC(config).verifyMode);
}

TEST(ModuleConfigTest, ExplicitValuesAreKept)
{
    auto config = minimalConfig();
    config.server_port = 27840;
    config.batch_size_bytes = 2048;
    config.notify_interval_s = 5;
    const auto typed = ModuleConfig::fromC(config);
    EXPECT_EQ(27840, typed.serverPort);
    EXPECT_EQ(2048u, typed.batchSizeBytes);
    EXPECT_EQ(5u, typed.notifyIntervalS);
}

TEST(ModuleConfigTest, UnterminatedFixedFieldIsBounded)
{
    auto config = minimalConfig();
    std::memset(config.agent_id, 'A', sizeof(config.agent_id)); // No NUL at all.
    const auto typed = ModuleConfig::fromC(config);
    EXPECT_EQ(sizeof(config.agent_id), typed.agentId.size());
    EXPECT_EQ(std::string(sizeof(config.agent_id), 'A'), typed.agentId);
}

TEST(ModuleConfigTest, BaseUrlFormat)
{
    auto config = minimalConfig();
    config.server_port = 27840;
    EXPECT_EQ("https://manager.example:27840", ModuleConfig::fromC(config).baseUrl());
}

TEST(ModuleConfigTest, BaseUrlBracketsIpv6Literals)
{
    auto config = minimalConfig();
    std::strncpy(config.server_host, "2001:db8::1", sizeof(config.server_host) - 1);
    config.server_port = 443;
    // The IPv6 literal must be bracketed so the last group is not read as a port.
    EXPECT_EQ("https://[2001:db8::1]:443", ModuleConfig::fromC(config).baseUrl());
}

TEST(ModuleConfigTest, BaseUrlLeavesIpv4AndHostnamesUnbracketed)
{
    auto ipv4 = minimalConfig();
    std::strncpy(ipv4.server_host, "10.0.0.1", sizeof(ipv4.server_host) - 1);
    ipv4.server_port = 8443;
    EXPECT_EQ("https://10.0.0.1:8443", ModuleConfig::fromC(ipv4).baseUrl());
}

TEST(ModuleConfigTest, ValidateRejectsMissingHostOrId)
{
    NiceMock<MockFsProbe> fsProbe;
    auto noHost = minimalConfig();
    noHost.server_host[0] = '\0';
    EXPECT_FALSE(ModuleConfig::fromC(noHost).validate(fsProbe, TEST_LOG));

    auto noId = minimalConfig();
    noId.agent_id[0] = '\0';
    EXPECT_FALSE(ModuleConfig::fromC(noId).validate(fsProbe, TEST_LOG));
}

TEST(ModuleConfigTest, ValidateRejectsUnknownVerifyMode)
{
    NiceMock<MockFsProbe> fsProbe;
    auto config = minimalConfig();
    config.verify_mode = 7;
    EXPECT_FALSE(ModuleConfig::fromC(config).validate(fsProbe, TEST_LOG));
}

TEST(ModuleConfigTest, FullModeFailsClosedWithoutCa)
{
    ::testing::StrictMock<MockFsProbe> fsProbe; // Probe must not even be asked.
    auto config = minimalConfig();
    config.verify_mode = HC_VERIFY_FULL;
    EXPECT_FALSE(ModuleConfig::fromC(config).validate(fsProbe, TEST_LOG));
}

TEST(ModuleConfigTest, FullModeFailsClosedWhenCaUnreadable)
{
    MockFsProbe fsProbe;
    auto config = minimalConfig();
    config.verify_mode = HC_VERIFY_FULL;
    std::strncpy(config.ca_path, "/etc/ca.pem", sizeof(config.ca_path) - 1);
    EXPECT_CALL(fsProbe, isReadableFile("/etc/ca.pem")).WillOnce(Return(false));
    EXPECT_FALSE(ModuleConfig::fromC(config).validate(fsProbe, TEST_LOG));
}

TEST(ModuleConfigTest, FullModeValidWithReadableCa)
{
    MockFsProbe fsProbe;
    auto config = minimalConfig();
    config.verify_mode = HC_VERIFY_FULL;
    std::strncpy(config.ca_path, "/etc/ca.pem", sizeof(config.ca_path) - 1);
    EXPECT_CALL(fsProbe, isReadableFile("/etc/ca.pem")).WillOnce(Return(true));
    EXPECT_TRUE(ModuleConfig::fromC(config).validate(fsProbe, TEST_LOG));
}

TEST(ModuleConfigTest, CertModeAlsoRequiresCa)
{
    NiceMock<MockFsProbe> fsProbe;
    auto config = minimalConfig();
    config.verify_mode = HC_VERIFY_CERT;
    EXPECT_FALSE(ModuleConfig::fromC(config).validate(fsProbe, TEST_LOG));
}

TEST(ModuleConfigTest, NoneModeIsValidWithoutCa)
{
    NiceMock<MockFsProbe> fsProbe;
    EXPECT_TRUE(ModuleConfig::fromC(minimalConfig()).validate(fsProbe, TEST_LOG));
}

TEST(ModuleConfigTest, ClientCertRequiresBothHalves)
{
    NiceMock<MockFsProbe> fsProbe;
    ON_CALL(fsProbe, isReadableFile(::testing::_)).WillByDefault(Return(true));

    auto certOnly = minimalConfig();
    std::strncpy(certOnly.client_cert, "/etc/agent.pem", sizeof(certOnly.client_cert) - 1);
    EXPECT_FALSE(ModuleConfig::fromC(certOnly).validate(fsProbe, TEST_LOG));

    auto keyOnly = minimalConfig();
    std::strncpy(keyOnly.client_key, "/etc/agent.key", sizeof(keyOnly.client_key) - 1);
    EXPECT_FALSE(ModuleConfig::fromC(keyOnly).validate(fsProbe, TEST_LOG));
}

TEST(ModuleConfigTest, ClientCertFilesMustBeReadable)
{
    MockFsProbe fsProbe;
    auto config = minimalConfig();
    std::strncpy(config.client_cert, "/etc/agent.pem", sizeof(config.client_cert) - 1);
    std::strncpy(config.client_key, "/etc/agent.key", sizeof(config.client_key) - 1);
    EXPECT_CALL(fsProbe, isReadableFile("/etc/agent.pem")).WillOnce(Return(false));
    EXPECT_FALSE(ModuleConfig::fromC(config).validate(fsProbe, TEST_LOG));
}

TEST(ModuleConfigTest, ClientCertValidWhenBothReadable)
{
    MockFsProbe fsProbe;
    auto config = minimalConfig();
    std::strncpy(config.client_cert, "/etc/agent.pem", sizeof(config.client_cert) - 1);
    std::strncpy(config.client_key, "/etc/agent.key", sizeof(config.client_key) - 1);
    EXPECT_CALL(fsProbe, isReadableFile("/etc/agent.pem")).WillOnce(Return(true));
    EXPECT_CALL(fsProbe, isReadableFile("/etc/agent.key")).WillOnce(Return(true));
    EXPECT_TRUE(ModuleConfig::fromC(config).validate(fsProbe, TEST_LOG));
}
