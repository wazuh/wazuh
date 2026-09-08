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

/*
 * hc_fetch_cacerts() end to end over the real curl path against a fork-based
 * fake manager. Mirrors enroll_component_test.cpp's idiom: a genuine TLS
 * handshake and a real HTTP GET, not the mocked CacertsClientTest suite's
 * fake IHttpPerformer. hc_fetch_cacerts() is deliberately handle-less, exactly
 * like hc_enroll(): it must work before any hc_handle exists, at the same
 * first-boot bootstrap moment.
 */

#include "https_client.h"

#include "fakeManager.hpp"

#include <gtest/gtest.h>

#include <cstring>
#include <string>

namespace
{
    hc_config_t tlsConfig(uint16_t port)
    {
        hc_config_t config {};
        std::strncpy(config.server_host, "127.0.0.1", sizeof(config.server_host) - 1);
        config.server_port = port;
        // Deliberately left at the fail-closed default (HC_VERIFY_FULL, no ca_path):
        // hc_fetch_cacerts() must force verification off for this one call regardless,
        // since GET /cacerts is the unverified bootstrap leg by definition -- this is
        // what CacertsFetchIgnoresAConfiguredVerifyModeAndSucceeds below actually proves.
        config.request_timeout_ms = 30000;
        return config;
    }

    hc_cacerts_request_t cacertsRequest()
    {
        hc_cacerts_request_t request {};
        request.log = nullptr; // No sink: must tolerate this (first boot, no logger yet).
        return request;
    }
} // namespace

TEST(CacertsComponentTest, FetchesTheCertificateBodyFromTheFakeManager)
{
    constexpr uint16_t port = 44880;
    FakeManager manager {port, "", /*tls=*/true};

    const auto config = tlsConfig(port);
    const auto request = cacertsRequest();
    hc_cacerts_result_t result {};

    ASSERT_TRUE(hc_fetch_cacerts(&config, &request, &result));
    EXPECT_EQ(200, result.http_code);
    EXPECT_NE(nullptr, std::strstr(result.body, "-----BEGIN CERTIFICATE-----"));
    EXPECT_NE(nullptr, std::strstr(result.body, "-----END CERTIFICATE-----"));
}

// The whole point of this call: it must succeed over an UNVERIFIED connection to
// the fake manager's self-signed TLS certificate even when the caller's config
// asks for full verification with no CA configured -- a config that would make
// every other endpoint (e.g. hc_enroll()) fail closed before ever sending.
TEST(CacertsComponentTest, CacertsFetchIgnoresAConfiguredVerifyModeAndSucceeds)
{
    constexpr uint16_t port = 44881;
    FakeManager manager {port, "", /*tls=*/true};

    auto config = tlsConfig(port);
    config.verify_mode = HC_VERIFY_FULL; // No ca_path: would fail closed anywhere else.
    const auto request = cacertsRequest();
    hc_cacerts_result_t result {};

    ASSERT_TRUE(hc_fetch_cacerts(&config, &request, &result));
    EXPECT_EQ(200, result.http_code);
}

TEST(CacertsComponentTest, NullArgumentsAreRejectedWithoutTouchingTheNetwork)
{
    hc_cacerts_result_t result {};
    EXPECT_FALSE(hc_fetch_cacerts(nullptr, nullptr, &result));
    EXPECT_EQ(0, result.http_code);
}
