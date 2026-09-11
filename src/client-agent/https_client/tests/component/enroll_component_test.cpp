/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/*
 * hc_enroll() end to end over the real curl path against a fork-based fake
 * manager (#38465). This is what the mocked EnrollClientTest suite cannot
 * prove: a genuine TLS handshake, a real HTTP round trip, and a signature the
 * fake manager verifies with its own independently-invoked EnrollSigner --
 * the same reuse-the-production-signer idiom the rest of this component
 * suite already uses for JwtSigner (facadeE2e/tlsVerification). hc_enroll()
 * is deliberately handle-less (no hc_create()/hc_start() involved): it must
 * work before any handle exists, exactly as it does on a real first boot.
 */

#include "https_client.h"

#include "fakeManager.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <gtest/gtest.h>

#include <cstdio>
#include <cstring>
#include <string>

namespace
{
    const std::string PASSWORD = "MyEnrollmentSecret123";
    const std::string BODY = R"({"name":"agent01","version":"5.0.0"})";

    // hc_enroll() is a pure C-ABI call: hc_config_t has no scheme field (that
    // is a ModuleConfig-only test seam other component tests reach past the
    // ABI to flip), so it always speaks real HTTPS in production -- and so
    // must every FakeManager here (tls=true), exactly like
    // facadeE2e/tlsVerification's ABI-level tests.
    hc_config_t tlsConfig(uint16_t port)
    {
        hc_config_t config {};
        std::strncpy(config.server_host, "127.0.0.1", sizeof(config.server_host) - 1);
        config.server_port = port;
        config.verify_mode = HC_VERIFY_NONE;
        config.request_timeout_ms = 30000;
        config.backoff_base_ms = 10;
        config.backoff_cap_ms = 50;
        return config;
    }

    hc_enroll_request_t enrollRequest(const std::string& body, const std::string& password)
    {
        hc_enroll_request_t request {};
        std::strncpy(request.body_json, body.c_str(), sizeof(request.body_json) - 1);
        std::strncpy(request.password, password.c_str(), sizeof(request.password) - 1);
        request.log = nullptr; // No sink: hc_enroll() must tolerate this (first boot, no logger yet).
        return request;
    }

    // A self-signed cert + key pair written to disk purely so a client-cert
    // config passes ModuleConfig::validateClientCert()'s file-readability
    // check; the fake manager's plain httplib::SSLServer never asks for one,
    // so this proves a configured cert does not disturb the enroll flow when
    // the manager does not require mTLS (a realistic deployment case), not
    // that mTLS itself was verified end to end.
    struct TempCertPair
    {
        std::string certPath;
        std::string keyPath;

        TempCertPair()
        {
            EVP_PKEY* pkey = EVP_RSA_gen(2048);
            X509* cert = X509_new();
            ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
            X509_gmtime_adj(X509_get_notBefore(cert), 0);
            X509_gmtime_adj(X509_get_notAfter(cert), 60L * 60L);
            X509_set_pubkey(cert, pkey);
            X509_NAME* name = X509_get_subject_name(cert);
            X509_NAME_add_entry_by_txt(
                name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("agent01"), -1, -1, 0);
            X509_set_issuer_name(cert, name);
            X509_sign(cert, pkey, EVP_sha256());

            certPath = ::testing::TempDir() + "hc_enroll_cert_" + std::to_string(::getpid()) + ".crt";
            keyPath = ::testing::TempDir() + "hc_enroll_key_" + std::to_string(::getpid()) + ".key";

            if (std::FILE* file = std::fopen(certPath.c_str(), "wb"))
            {
                PEM_write_X509(file, cert);
                std::fclose(file);
            }

            if (std::FILE* file = std::fopen(keyPath.c_str(), "wb"))
            {
                PEM_write_PrivateKey(file, pkey, nullptr, nullptr, 0, nullptr, nullptr);
                std::fclose(file);
            }

            X509_free(cert);
            EVP_PKEY_free(pkey);
        }

        ~TempCertPair()
        {
            std::remove(certPath.c_str());
            std::remove(keyPath.c_str());
        }

        TempCertPair(const TempCertPair&) = delete;
        TempCertPair& operator=(const TempCertPair&) = delete;
    };
} // namespace

TEST(EnrollComponentTest, OpenModeSucceedsAgainstFakeManager)
{
    constexpr uint16_t port = 44870;
    FakeManager manager {port, "", /*tls=*/true};

    const auto config = tlsConfig(port);
    const auto request = enrollRequest(BODY, "");
    hc_enroll_result_t result {};

    ASSERT_TRUE(hc_enroll(&config, &request, &result));
    EXPECT_EQ(200, result.http_code);
    EXPECT_NE(nullptr, std::strstr(result.body, "\"id\":\"042\""));
    EXPECT_NE(nullptr, std::strstr(result.body, "\"name\":\"agent01\""));
}

TEST(EnrollComponentTest, PasswordModeSucceedsWithCorrectSignature)
{
    constexpr uint16_t port = 44871;
    FakeManager manager {port,
                         /*keyHex=*/"",
                         /*tls=*/true,
                         /*settingsFlipAfter=*/0,
                         /*configBlob=*/ {},
                         /*statelessMaxBody=*/0,
                         /*rotateKeyAfterNotifies=*/0,
                         /*rotatedKeyHex=*/ {},
                         /*statefulHoldFile=*/ {},
                         /*vdFeedOffset=*/0,
                         /*scanVdRejectFirstNAttempts=*/0,
                         /*enrollPassword=*/PASSWORD};

    const auto config = tlsConfig(port);
    const auto request = enrollRequest(BODY, PASSWORD);
    hc_enroll_result_t result {};

    ASSERT_TRUE(hc_enroll(&config, &request, &result));
    EXPECT_EQ(200, result.http_code);
    EXPECT_NE(nullptr, std::strstr(result.body, "\"name\":\"agent01\""));
}

TEST(EnrollComponentTest, PasswordModeIsRejectedWhenPasswordsDiffer)
{
    constexpr uint16_t port = 44872;
    FakeManager manager {port,
                         "",
                         true,
                         0,
                         {},
                         0,
                         0,
                         {},
                         {},
                         0,
                         0,
                         /*enrollPassword=*/PASSWORD};

    const auto config = tlsConfig(port);
    const auto request = enrollRequest(BODY, "WrongPassword");
    hc_enroll_result_t result {};

    // Transport itself succeeds (a real HTTP response came back); it is an
    // application-level 401 the C caller (w_enrollment_process_response) must
    // map, not a transport failure -- confirmed here, not assumed.
    ASSERT_TRUE(hc_enroll(&config, &request, &result));
    EXPECT_EQ(401, result.http_code);
}

TEST(EnrollComponentTest, ForcedApplicationErrorsPassThroughUnmapped)
{
    constexpr uint16_t port = 44873;
    FakeManager manager {port, "", true, 0, {}, 0, 0, {}, {}, 0, 0, {}, /*enrollForcedStatus=*/409};

    const auto config = tlsConfig(port);
    const auto request = enrollRequest(BODY, "");
    hc_enroll_result_t result {};

    ASSERT_TRUE(hc_enroll(&config, &request, &result));
    EXPECT_EQ(409, result.http_code);
}

TEST(EnrollComponentTest, ClientCertConfigCoexistsWithPasswordOverRealHandshake)
{
    constexpr uint16_t port = 44874;
    FakeManager manager {port,
                         "",
                         /*tls=*/true,
                         0,
                         {},
                         0,
                         0,
                         {},
                         {},
                         0,
                         0,
                         /*enrollPassword=*/PASSWORD};

    TempCertPair certPair;
    auto config = tlsConfig(port);
    config.verify_mode = HC_VERIFY_NONE; // Self-signed fake manager cert.
    std::strncpy(config.client_cert, certPair.certPath.c_str(), sizeof(config.client_cert) - 1);
    std::strncpy(config.client_key, certPair.keyPath.c_str(), sizeof(config.client_key) - 1);

    const auto request = enrollRequest(BODY, PASSWORD);
    hc_enroll_result_t result {};

    ASSERT_TRUE(hc_enroll(&config, &request, &result));
    EXPECT_EQ(200, result.http_code);
}

TEST(EnrollComponentTest, NullArgumentsAreRejectedWithoutTouchingTheNetwork)
{
    hc_enroll_result_t result {};
    EXPECT_FALSE(hc_enroll(nullptr, nullptr, &result));
    EXPECT_EQ(0, result.http_code);
}
