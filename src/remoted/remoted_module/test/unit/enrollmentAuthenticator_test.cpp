/*
 * Wazuh remoted module - EnrollmentAuthenticator unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Exercises EnrollmentAuthenticator in isolation -- no sockets, no transport -- covering the
// per-mode pass/deny matrix and the WazuhEnroll CMAC tamper scenarios a real E2E test re-runs
// over the wire.

#include <cstdio>
#include <fstream>
#include <string>
#include <unistd.h>

#include <gtest/gtest.h>

#include "auth/cmac.hpp"
#include "enrollment/enrollmentAuthenticator.hpp"

using namespace remoted::enrollment;
using remoted::auth::AuthError;
using remoted::auth::Cmac;
using remoted::auth::PasswordKeySource;
using remoted::auth::toLowerHex;

namespace
{
    constexpr std::int64_t kNow = 1'784'238'000;

    std::string writePasswordFile(const std::string& password)
    {
        const std::string path = "/tmp/enrollmentAuthenticator_test_" + std::to_string(getpid()) + ".pass";
        std::ofstream file(path);
        file << password << "\n";
        return path;
    }

    // Builds the same canonical byte sequence EnrollmentAuthenticator verifies in Password mode,
    // so tests can sign a request without a production signer.
    std::string sign(const std::vector<std::uint8_t>& key,
                     std::string_view method,
                     std::string_view target,
                     std::string_view body,
                     std::int64_t ts)
    {
        Cmac cmac(key);
        cmac.update("WAZUH-ENROLL\n");
        cmac.update("1\n");
        cmac.update(method);
        cmac.update("\n");
        cmac.update(target);
        cmac.update("\n");
        cmac.update(std::to_string(ts));
        cmac.update("\n");
        cmac.update(body);
        const auto mac = cmac.finalize();
        return "WazuhEnroll " + std::to_string(ts) + ":" + toLowerHex(mac.data(), mac.size());
    }

    struct PasswordFixture : public ::testing::Test
    {
        std::string path = writePasswordFile("MyEnrollmentSecret123");
        std::shared_ptr<PasswordKeySource> keySource = std::make_shared<PasswordKeySource>(path);
        EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {true}, keySource};

        void TearDown() override
        {
            std::remove(path.c_str());
        }

        std::string signValid(std::string_view method = "POST",
                              std::string_view target = "/enroll",
                              std::string_view body = R"({"name":"agent1"})",
                              std::int64_t ts = kNow)
        {
            const auto key = keySource->currentKey();
            return sign(*key, method, target, body, ts);
        }
    };
} // namespace

// -----------------------------------------------------------------------------
// Password mode
// -----------------------------------------------------------------------------

TEST_F(PasswordFixture, ValidSignatureIsAccepted)
{
    const std::string auth = signValid();
    EXPECT_EQ(authenticator.authenticate(auth, "POST", "/enroll", R"({"name":"agent1"})", kNow), std::nullopt);
}

TEST_F(PasswordFixture, MissingAuthorizationHeaderIsRejected)
{
    const auto err = authenticator.authenticate("", "POST", "/enroll", R"({"name":"agent1"})", kNow);
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::MissingAuthorization);
}

TEST_F(PasswordFixture, WrongSchemeIsRejected)
{
    const auto err =
        authenticator.authenticate("Wazuh 001:1739999999:deadbeef", "POST", "/enroll", R"({"name":"agent1"})", kNow);
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::MalformedAuthorization);
}

TEST_F(PasswordFixture, NonHexMacIsRejected)
{
    const auto err = authenticator.authenticate(
        "WazuhEnroll 1784238000:not-a-valid-mac-hex-string-000", "POST", "/enroll", "{}", kNow);
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::MalformedAuthorization);
}

TEST_F(PasswordFixture, NonNumericTimestampIsRejected)
{
    const std::string mac(32, 'a');
    const auto err = authenticator.authenticate("WazuhEnroll notanumber:" + mac, "POST", "/enroll", "{}", kNow);
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::MalformedAuthorization);
}

TEST_F(PasswordFixture, TamperedBodyIsRejected)
{
    const std::string auth = signValid("POST", "/enroll", R"({"name":"agent1"})", kNow);
    const auto err = authenticator.authenticate(auth, "POST", "/enroll", R"({"name":"agent2"})", kNow);
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::InvalidMac);
}

TEST_F(PasswordFixture, TamperedTargetIsRejected)
{
    const std::string auth = signValid("POST", "/enroll", R"({"name":"agent1"})", kNow);
    const auto err = authenticator.authenticate(auth, "POST", "/other", R"({"name":"agent1"})", kNow);
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::InvalidMac);
}

TEST_F(PasswordFixture, WrongKeyIsRejected)
{
    const std::vector<std::uint8_t> otherKey(32, 0x42);
    const std::string auth = sign(otherKey, "POST", "/enroll", R"({"name":"agent1"})", kNow);
    const auto err = authenticator.authenticate(auth, "POST", "/enroll", R"({"name":"agent1"})", kNow);
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::InvalidMac);
}

TEST_F(PasswordFixture, ExpiredTimestampIsRejected)
{
    const std::int64_t oldTs = kNow - 301; // just past the 300s default window
    const std::string auth = signValid("POST", "/enroll", "{}", oldTs);
    const auto err = authenticator.authenticate(auth, "POST", "/enroll", "{}", kNow);
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::ExpiredRequest);
}

TEST_F(PasswordFixture, FutureTimestampIsRejected)
{
    const std::int64_t futureTs = kNow + 31; // just past the 30s default skew
    const std::string auth = signValid("POST", "/enroll", "{}", futureTs);
    const auto err = authenticator.authenticate(auth, "POST", "/enroll", "{}", kNow);
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::FutureRequest);
}

TEST(EnrollmentAuthenticatorTest, PasswordModeMissingKeyFileFailsClosed)
{
    // Points at a file that was never written: PasswordKeySource::currentKey() stays nullopt.
    // Fail-closed is security-critical here -- must be MissingKey/401, never treated as Open mode.
    auto keySource = std::make_shared<PasswordKeySource>("/tmp/enrollmentAuthenticator_test_absent.pass");
    EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {true}, keySource};

    const std::string mac(32, 'a');
    const auto err =
        authenticator.authenticate("WazuhEnroll " + std::to_string(kNow) + ":" + mac, "POST", "/enroll", "{}", kNow);
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(*err, AuthError::MissingKey);
}

// -----------------------------------------------------------------------------
// requirePassword=false: passes unconditionally, regardless of whether the listener separately
// requires a client certificate ("mTLS-only") or not ("Open") -- this class has no notion of
// mTLS at all, since a client certificate is the TLS listener's concern, never this one's (see
// the class comment in enrollmentAuthenticator.hpp).
// -----------------------------------------------------------------------------

TEST(EnrollmentAuthenticatorTest, RequirePasswordFalseAlwaysPasses)
{
    EnrollmentAuthenticator authenticator {EnrollmentAuthConfig {false}, nullptr};
    EXPECT_EQ(authenticator.authenticate("", "POST", "/enroll", "{}", kNow), std::nullopt);
    EXPECT_EQ(authenticator.authenticate("garbage", "POST", "/enroll", "{}", kNow), std::nullopt);
}
