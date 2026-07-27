/*
 * Wazuh auth middleware (framework-agnostic) - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 20, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Exercises AuthMiddleware in isolation -- no sockets, no transport --
// covering the tamper scenarios a real transport's component tests re-run
// end-to-end over the wire.
#include <cstdio>
#include <fstream>
#include <unistd.h>

#include <gtest/gtest.h>

#include "auth/authMiddleware.hpp"
#include "auth/cmac.hpp"
#include "auth/keystore.hpp"

using namespace remoted::auth;

namespace
{

    constexpr std::int64_t kNow = 1'784'238'000;
    const std::vector<std::uint8_t> kKey = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

    // Writes a one-agent client.keys to a scratch path so Keystore has
    // something real to parse, instead of a stub built just for tests.
    std::string writeClientKeysFile(const std::string& agentId, const std::vector<std::uint8_t>& key)
    {
        const std::string path = "/tmp/authMiddleware_test_" + std::to_string(getpid()) + ".keys";
        std::ofstream file(path);
        file << agentId << " test-agent any " << toLowerHex(key.data(), key.size()) << "\n";
        return path;
    }

    struct Fixture
    {
        std::string path = writeClientKeysFile("001", kKey);
        std::shared_ptr<Keystore> keyStore = std::make_shared<Keystore>(path);
        AuthMiddleware middleware {AuthConfig {}, keyStore};

        ~Fixture()
        {
            std::remove(path.c_str());
        }

        std::variant<AuthenticatedRequest, AuthError> run(std::string_view protocolVersion,
                                                          std::string_view authorization,
                                                          std::string_view method,
                                                          std::string_view target,
                                                          std::string_view body,
                                                          std::int64_t now = kNow)
        {
            auto sessionOrErr = middleware.beginSession(protocolVersion, authorization, method, target, now);
            if (std::holds_alternative<AuthError>(sessionOrErr))
            {
                return std::get<AuthError>(sessionOrErr);
            }
            auto& session = std::get<AuthMiddleware::Session>(sessionOrErr);
            const auto err = session.update(reinterpret_cast<const std::uint8_t*>(body.data()), body.size());
            if (err != AuthError::None)
            {
                return err;
            }
            return session.finish();
        }

        // Builds the same canonical byte sequence AuthMiddleware verifies, so
        // tests can sign a request without a production signer.
        std::string
        sign(std::string_view method, std::string_view target, std::string_view body, std::int64_t ts = kNow)
        {
            Cmac cmac(kKey);
            cmac.update("WAZUH-REQUEST\n");
            cmac.update("1\n");
            cmac.update(method);
            cmac.update("\n");
            cmac.update(target);
            cmac.update("\n");
            cmac.update("001\n");
            cmac.update(std::to_string(ts));
            cmac.update("\n");
            cmac.update(body);
            const auto mac = cmac.finalize();
            return toLowerHex(mac.data(), mac.size());
        }
    };

    TEST(Middleware, ValidRequestSucceeds)
    {
        Fixture f;
        const std::string body = "H {\"wazuh\":{\"agent\":{\"id\":\"001\"}}}\nE 1:/var/log/syslog:hi";
        const auto mac = f.sign("POST", "/stateless", body);
        const auto result = f.run("1", "Wazuh 001:" + std::to_string(kNow) + ":" + mac, "POST", "/stateless", body);
        ASSERT_TRUE(std::holds_alternative<AuthenticatedRequest>(result));
        const auto& req = std::get<AuthenticatedRequest>(result);
        EXPECT_EQ(req.agentId, "001");
        EXPECT_EQ(req.method, "POST");
        EXPECT_EQ(req.requestTarget, "/stateless");
    }

    TEST(Middleware, ModifiedBodyIsRejected)
    {
        Fixture f;
        const std::string signedBody = "original";
        const auto mac = f.sign("POST", "/stateless", signedBody);
        const auto result =
            f.run("1", "Wazuh 001:" + std::to_string(kNow) + ":" + mac, "POST", "/stateless", "tampered!");
        ASSERT_TRUE(std::holds_alternative<AuthError>(result));
        EXPECT_EQ(std::get<AuthError>(result), AuthError::InvalidMac);
    }

    TEST(Middleware, ModifiedMethodIsRejected)
    {
        Fixture f;
        const std::string body = "body";
        const auto mac = f.sign("POST", "/stateless", body);
        const auto result = f.run("1", "Wazuh 001:" + std::to_string(kNow) + ":" + mac, "PUT", "/stateless", body);
        ASSERT_TRUE(std::holds_alternative<AuthError>(result));
        EXPECT_EQ(std::get<AuthError>(result), AuthError::InvalidMac);
    }

    TEST(Middleware, ModifiedTargetIsRejected)
    {
        Fixture f;
        const std::string body = "body";
        const auto mac = f.sign("POST", "/stateless", body);
        const auto result = f.run("1", "Wazuh 001:" + std::to_string(kNow) + ":" + mac, "POST", "/other", body);
        ASSERT_TRUE(std::holds_alternative<AuthError>(result));
        EXPECT_EQ(std::get<AuthError>(result), AuthError::InvalidMac);
    }

    TEST(Middleware, ModifiedProtocolVersionIsRejected)
    {
        Fixture f;
        const std::string body = "body";
        const auto mac = f.sign("POST", "/stateless", body);
        const auto result = f.run("2", "Wazuh 001:" + std::to_string(kNow) + ":" + mac, "POST", "/stateless", body);
        ASSERT_TRUE(std::holds_alternative<AuthError>(result));
        EXPECT_EQ(std::get<AuthError>(result), AuthError::UnsupportedProtocolVersion);
    }

    TEST(Middleware, ExpiredTimestampIsRejected)
    {
        Fixture f;
        const std::string body = "body";
        const auto oldTs = kNow - 301;
        const auto mac = f.sign("POST", "/stateless", body, oldTs);
        const auto result = f.run("1", "Wazuh 001:" + std::to_string(oldTs) + ":" + mac, "POST", "/stateless", body);
        ASSERT_TRUE(std::holds_alternative<AuthError>(result));
        EXPECT_EQ(std::get<AuthError>(result), AuthError::ExpiredRequest);
    }

    TEST(Middleware, FutureTimestampIsRejected)
    {
        Fixture f;
        const std::string body = "body";
        const auto futureTs = kNow + 31;
        const auto mac = f.sign("POST", "/stateless", body, futureTs);
        const auto result = f.run("1", "Wazuh 001:" + std::to_string(futureTs) + ":" + mac, "POST", "/stateless", body);
        ASSERT_TRUE(std::holds_alternative<AuthError>(result));
        EXPECT_EQ(std::get<AuthError>(result), AuthError::FutureRequest);
    }

    TEST(Middleware, UnknownAgentIsRejected)
    {
        Fixture f;
        const std::string body = "body";
        const auto result = f.run(
            "1", "Wazuh 999:" + std::to_string(kNow) + ":deadbeefdeadbeefdeadbeefdeadbeef", "POST", "/stateless", body);
        ASSERT_TRUE(std::holds_alternative<AuthError>(result));
        EXPECT_EQ(std::get<AuthError>(result), AuthError::UnknownAgent);
    }

    TEST(Middleware, NonNumericAgentIdInAuthorizationIsRejected)
    {
        // An agent id is always numeric by design -- a non-digit agent-id segment must fail at
        // header-parsing time (MalformedAuthorization), before it ever reaches the Keystore lookup.
        Fixture f;
        const std::string body = "body";
        const auto result = f.run(
            "1", "Wazuh abc:" + std::to_string(kNow) + ":deadbeefdeadbeefdeadbeefdeadbeef", "POST", "/stateless", body);
        ASSERT_TRUE(std::holds_alternative<AuthError>(result));
        EXPECT_EQ(std::get<AuthError>(result), AuthError::MalformedAuthorization);
    }

    TEST(Middleware, MalformedAuthorizationIsRejected)
    {
        Fixture f;
        const auto result = f.run("1", "Wazuh not-even-close", "POST", "/stateless", "body");
        ASSERT_TRUE(std::holds_alternative<AuthError>(result));
        EXPECT_EQ(std::get<AuthError>(result), AuthError::MalformedAuthorization);
    }

    TEST(Middleware, MissingProtocolVersionIsRejected)
    {
        Fixture f;
        const std::string body = "body";
        const auto mac = f.sign("POST", "/stateless", body);
        const auto result = f.run("", "Wazuh 001:" + std::to_string(kNow) + ":" + mac, "POST", "/stateless", body);
        ASSERT_TRUE(std::holds_alternative<AuthError>(result));
        EXPECT_EQ(std::get<AuthError>(result), AuthError::MissingProtocolVersion);
    }

    TEST(Middleware, DifferentQueryStringOrderChangesMac)
    {
        Fixture f;
        const std::string body = "body";
        const auto mac = f.sign("GET", "/events?offset=10&limit=100", body);
        const auto result =
            f.run("1", "Wazuh 001:" + std::to_string(kNow) + ":" + mac, "GET", "/events?limit=100&offset=10", body);
        ASSERT_TRUE(std::holds_alternative<AuthError>(result));
        EXPECT_EQ(std::get<AuthError>(result), AuthError::InvalidMac);
    }

    TEST(Middleware, MethodIsUppercasedBeforeSigningComparison)
    {
        Fixture f;
        const std::string body = "body";
        const auto mac = f.sign("POST", "/stateless", body); // signer already uppercases
        const auto result = f.run("1", "Wazuh 001:" + std::to_string(kNow) + ":" + mac, "post", "/stateless", body);
        ASSERT_TRUE(std::holds_alternative<AuthenticatedRequest>(result));
    }

} // namespace
