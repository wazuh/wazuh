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
#include <set>
#include <string>
#include <type_traits>
#include <unistd.h>
#include <vector>

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
        // tests can sign a request without a production signer. `signedAgentId` is the id text the
        // agent puts in the header and therefore hashes -- not necessarily the canonical form.
        std::string sign(std::string_view method,
                         std::string_view target,
                         std::string_view body,
                         std::int64_t ts = kNow,
                         std::string_view signedAgentId = "001")
        {
            Cmac cmac(kKey);
            cmac.update("WAZUH-REQUEST\n");
            cmac.update("1\n");
            cmac.update(method);
            cmac.update("\n");
            cmac.update(target);
            cmac.update("\n");
            cmac.update(signedAgentId);
            cmac.update("\n");
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

    /**
     * The key lookup is numeric, so an agent that pads its id differently still authenticates. What
     * the request carries onwards must be the client.keys form regardless: that is the identity the
     * API's agent list is spelled with, and `POST /stats` uses it as the id of the agent's document,
     * so a second spelling would be a second, unmatchable agent. The MAC still covers the bytes the
     * agent actually sent -- that is the whole reason the session keeps the two apart.
     */
    TEST(Middleware, ANonCanonicalAgentIdIsCanonicalizedOnTheRequest)
    {
        Fixture f;
        const std::string body = "payload";

        for (const auto* signedId : {"1", "01", "001", "0001"})
        {
            const auto mac = f.sign("POST", "/stats", body, kNow, signedId);
            const auto result = f.run(
                "1", std::string {"Wazuh "} + signedId + ":" + std::to_string(kNow) + ":" + mac, "POST", "/stats", body);

            ASSERT_TRUE(std::holds_alternative<AuthenticatedRequest>(result)) << "signed id: " << signedId;
            EXPECT_EQ(std::get<AuthenticatedRequest>(result).agentId, "001") << "signed id: " << signedId;
        }
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

    // toString() is what puts a human-readable reason in wazuh-manager.log for every rejected request
    // (endpoint.cpp's errorResponseFor()). A new AuthError enumerator added without extending the
    // switch would silently log "unknown", so pin every value here.
    TEST(AuthErrorToString, CoversEveryEnumerator)
    {
        const AuthError all[] = {AuthError::None,
                                 AuthError::MissingProtocolVersion,
                                 AuthError::UnsupportedProtocolVersion,
                                 AuthError::MissingAuthorization,
                                 AuthError::MalformedAuthorization,
                                 AuthError::UnknownAgent,
                                 AuthError::MissingKey,
                                 AuthError::ExpiredRequest,
                                 AuthError::FutureRequest,
                                 AuthError::InvalidMac,
                                 AuthError::PayloadAgentMismatch,
                                 AuthError::BodyTooLarge};

        std::set<std::string> seen;
        for (const auto err : all)
        {
            const char* tag = toString(err);
            ASSERT_NE(tag, nullptr);
            EXPECT_STRNE(tag, "unknown") << "missing switch case for " << static_cast<int>(err);
            EXPECT_TRUE(seen.insert(tag).second) << "duplicate tag '" << tag << "'";
        }
        EXPECT_EQ(seen.size(), std::size(all));
    }

    // A key of the wrong length is one agent's problem; a provider failure is everyone's. The two must
    // be distinguishable by type so the middleware can stay quiet about the former and raise an ERROR
    // for the latter (see AuthMiddleware::beginSession).
    TEST(CmacExceptions, KeyErrorAndProviderErrorAreDistinctTypes)
    {
        EXPECT_THROW(Cmac(std::vector<std::uint8_t>(7, 0xAB)), CmacKeyError);

        // CmacKeyError must NOT be catchable as CmacProviderError (and vice versa), otherwise the
        // discrimination in beginSession() collapses back to the old behaviour.
        try
        {
            Cmac bad {std::vector<std::uint8_t>(7, 0xAB)};
            FAIL() << "expected CmacKeyError";
        }
        catch (const CmacProviderError&)
        {
            FAIL() << "a bad key length must not be reported as a provider failure";
        }
        catch (const CmacKeyError&)
        {
            SUCCEED();
        }

        // Both remain std::exception, so existing generic handlers keep working.
        EXPECT_TRUE((std::is_base_of_v<std::exception, CmacKeyError>));
        EXPECT_TRUE((std::is_base_of_v<std::exception, CmacProviderError>));
    }

} // namespace
