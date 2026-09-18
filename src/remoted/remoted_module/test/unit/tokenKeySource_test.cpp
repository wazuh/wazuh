/*
 * Wazuh auth middleware (framework-agnostic) - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * September 8, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Unit tests of TokenKeySource: the read-only replica of authd's enrollment token store that backs
// the enrollment-token path of /enroll (issue #38993). What is pinned here: the file authd writes
// (enrollment_token_store.c) is what this reader accepts, the HKDF key it caches matches the frozen
// vector, credential-less tokens are not replicated, a malformed file never drops the previous
// replica, the unknown-`kid` forced re-read is rate-limited, and the watcher notices authd's
// atomic replace, a file appearing after startup and a file removed.

#include <chrono>
#include <cstdio>
#include <fstream>
#include <functional>
#include <string>
#include <thread>
#include <unistd.h>

#include <gtest/gtest.h>

#include "auth/tokenKeySource.hpp"
#include "jwt/testVectors.hpp"

using namespace remoted::auth;
namespace tv = jwt_profile::v1::test_vectors::enroll_token;

namespace
{
    constexpr std::int64_t kFarFuture = 4102444800; // 2100-01-01
    // A second well-formed id (16 zero bytes) for the records a case needs the reader to drop.
    constexpr const char* kOtherId = "AAAAAAAAAAAAAAAAAAAAAA";
    // Another canonical 22-char id (16 zero bytes): well-formed, never minted.
    constexpr std::string_view kOtherKid = "AAAAAAAAAAAAAAAAAAAAAA";

    std::string toLowerHex(const std::uint8_t* data, std::size_t len)
    {
        static constexpr char kDigits[] = "0123456789abcdef";
        std::string out;
        out.reserve(len * 2);
        for (std::size_t i = 0; i < len; ++i)
        {
            out.push_back(kDigits[data[i] >> 4]);
            out.push_back(kDigits[data[i] & 0x0f]);
        }
        return out;
    }

    // One store record exactly as authd writes it (every field, in its order), for the vector token.
    std::string vectorRecord(std::int64_t expires = kFarFuture, bool revoked = false)
    {
        std::string out = R"({"id":")";
        out += tv::kIdB64Url;
        out += R"(","secret":")";
        out += tv::kSecretB64Url;
        out += R"(","adr":"siem.example.local","pin":")";
        out += tv::kPinB64Url;
        out += R"(","ca":null,"created":1700000000,"expires":)";
        out += std::to_string(expires);
        out += R"(,"max_uses":0,"uses":0,"revoked":)";
        out += revoked ? "true" : "false";
        out += R"(,"description":null})";
        return out;
    }

    // A credential-less token (public: pins the CA only), as authd writes it.
    std::string publicRecord(std::string_view id)
    {
        std::string out = R"({"id":")";
        out += id;
        out += R"(","secret":null,"adr":"siem.example.local","pin":")";
        out += tv::kPinB64Url;
        out +=
            R"(","ca":null,"created":1700000000,"expires":4102444800,"max_uses":0,"uses":0,"revoked":false,"description":"public"})";
        return out;
    }

    // A record with a well-formed id and a `expires` no reader accepts: what a lifetime near LONG_MAX
    // used to persist, before the mint bounded it (issue #39133).
    std::string poisonedRecord(std::string_view id)
    {
        std::string out = R"({"id":")";
        out += id;
        out += R"(","secret":")";
        out += tv::kSecretB64Url;
        out += R"(","adr":"siem.example.local","pin":")";
        out += tv::kPinB64Url;
        out +=
            R"(","ca":null,"created":1700000000,"expires":-9223372035074776832,"max_uses":0,"uses":0,"revoked":false,"description":null})";
        return out;
    }

    std::string store(const std::string& records)
    {
        return R"({"version":1,"tokens":[)" + records + "]}";
    }

    class TokenKeySourceTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            const auto* testInfo = ::testing::UnitTest::GetInstance()->current_test_info();
            m_path = "/tmp/" + std::string(testInfo->test_suite_name()) + "_" + testInfo->name() + "_" +
                     std::to_string(getpid()) + ".json";
        }

        void TearDown() override
        {
            std::remove(m_path.c_str());
            std::remove((m_path + ".tmp").c_str());
        }

        void writeFile(const std::string& contents)
        {
            std::ofstream file(m_path);
            file << contents;
        }

        // authd's own write discipline: temp file + rename.
        void replaceAtomically(const std::string& contents)
        {
            const std::string tmp = m_path + ".tmp";
            {
                std::ofstream file(tmp);
                file << contents;
            }
            ASSERT_EQ(rename(tmp.c_str(), m_path.c_str()), 0);
        }

        static bool waitFor(const std::function<bool()>& predicate,
                            std::chrono::milliseconds timeout = std::chrono::seconds(3))
        {
            const auto deadline = std::chrono::steady_clock::now() + timeout;
            while (std::chrono::steady_clock::now() < deadline)
            {
                if (predicate())
                {
                    return true;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            }
            return predicate();
        }

        std::string m_path;
    };

    TEST_F(TokenKeySourceTest, MissingFileIsEmptyNotAnError)
    {
        TokenKeySource source(m_path);
        EXPECT_FALSE(source.lookup(tv::kIdB64Url).has_value());

        const auto diag = source.diagnostics();
        EXPECT_EQ(diag.tokens, 0U);
        EXPECT_TRUE(diag.lastLoadOk); // no store yet is a valid state, not a failed load
        EXPECT_EQ(diag.reloads, 1U);
        EXPECT_EQ(diag.reloadFailures, 0U);
    }

    TEST_F(TokenKeySourceTest, LoadsTheStoreAndDerivesTheVectorKey)
    {
        writeFile(store(vectorRecord(1700003600, false)));
        TokenKeySource source(m_path);

        const auto entry = source.lookup(tv::kIdB64Url);
        ASSERT_TRUE(entry.has_value());
        // Frozen known-answer vector (testVectors.hpp / jwt_vectors.json): the key authd derives in C
        // from the same 16-byte secret, so the token an agent signs with the pasted token verifies here.
        EXPECT_EQ(toLowerHex(entry->key.data(), entry->key.size()), tv::kTokenKeyHex);
        EXPECT_EQ(entry->expires, 1700003600);
        EXPECT_FALSE(entry->revoked);

        EXPECT_FALSE(source.lookup(kOtherKid).has_value());
        EXPECT_EQ(source.diagnostics().tokens, 1U);
    }

    TEST_F(TokenKeySourceTest, RevokedFlagIsReplicated)
    {
        writeFile(store(vectorRecord(kFarFuture, true)));
        TokenKeySource source(m_path);

        const auto entry = source.lookup(tv::kIdB64Url);
        ASSERT_TRUE(entry.has_value());
        EXPECT_TRUE(entry->revoked);
    }

    TEST_F(TokenKeySourceTest, CredentialLessTokensAreNotReplicated)
    {
        // A public token carries nothing an agent could present: its id is simply unknown here.
        writeFile(store(publicRecord(kOtherKid) + "," + vectorRecord()));
        TokenKeySource source(m_path);

        EXPECT_FALSE(source.lookup(kOtherKid).has_value());
        EXPECT_TRUE(source.lookup(tv::kIdB64Url).has_value());
        EXPECT_EQ(source.diagnostics().tokens, 1U);
        EXPECT_TRUE(source.diagnostics().lastLoadOk);
    }

    TEST_F(TokenKeySourceTest, MalformedFileKeepsThePreviousReplica)
    {
        writeFile(store(vectorRecord()));
        TokenKeySource source(m_path);
        ASSERT_TRUE(source.lookup(tv::kIdB64Url).has_value());

        // A document that is not a store at all. There is no "rest of the file" to keep in any of
        // these, so the previous replica goes on serving.
        for (const auto* bad : {"not json", R"({"version":2,"tokens":[]})", R"({"version":1})"})
        {
            writeFile(bad);
            EXPECT_FALSE(source.reload()) << bad;
            EXPECT_TRUE(source.lookup(tv::kIdB64Url).has_value()) << bad;
            EXPECT_FALSE(source.diagnostics().lastLoadOk) << bad;
        }
        // Two records with one id: authd never writes that, so the file was edited by hand and
        // choosing between them would be guessing.
        writeFile(store(vectorRecord() + "," + vectorRecord()));
        EXPECT_FALSE(source.reload());

        // Lower bounds, not exact counts: the file existed at construction, so the inotify watcher
        // is armed and may reload each rewrite too (through the same mutex, to the same verdict).
        const auto diag = source.diagnostics();
        EXPECT_EQ(diag.tokens, 1U);
        EXPECT_GE(diag.reloadFailures, 4U);
        EXPECT_GE(diag.reloads, 1U);

        // A good file again: the replica follows it and the load is marked ok.
        writeFile(store(vectorRecord(1700003600, true)));
        EXPECT_TRUE(source.reload());
        EXPECT_TRUE(source.diagnostics().lastLoadOk);
        EXPECT_GE(source.diagnostics().reloads, 2U);
        EXPECT_TRUE(source.lookup(tv::kIdB64Url)->revoked);
    }

    TEST_F(TokenKeySourceTest, ARecordThatCannotBeReadIsDroppedAndTheRestIsReplicated)
    {
        // The failure this is about: a token minted with an unbounded lifetime persisted a negative
        // `expires`, and refusing the whole file over it froze this replica at whatever it held --
        // for good, on every worker the cluster synchronised the file to, so NO token enrolled
        // anybody any more. One unreadable record now costs exactly that record (issue #39133).
        writeFile(store(poisonedRecord(kOtherId) + "," + vectorRecord()));
        TokenKeySource source(m_path);

        EXPECT_TRUE(source.diagnostics().lastLoadOk);
        EXPECT_EQ(source.diagnostics().tokens, 1U);
        EXPECT_TRUE(source.lookup(tv::kIdB64Url).has_value());
        EXPECT_FALSE(source.lookup(kOtherId).has_value());

        // Every field an entry owns, one bad record each, with a good one beside it: the load
        // succeeds and only the bad record is missing.
        for (const auto* bad :
             {R"({"id":"bad","secret":null,"expires":1,"revoked":false})",
              R"({"id":"AAAAAAAAAAAAAAAAAAAAAA","secret":"short","expires":1,"revoked":false})",
              R"({"id":"AAAAAAAAAAAAAAAAAAAAAA","secret":"EBESExQVFhcYGRobHB0eHw","expires":-1,"revoked":false})",
              R"({"id":"AAAAAAAAAAAAAAAAAAAAAA","secret":"EBESExQVFhcYGRobHB0eHw","expires":1,"revoked":"no"})"})
        {
            writeFile(store(std::string(bad) + "," + vectorRecord()));
            EXPECT_TRUE(source.reload()) << bad;
            EXPECT_TRUE(source.diagnostics().lastLoadOk) << bad;
            EXPECT_EQ(source.diagnostics().tokens, 1U) << bad;
            EXPECT_TRUE(source.lookup(tv::kIdB64Url).has_value()) << bad;
        }

        // And a file whose every record is unreadable is an empty replica, not a refusal: it is what
        // the file says, and the previous tokens are no longer in it.
        writeFile(store(poisonedRecord(kOtherId)));
        EXPECT_TRUE(source.reload());
        EXPECT_TRUE(source.diagnostics().lastLoadOk);
        EXPECT_EQ(source.diagnostics().tokens, 0U);
        EXPECT_FALSE(source.lookup(tv::kIdB64Url).has_value());
    }

    TEST_F(TokenKeySourceTest, UnknownFieldsAreIgnored)
    {
        // A future authd may add fields; the reader only owns id/secret/expires/revoked.
        writeFile(R"({"version":1,"tokens":[{"id":"AAECAwQFBgcICQoLDA0ODw","secret":"EBESExQVFhcYGRobHB0eHw",)"
                  R"("expires":4102444800,"revoked":false,"future_field":{"x":1}}],"future_top":true})");
        TokenKeySource source(m_path);
        EXPECT_TRUE(source.lookup(tv::kIdB64Url).has_value());
        EXPECT_TRUE(source.diagnostics().lastLoadOk);
    }

    TEST_F(TokenKeySourceTest, ReloadIfMissingReReadsOnceAndIsRateLimited)
    {
        // No file at construction (so no inotify watch) and an hour-long poll: the ONLY way the
        // replica can change below is the forced re-read.
        TokenKeySource source(m_path, /*refreshIntervalSeconds=*/3600);
        ASSERT_FALSE(source.lookup(tv::kIdB64Url).has_value());

        writeFile(store(vectorRecord()));
        EXPECT_TRUE(source.reloadIfMissing(tv::kIdB64Url)); // performed
        EXPECT_TRUE(source.lookup(tv::kIdB64Url).has_value());

        // The token is dropped from the file; a second unknown kid right away must NOT re-read
        // (a peer probing random ids cannot turn the store into a per-request file read).
        writeFile(store(""));
        EXPECT_FALSE(source.reloadIfMissing(kOtherKid)); // suppressed by the rate limit
        EXPECT_TRUE(source.lookup(tv::kIdB64Url).has_value());

        std::this_thread::sleep_for(std::chrono::milliseconds(TokenKeySource::kMissingKidReloadMinIntervalMs + 50));
        EXPECT_TRUE(source.reloadIfMissing(kOtherKid)); // window elapsed: performed again
        EXPECT_FALSE(source.lookup(tv::kIdB64Url).has_value());
    }

    // ---------------------------------------------------------------------------
    // Hot-reload: background watcher (inotify + fallback poll)
    // ---------------------------------------------------------------------------

    TEST_F(TokenKeySourceTest, HotReloadPicksUpAnAtomicReplace)
    {
        writeFile(store(vectorRecord(kFarFuture, false)));
        TokenKeySource source(m_path, /*refreshIntervalSeconds=*/1);
        ASSERT_FALSE(source.lookup(tv::kIdB64Url)->revoked);

        // A revocation, written the way authd writes every change (temp file + rename).
        replaceAtomically(store(vectorRecord(kFarFuture, true)));

        EXPECT_TRUE(waitFor(
            [&]
            {
                const auto entry = source.lookup(tv::kIdB64Url);
                return entry.has_value() && entry->revoked;
            }));
        EXPECT_GE(source.diagnostics().reloads, 2U);
    }

    TEST_F(TokenKeySourceTest, FileAppearingAfterStartupIsPickedUp)
    {
        // A worker starts before the master's first mint reaches it: the replica must fill in
        // without a restart.
        TokenKeySource source(m_path, /*refreshIntervalSeconds=*/1);
        ASSERT_EQ(source.diagnostics().tokens, 0U);

        replaceAtomically(store(vectorRecord()));

        EXPECT_TRUE(waitFor([&] { return source.lookup(tv::kIdB64Url).has_value(); }));
    }

    TEST_F(TokenKeySourceTest, RemovedFileEmptiesTheReplica)
    {
        writeFile(store(vectorRecord()));
        TokenKeySource source(m_path, /*refreshIntervalSeconds=*/1);
        ASSERT_TRUE(source.lookup(tv::kIdB64Url).has_value());

        std::remove(m_path.c_str());

        EXPECT_TRUE(waitFor([&] { return !source.lookup(tv::kIdB64Url).has_value(); }));
        EXPECT_TRUE(source.diagnostics().lastLoadOk); // absent is a valid (empty) state
    }

} // namespace
