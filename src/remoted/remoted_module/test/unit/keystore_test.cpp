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

#include <cstdio>
#include <fstream>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <thread>

#include <gtest/gtest.h>

#include "auth/keystore.hpp"

using namespace remoted::auth;

namespace
{

    class KeystoreTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            const auto* testInfo = ::testing::UnitTest::GetInstance()->current_test_info();
            m_path = "/tmp/" + std::string(testInfo->test_suite_name()) + "_" + testInfo->name() + "_" +
                     std::to_string(getpid()) + ".keys";
        }

        void TearDown() override
        {
            std::remove(m_path.c_str());
        }

        // The interface resolves key and address together; these keep the assertions below focused on
        // one property at a time.
        static std::optional<std::vector<std::uint8_t>> keyOf(const Keystore& keystore, AgentId id)
        {
            const auto found = keystore.lookup(id, "127.0.0.1");
            return found ? std::optional {found->key} : std::nullopt;
        }

        static bool allowed(const Keystore& keystore, AgentId id, std::string_view peerIp)
        {
            const auto found = keystore.lookup(id, peerIp);
            return found && found->addressAllowed;
        }

        void writeFile(const std::string& contents)
        {
            std::ofstream file(m_path);
            file << contents;
        }

        // Polls `predicate` until it's true or `timeout` elapses. The hot-reload tests below are
        // driven by a real background thread (inotify + a short fallback poll), so they can't
        // assert synchronously the way the manual-reload() tests above do.
        static bool waitFor(const std::function<bool()>& predicate,
                            std::chrono::milliseconds timeout = std::chrono::seconds(2))
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

    TEST_F(KeystoreTest, LoadsAValidEntry)
    {
        writeFile("3824 debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path);

        const auto key = keyOf(keystore, 3824);
        ASSERT_TRUE(key.has_value());
        EXPECT_EQ(key->size(), 32u);
    }

    // The health counters behind the remoted.auth.keystore.* pulls: the LEVEL follows each
    // successful load, the totals accumulate successes and failures separately, and a failed
    // reload keeps the previous level (the table is untouched). GE where the background watcher
    // could legitimately add reloads of its own.
    TEST_F(KeystoreTest, HealthCountersTrackLoadsAndFailures)
    {
        writeFile("3824 debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path);

        EXPECT_EQ(keystore.agentsLoaded(), 1U); // the startup load
        EXPECT_GE(keystore.reloadsTotal(), 1U);
        EXPECT_EQ(keystore.reloadFailuresTotal(), 0U);

        writeFile("3824 debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n"
                  "3825 debian11 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        EXPECT_EQ(keystore.reload(), 2);
        EXPECT_EQ(keystore.agentsLoaded(), 2U);
        EXPECT_GE(keystore.reloadsTotal(), 2U);

        std::remove(m_path.c_str());
        EXPECT_EQ(keystore.reload(), Keystore::kReloadUnreadable);
        EXPECT_GE(keystore.reloadFailuresTotal(), 1U);
        EXPECT_EQ(keystore.agentsLoaded(), 2U); // previous table (and its level) kept
    }

    // entries_skipped is the companion level to `agents`: it counts the client.keys lines the
    // adopted load could NOT use, which is what tells an operator "that agent is silently
    // unauthenticable, go fix line N". Comments, blanks and deliberately removed entries are
    // normal states and must never inflate it.
    TEST_F(KeystoreTest, SkippedEntriesLevelCountsOnlyUnusableLines)
    {
        const std::string goodKey {"ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751"};
        // One well-formed line per call, so each fixture line below stays short enough to read
        // (and to survive clang-format) while only the field under test varies.
        const auto entry = [&goodKey](const std::string& id, const std::string& name, const std::string& ip)
        {
            return id + " " + name + " " + ip + " " + goodKey + "\n";
        };

        writeFile("# a comment\n"
                  "\n" +
                  entry("3824", "debian10", "any") +            // usable
                  entry("3825", "debian11", "192.168.0.0/33") + // ip column does not parse
                  "3826 debian12 any nothexatall\n" +           // key does not decode
                  entry("notanid", "debian13", "any") +         // id column is not numeric
                  "3827 onlythreefields\n" +                    // fewer than 4 fields
                  entry("3828", "!removed", "any"));            // deliberately removed entry
        Keystore keystore(m_path);

        EXPECT_EQ(keystore.agentsLoaded(), 1U);   // only the usable entry
        EXPECT_EQ(keystore.entriesSkipped(), 4U); // the four unusable lines, and nothing else

        // A file with nothing wrong clears the level: it describes the file as it stands now,
        // not a running total across loads.
        writeFile(entry("3824", "debian10", "any"));
        EXPECT_EQ(keystore.reload(), 1);
        EXPECT_EQ(keystore.agentsLoaded(), 1U);
        EXPECT_EQ(keystore.entriesSkipped(), 0U);

        // An unreadable file is a failed load: the previous level survives untouched, exactly
        // like agentsLoaded().
        writeFile(entry("3824", "debian10", "any") + entry("3825", "debian11", "999.1.1.1"));
        EXPECT_EQ(keystore.reload(), 1);
        EXPECT_EQ(keystore.entriesSkipped(), 1U);
        std::remove(m_path.c_str());
        EXPECT_EQ(keystore.reload(), Keystore::kReloadUnreadable);
        EXPECT_EQ(keystore.entriesSkipped(), 1U);
    }

    TEST_F(KeystoreTest, UnknownAgentIsNullopt)
    {
        writeFile("3824 debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path);

        EXPECT_FALSE(keyOf(keystore, 9999).has_value());
    }

    TEST_F(KeystoreTest, NonNumericIdLineIsSkipped)
    {
        writeFile("abc debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path);

        EXPECT_EQ(keystore.reload(), 0);
    }

    TEST_F(KeystoreTest, NonNumericIdLineDoesNotBlockOtherEntries)
    {
        writeFile("abc debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n"
                  "3824 debian11 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path);

        EXPECT_EQ(keystore.reload(), 1);
        EXPECT_TRUE(keyOf(keystore, 3824).has_value());
    }

    TEST_F(KeystoreTest, CommentAndBlankLinesAreSkipped)
    {
        writeFile("# a comment\n"
                  " # another, indented\n"
                  "3824 debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path);

        EXPECT_TRUE(keyOf(keystore, 3824).has_value());
    }

    TEST_F(KeystoreTest, RemovedEntryIsSkipped)
    {
        writeFile("3824 !debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path);

        EXPECT_FALSE(keyOf(keystore, 3824).has_value());
    }

    TEST_F(KeystoreTest, MalformedLineIsSkipped)
    {
        writeFile("3824 debian10 any\n"); // missing key column
        Keystore keystore(m_path);

        EXPECT_FALSE(keyOf(keystore, 3824).has_value());
    }

    // The bearer profile's HS256 key is exactly the 32 bytes of a 64-hex secret. A shorter key is
    // PRESENT but unusable (-> MissingKey, "re-enroll"), and is not counted as loaded.
    TEST_F(KeystoreTest, ShortKeysResolveToAnEmptyKey)
    {
        writeFile("1 agent-16 any 2b7e151628aed2a6abf7158809cf4f3c\n"
                  "2 agent-24 any 2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6\n"
                  "3 agent-32 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n"
                  "4 agent-UP any AB3193E717865907FC0D347FE49F854699D497E441DD7F4D4C48052334363751\n");
        Keystore keystore(m_path);

        EXPECT_EQ(keystore.reload(), 1); // only the 32-byte lowercase one
        for (const AgentId id : {1u, 2u, 4u})
        {
            const auto key = keyOf(keystore, id);
            ASSERT_TRUE(key.has_value()) << id;
            EXPECT_TRUE(key->empty()) << id;
        }
        const auto usable = keyOf(keystore, 3);
        ASSERT_TRUE(usable.has_value());
        EXPECT_EQ(usable->size(), 32u);
    }

    TEST_F(KeystoreTest, NonHexKeyResolvesToAnEmptyKey)
    {
        writeFile("3824 debian10 any not-hex-at-all\n");
        Keystore keystore(m_path);

        // The entry is still PRESENT (an empty key, not nullopt): that is what lets the auth
        // middleware answer the precise MissingKey rather than the vaguer UnknownAgent.
        const auto key = keyOf(keystore, 3824);
        ASSERT_TRUE(key.has_value());
        EXPECT_TRUE(key->empty());
    }

    // ...but it must not be COUNTED as loaded. Previously a file containing nothing but corrupted
    // keys reported "1 key loaded" while rejecting every request from that agent, which read as a
    // healthy keystore. The count is now what an operator can trust: keys that can authenticate.
    TEST_F(KeystoreTest, CorruptKeyIsNotCountedAsLoaded)
    {
        writeFile("3824 debian10 any not-hex-at-all\n");
        Keystore keystore(m_path);

        EXPECT_EQ(keystore.reload(), 0);
        const auto key = keyOf(keystore, 3824);
        ASSERT_TRUE(key.has_value());
        EXPECT_TRUE(key->empty());
    }

    TEST_F(KeystoreTest, ValidAndCorruptKeysAreCountedSeparately)
    {
        writeFile("1 agent-a any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n"
                  "2 agent-b any not-hex-at-all\n");
        Keystore keystore(m_path);

        EXPECT_EQ(keystore.reload(), 1); // only the usable one
        EXPECT_FALSE(keyOf(keystore, 1)->empty());
        EXPECT_TRUE(keyOf(keystore, 2)->empty());
    }

    TEST_F(KeystoreTest, AnyRegistrationAllowsEveryAddress)
    {
        writeFile("3824 debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path);

        EXPECT_TRUE(allowed(keystore, 3824, "10.0.0.7"));
        EXPECT_TRUE(allowed(keystore, 3824, "203.0.113.9"));
        EXPECT_TRUE(allowed(keystore, 3824, "2001:db8::1"));
    }

    TEST_F(KeystoreTest, FixedRegistrationAllowsOnlyThatAddress)
    {
        writeFile("3824 debian10 10.0.0.5 ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path);

        EXPECT_TRUE(allowed(keystore, 3824, "10.0.0.5"));
        EXPECT_FALSE(allowed(keystore, 3824, "10.0.0.6"));
    }

    TEST_F(KeystoreTest, RangeRegistrationAllowsTheWholeRange)
    {
        writeFile("3824 debian10 10.0.0.0/24 ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path);

        EXPECT_TRUE(allowed(keystore, 3824, "10.0.0.7"));
        EXPECT_FALSE(allowed(keystore, 3824, "10.0.1.7"));
    }

    TEST_F(KeystoreTest, UnknownAgentIsNotAllowedFromAnywhere)
    {
        writeFile("3824 debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path);

        EXPECT_FALSE(allowed(keystore, 9999, "10.0.0.7"));
    }

    TEST_F(KeystoreTest, UnparseableAddressSkipsTheLine)
    {
        // The entry is dropped rather than loaded without a restriction, so the agent is unknown and
        // no address is allowed for it.
        writeFile("3824 debian10 10.0.0.256 ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path);

        EXPECT_EQ(keystore.reload(), 0);
        EXPECT_FALSE(keyOf(keystore, 3824).has_value());
        EXPECT_FALSE(allowed(keystore, 3824, "10.0.0.256"));
    }

    TEST_F(KeystoreTest, UnparseableAddressDoesNotBlockOtherEntries)
    {
        // One mistyped address costs that agent only. The C keystore calls merror_exit() here, which
        // would take the whole daemon down over this same file.
        writeFile("1 agent-a bogus-address ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n"
                  "2 agent-b any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path);

        EXPECT_EQ(keystore.reload(), 1);
        EXPECT_FALSE(keyOf(keystore, 1).has_value());
        EXPECT_TRUE(keyOf(keystore, 2).has_value());
    }

    TEST_F(KeystoreTest, AddressRestrictionFollowsAReload)
    {
        writeFile("3824 debian10 10.0.0.5 ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path);
        ASSERT_TRUE(allowed(keystore, 3824, "10.0.0.5"));

        writeFile("3824 debian10 10.0.0.9 ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        ASSERT_EQ(keystore.reload(), 1);

        EXPECT_FALSE(allowed(keystore, 3824, "10.0.0.5"));
        EXPECT_TRUE(allowed(keystore, 3824, "10.0.0.9"));
    }

    TEST_F(KeystoreTest, MissingFileLeavesKeystoreEmpty)
    {
        Keystore keystore(m_path + "-does-not-exist");
        EXPECT_FALSE(keyOf(keystore, 3824).has_value());
    }

    // An unreadable file must be distinguishable from an empty one by the return value, so the
    // caller can tell the operator "every request will be rejected" instead of staying silent.
    TEST_F(KeystoreTest, MissingFileReloadReportsUnreadable)
    {
        Keystore keystore(m_path + "-does-not-exist");
        EXPECT_EQ(keystore.reload(), Keystore::kReloadUnreadable);
    }

    // A line whose id column is not numeric is skipped, and skipping it must not be mistaken for a
    // load failure: the rest of the file is still usable.
    TEST_F(KeystoreTest, NonNumericAgentIdIsSkippedWithoutFailingTheReload)
    {
        writeFile("not-a-number agent-x any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n"
                  "7 agent-y any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path);

        EXPECT_EQ(keystore.reload(), 1);
        EXPECT_TRUE(keyOf(keystore, 7).has_value());
    }

    TEST_F(KeystoreTest, ReloadPicksUpChanges)
    {
        writeFile("3824 debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path);
        ASSERT_TRUE(keyOf(keystore, 3824).has_value());

        writeFile("3824 !debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        EXPECT_EQ(keystore.reload(), 0);
        EXPECT_FALSE(keyOf(keystore, 3824).has_value());
    }

    // ---------------------------------------------------------------------------
    // Hot-reload: background watcher (inotify + fallback poll)
    // ---------------------------------------------------------------------------

    TEST_F(KeystoreTest, HotReloadPicksUpRewriteAutomatically)
    {
        writeFile("3824 debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path, /*refreshIntervalSeconds=*/1);
        ASSERT_TRUE(keyOf(keystore, 3824).has_value());

        // Rewrite in place -- no manual reload() call. The watcher must pick this up on its own.
        writeFile("9999 debian11 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");

        EXPECT_TRUE(waitFor([&] { return keyOf(keystore, 9999).has_value(); }));
        EXPECT_FALSE(keyOf(keystore, 3824).has_value());
    }

    TEST_F(KeystoreTest, HotReloadSurvivesAtomicReplace)
    {
        writeFile("3824 debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path, /*refreshIntervalSeconds=*/1);
        ASSERT_TRUE(keyOf(keystore, 3824).has_value());

        // Simulate authd/enrollment tooling replacing the file atomically (write to a temp file,
        // then rename() it over the watched path) -- this invalidates the original inotify watch,
        // exercising the re-arm path in drainInotifyEvents().
        const std::string tmpPath = m_path + ".tmp";
        {
            std::ofstream file(tmpPath);
            file << "9999 debian11 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n";
        }
        ASSERT_EQ(rename(tmpPath.c_str(), m_path.c_str()), 0);

        EXPECT_TRUE(waitFor([&] { return keyOf(keystore, 9999).has_value(); }));
        EXPECT_FALSE(keyOf(keystore, 3824).has_value());
    }

    // Races a background writer (repeatedly rewriting the file between two fully-valid but
    // mutually-exclusive contents) against repeated reload() calls, and asserts the in-memory
    // table is never a mix of both -- i.e. reload() never adopts a torn/mid-write snapshot. Each
    // content is internally consistent (agent 111 XOR agent 222); seeing both at once could only
    // happen if a parse read part of one content and part of the other.
    TEST_F(KeystoreTest, ReloadNeverAdoptsATornMixOfTwoValidContents)
    {
        const std::string contentA = "111 hostA any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n";
        const std::string contentB = "222 hostB any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n";
        writeFile(contentA);
        Keystore keystore(m_path);

        std::atomic_bool stop {false};
        std::thread writer(
            [&]
            {
                bool useA = false;
                while (!stop.load())
                {
                    writeFile(useA ? contentA : contentB);
                    useA = !useA;
                }
            });

        const auto raceDeadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(300);
        while (std::chrono::steady_clock::now() < raceDeadline)
        {
            keystore.reload();
            const bool has111 = keyOf(keystore, 111).has_value();
            const bool has222 = keyOf(keystore, 222).has_value();
            EXPECT_FALSE(has111 && has222) << "keystore adopted a torn read mixing both contents";
        }

        stop.store(true);
        writer.join();
    }

} // namespace
