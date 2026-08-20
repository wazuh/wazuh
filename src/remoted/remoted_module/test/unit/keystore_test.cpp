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

        const auto key = keystore.keyFor(3824);
        ASSERT_TRUE(key.has_value());
        EXPECT_EQ(key->size(), 32u);
    }

    TEST_F(KeystoreTest, UnknownAgentIsNullopt)
    {
        writeFile("3824 debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path);

        EXPECT_FALSE(keystore.keyFor(9999).has_value());
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
        EXPECT_TRUE(keystore.keyFor(3824).has_value());
    }

    TEST_F(KeystoreTest, CommentAndBlankLinesAreSkipped)
    {
        writeFile("# a comment\n"
                  " # another, indented\n"
                  "3824 debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path);

        EXPECT_TRUE(keystore.keyFor(3824).has_value());
    }

    TEST_F(KeystoreTest, RemovedEntryIsSkipped)
    {
        writeFile("3824 !debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path);

        EXPECT_FALSE(keystore.keyFor(3824).has_value());
    }

    TEST_F(KeystoreTest, MalformedLineIsSkipped)
    {
        writeFile("3824 debian10 any\n"); // missing key column
        Keystore keystore(m_path);

        EXPECT_FALSE(keystore.keyFor(3824).has_value());
    }

    TEST_F(KeystoreTest, NonHexKeyResolvesToAnEmptyKey)
    {
        writeFile("3824 debian10 any not-hex-at-all\n");
        Keystore keystore(m_path);

        // The entry is still PRESENT (an empty key, not nullopt): that is what lets the auth
        // middleware answer the precise MissingKey rather than the vaguer UnknownAgent.
        const auto key = keystore.keyFor(3824);
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
        const auto key = keystore.keyFor(3824);
        ASSERT_TRUE(key.has_value());
        EXPECT_TRUE(key->empty());
    }

    TEST_F(KeystoreTest, ValidAndCorruptKeysAreCountedSeparately)
    {
        writeFile("1 agent-a any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n"
                  "2 agent-b any not-hex-at-all\n");
        Keystore keystore(m_path);

        EXPECT_EQ(keystore.reload(), 1); // only the usable one
        EXPECT_FALSE(keystore.keyFor(1)->empty());
        EXPECT_TRUE(keystore.keyFor(2)->empty());
    }

    TEST_F(KeystoreTest, MissingFileLeavesKeystoreEmpty)
    {
        Keystore keystore(m_path + "-does-not-exist");
        EXPECT_FALSE(keystore.keyFor(3824).has_value());
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
        EXPECT_TRUE(keystore.keyFor(7).has_value());
    }

    TEST_F(KeystoreTest, ReloadPicksUpChanges)
    {
        writeFile("3824 debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path);
        ASSERT_TRUE(keystore.keyFor(3824).has_value());

        writeFile("3824 !debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        EXPECT_EQ(keystore.reload(), 0);
        EXPECT_FALSE(keystore.keyFor(3824).has_value());
    }

    // ---------------------------------------------------------------------------
    // Hot-reload: background watcher (inotify + fallback poll)
    // ---------------------------------------------------------------------------

    TEST_F(KeystoreTest, HotReloadPicksUpRewriteAutomatically)
    {
        writeFile("3824 debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path, /*refreshIntervalSeconds=*/1);
        ASSERT_TRUE(keystore.keyFor(3824).has_value());

        // Rewrite in place -- no manual reload() call. The watcher must pick this up on its own.
        writeFile("9999 debian11 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");

        EXPECT_TRUE(waitFor([&] { return keystore.keyFor(9999).has_value(); }));
        EXPECT_FALSE(keystore.keyFor(3824).has_value());
    }

    TEST_F(KeystoreTest, HotReloadSurvivesAtomicReplace)
    {
        writeFile("3824 debian10 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n");
        Keystore keystore(m_path, /*refreshIntervalSeconds=*/1);
        ASSERT_TRUE(keystore.keyFor(3824).has_value());

        // Simulate authd/enrollment tooling replacing the file atomically (write to a temp file,
        // then rename() it over the watched path) -- this invalidates the original inotify watch,
        // exercising the re-arm path in drainInotifyEvents().
        const std::string tmpPath = m_path + ".tmp";
        {
            std::ofstream file(tmpPath);
            file << "9999 debian11 any ab3193e717865907fc0d347fe49f854699d497e441dd7f4d4c48052334363751\n";
        }
        ASSERT_EQ(rename(tmpPath.c_str(), m_path.c_str()), 0);

        EXPECT_TRUE(waitFor([&] { return keystore.keyFor(9999).has_value(); }));
        EXPECT_FALSE(keystore.keyFor(3824).has_value());
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
            const bool has111 = keystore.keyFor(111).has_value();
            const bool has222 = keystore.keyFor(222).has_value();
            EXPECT_FALSE(has111 && has222) << "keystore adopted a torn read mixing both contents";
        }

        stop.store(true);
        writer.join();
    }

} // namespace
