/*
 * Wazuh auth middleware (framework-agnostic) - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <cstdio>
#include <fstream>
#include <unistd.h>

#include <chrono>
#include <functional>
#include <thread>

#include <gtest/gtest.h>

#include "auth/cmac.hpp" // toLowerHex(), for the known-answer-vector assertion
#include "auth/passwordKeySource.hpp"

using namespace remoted::auth;

namespace
{

    class PasswordKeySourceTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            const auto* testInfo = ::testing::UnitTest::GetInstance()->current_test_info();
            m_path = "/tmp/" + std::string(testInfo->test_suite_name()) + "_" + testInfo->name() + "_" +
                     std::to_string(getpid()) + ".pass";
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

    TEST_F(PasswordKeySourceTest, MissingFileHasNoKey)
    {
        PasswordKeySource source(m_path);
        EXPECT_FALSE(source.currentKey().has_value());
    }

    TEST_F(PasswordKeySourceTest, ValidPasswordProducesA32ByteKey)
    {
        writeFile("MyEnrollmentSecret123\n");
        PasswordKeySource source(m_path);

        const auto key = source.currentKey();
        ASSERT_TRUE(key.has_value());
        EXPECT_EQ(key->size(), 32u);
    }

    TEST_F(PasswordKeySourceTest, KeyIsStableAcrossRepeatedReads)
    {
        writeFile("MyEnrollmentSecret123\n");
        PasswordKeySource source(m_path);

        const auto first = source.currentKey();
        const auto second = source.currentKey();
        ASSERT_TRUE(first.has_value());
        ASSERT_TRUE(second.has_value());
        EXPECT_EQ(*first, *second);
    }

    // Verified known-answer vector (see the Agent enrollment chapter of remoted_module/README.md):
    // computed independently via `openssl kdf ... HKDF` against the exact construction this class
    // implements (HKDF-SHA256, empty salt, info = "WAZUH-ENROLL-CMAC-KEY" + 0x01, 32-byte output).
    TEST_F(PasswordKeySourceTest, HkdfMatchesTheVerifiedKnownAnswerVector)
    {
        writeFile("MyEnrollmentSecret123\n");
        PasswordKeySource source(m_path);

        const auto key = source.currentKey();
        ASSERT_TRUE(key.has_value());
        EXPECT_EQ(toLowerHex(key->data(), key->size()),
                  "2ea29504f294bce5039bdb4fb78747dec59866204dc2588dc59f3b8cd5875a9e");
    }

    TEST_F(PasswordKeySourceTest, DifferentPasswordsProduceDifferentKeys)
    {
        writeFile("MyEnrollmentSecret123\n");
        PasswordKeySource source(m_path);
        const auto key1 = source.currentKey();
        ASSERT_TRUE(key1.has_value());

        writeFile("SomeOtherSecret456\n");
        ASSERT_TRUE(source.reload());
        const auto key2 = source.currentKey();
        ASSERT_TRUE(key2.has_value());

        EXPECT_NE(*key1, *key2);
    }

    TEST_F(PasswordKeySourceTest, TrailingCrlfIsStrippedBeforeDerivation)
    {
        writeFile("MyEnrollmentSecret123\r\n");
        PasswordKeySource withCrlf(m_path);

        const std::string otherPath = m_path + ".nocrlf";
        {
            std::ofstream file(otherPath);
            file << "MyEnrollmentSecret123";
        }
        PasswordKeySource withoutCrlf(otherPath);

        const auto key1 = withCrlf.currentKey();
        const auto key2 = withoutCrlf.currentKey();
        ASSERT_TRUE(key1.has_value());
        ASSERT_TRUE(key2.has_value());
        EXPECT_EQ(*key1, *key2);

        std::remove(otherPath.c_str());
    }

    TEST_F(PasswordKeySourceTest, LengthTwoOrLessIsRejected)
    {
        writeFile("ab\n");
        PasswordKeySource source(m_path);
        EXPECT_FALSE(source.currentKey().has_value());
    }

    TEST_F(PasswordKeySourceTest, LengthThreeIsAccepted)
    {
        writeFile("abc\n");
        PasswordKeySource source(m_path);
        EXPECT_TRUE(source.currentKey().has_value());
    }

    TEST_F(PasswordKeySourceTest, AllWhitespaceIsRejected)
    {
        writeFile("      \n");
        PasswordKeySource source(m_path);
        EXPECT_FALSE(source.currentKey().has_value());
    }

    TEST_F(PasswordKeySourceTest, EmptyFileIsRejected)
    {
        writeFile("");
        PasswordKeySource source(m_path);
        EXPECT_FALSE(source.currentKey().has_value());
    }

    TEST_F(PasswordKeySourceTest, LineExceedingBufferIsRejected)
    {
        // 4096 non-newline characters: fgets fills the whole buffer without ever seeing '\n',
        // matching authd's own read_password_line() "too long" rejection.
        writeFile(std::string(4096, 'a'));
        PasswordKeySource source(m_path);
        EXPECT_FALSE(source.currentKey().has_value());
    }

    TEST_F(PasswordKeySourceTest, OnlyFirstLineIsUsed)
    {
        writeFile("MyEnrollmentSecret123\nSomeOtherSecret456\n");
        PasswordKeySource firstLineOnly(m_path);

        const std::string otherPath = m_path + ".single";
        {
            std::ofstream file(otherPath);
            file << "MyEnrollmentSecret123\n";
        }
        PasswordKeySource singleLine(otherPath);

        const auto key1 = firstLineOnly.currentKey();
        const auto key2 = singleLine.currentKey();
        ASSERT_TRUE(key1.has_value());
        ASSERT_TRUE(key2.has_value());
        EXPECT_EQ(*key1, *key2);

        std::remove(otherPath.c_str());
    }

    TEST_F(PasswordKeySourceTest, ManualReloadPicksUpChanges)
    {
        writeFile("MyEnrollmentSecret123\n");
        PasswordKeySource source(m_path);
        ASSERT_TRUE(source.currentKey().has_value());

        writeFile("  \n"); // now invalid (all-whitespace)
        EXPECT_FALSE(source.reload());
        EXPECT_FALSE(source.currentKey().has_value());
    }

    // ---------------------------------------------------------------------------
    // Hot-reload: background watcher (inotify + fallback poll)
    // ---------------------------------------------------------------------------

    TEST_F(PasswordKeySourceTest, HotReloadPicksUpRewriteAutomatically)
    {
        writeFile("MyEnrollmentSecret123\n");
        PasswordKeySource source(m_path, /*refreshIntervalSeconds=*/1);
        const auto originalKey = source.currentKey();
        ASSERT_TRUE(originalKey.has_value());

        writeFile("SomeOtherSecret456\n");

        EXPECT_TRUE(waitFor(
            [&]
            {
                const auto key = source.currentKey();
                return key.has_value() && *key != *originalKey;
            }));
    }

    TEST_F(PasswordKeySourceTest, HotReloadSurvivesAtomicReplace)
    {
        writeFile("MyEnrollmentSecret123\n");
        PasswordKeySource source(m_path, /*refreshIntervalSeconds=*/1);
        const auto originalKey = source.currentKey();
        ASSERT_TRUE(originalKey.has_value());

        const std::string tmpPath = m_path + ".tmp";
        {
            std::ofstream file(tmpPath);
            file << "SomeOtherSecret456\n";
        }
        ASSERT_EQ(rename(tmpPath.c_str(), m_path.c_str()), 0);

        EXPECT_TRUE(waitFor(
            [&]
            {
                const auto key = source.currentKey();
                return key.has_value() && *key != *originalKey;
            }));
    }

    TEST_F(PasswordKeySourceTest, HotReloadPicksUpFileAppearingAfterStartup)
    {
        // File absent at construction (Password mode active but authd.pass not yet synced from
        // the master to a worker) -- currentKey() must start at nullopt and recover once the
        // file appears, without restarting remoted.
        PasswordKeySource source(m_path, /*refreshIntervalSeconds=*/1);
        ASSERT_FALSE(source.currentKey().has_value());

        writeFile("MyEnrollmentSecret123\n");

        EXPECT_TRUE(waitFor([&] { return source.currentKey().has_value(); }));
    }

} // namespace
