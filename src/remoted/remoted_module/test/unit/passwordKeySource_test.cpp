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
#include <sys/resource.h>
#include <unistd.h>

#include <chrono>
#include <functional>
#include <memory>
#include <thread>

#include <gtest/gtest.h>

#include "auth/passwordKeySource.hpp"
#include "jwt/testVectors.hpp"

using namespace remoted::auth;

namespace
{
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

    // Frozen known-answer vector (jwt/testVectors.hpp, mirrored in jwt_vectors.json; computed with
    // Python's stdlib as an independent oracle) of the exact construction the shared
    // jwt/enrollKeyDerivation.hpp implements: HKDF-SHA256, salt 32 x 0x00,
    // info = "WAZUH-ENROLL-JWT-KEY" + 0x01, 32-byte output.
    TEST_F(PasswordKeySourceTest, HkdfMatchesTheVerifiedKnownAnswerVector)
    {
        writeFile("MyEnrollmentSecret123\n");
        PasswordKeySource source(m_path);

        const auto key = source.currentKey();
        ASSERT_TRUE(key.has_value());
        EXPECT_EQ(toLowerHex(key->data(), key->size()), jwt_profile::v1::test_vectors::enroll::kKeyHex);
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

    // Restores RLIMIT_NOFILE to whatever it was at construction, even if the test body throws --
    // a test that lowers the process-wide fd limit must never leak that to the rest of the suite.
    class RlimitNofileGuard
    {
    public:
        RlimitNofileGuard()
        {
            if (::getrlimit(RLIMIT_NOFILE, &m_original) != 0)
            {
                m_valid = false;
            }
        }

        ~RlimitNofileGuard()
        {
            restore();
        }

        bool lowerTo(rlim_t n)
        {
            if (!m_valid)
            {
                return false;
            }
            struct rlimit lowered = m_original;
            lowered.rlim_cur = n;
            return ::setrlimit(RLIMIT_NOFILE, &lowered) == 0;
        }

        // Idempotent -- callable explicitly to restore early, and safe to call again (or not at
        // all) from the destructor.
        void restore()
        {
            if (m_valid && !m_restored)
            {
                ::setrlimit(RLIMIT_NOFILE, &m_original);
                m_restored = true;
            }
        }

    private:
        struct rlimit m_original
        {
        };
        bool m_valid {true};
        bool m_restored {false};
    };

    TEST_F(PasswordKeySourceTest, DestructorDoesNotHangWhenEventfdCreationFails)
    {
        // Regression guard: eventfd() failing at construction (fd exhaustion) must not make the
        // watcher thread unjoinable forever -- the destructor's join() would then block the
        // process's shutdown indefinitely. Forces that exact failure by dropping the process's own
        // fd limit low enough that eventfd()/inotify_init1() both fail (stdin/stdout/stderr, at fds
        // 0-2, stay open regardless -- RLIMIT_NOFILE only blocks NEW fds beyond the limit), then
        // asserts destruction completes within a bounded time instead of hanging.
        writeFile("MyEnrollmentSecret123\n");

        RlimitNofileGuard guard;
        ASSERT_TRUE(guard.lowerTo(3));

        constexpr int kRefreshSeconds = 1;
        std::unique_ptr<PasswordKeySource> source;
        try
        {
            source = std::make_unique<PasswordKeySource>(m_path, kRefreshSeconds);
        }
        catch (...)
        {
            // Restore before letting a construction failure fail the test loudly below.
        }

        // Restore immediately: everything after this point should run with a normal fd budget.
        guard.restore();

        ASSERT_TRUE(static_cast<bool>(source)) << "construction itself must still succeed "
                                                  "(eventfd/inotify failures are handled, logged, "
                                                  "and fallen back on, not fatal)";

        const auto start = std::chrono::steady_clock::now();
        source.reset();
        const auto elapsed = std::chrono::steady_clock::now() - start;

        // Generous margin over kRefreshSeconds (the worst-case bound via the poll() timeout
        // fallback) to absorb scheduling jitter without being flaky, while still being far below
        // "hung forever".
        EXPECT_LT(elapsed, std::chrono::seconds(kRefreshSeconds * 5));
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

    TEST_F(PasswordKeySourceTest, ReappearingWithIdenticalContentAfterDisappearingIsReloaded)
    {
        // Regression guard: a file that goes missing (revoking Password-mode enrollment) and then
        // comes back with the EXACT same content it had before must still be re-derived, not left
        // stuck at nullopt forever. Before this was fixed, fileLooksChanged() compared the
        // reappeared file's hash against the stale m_lastHash from before the disappearance, saw
        // no difference, and never called reload() again -- even though reload()'s own
        // missing-file branch had already cleared m_derivedKey to nullopt in the meantime.
        writeFile("MyEnrollmentSecret123\n");
        PasswordKeySource source(m_path, /*refreshIntervalSeconds=*/1);
        const auto originalKey = source.currentKey();
        ASSERT_TRUE(originalKey.has_value());

        std::remove(m_path.c_str());
        ASSERT_TRUE(waitFor([&] { return !source.currentKey().has_value(); }));

        writeFile("MyEnrollmentSecret123\n"); // byte-identical to the pre-disappearance content

        ASSERT_TRUE(waitFor([&] { return source.currentKey().has_value(); }));
        EXPECT_EQ(*source.currentKey(), *originalKey);
    }

} // namespace
