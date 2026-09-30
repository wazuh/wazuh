/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "auth_failures_linux.hpp"

#include <utmpx.h>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <vector>

class AuthFailuresProviderTests : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            m_tempDir = std::filesystem::temp_directory_path() / "auth_failures_provider_test";
            std::filesystem::remove_all(m_tempDir);
            std::filesystem::create_directories(m_tempDir / "pam.d");
            std::filesystem::create_directories(m_tempDir / "faillock");
            m_conf = (m_tempDir / "faillock.conf").string();
            m_pamDir = (m_tempDir / "pam.d").string();
            m_btmp = (m_tempDir / "btmp").string();
        }

        void TearDown() override
        {
            std::filesystem::remove_all(m_tempDir);
        }

        /// @brief Wires pam_faillock in a PAM stack and points the configuration at the tally directory.
        void enableFaillock(const std::string& pamLine = "auth required pam_faillock.so preauth") const
        {
            std::ofstream(m_pamDir + "/system-auth") << "auth sufficient pam_unix.so\n" << pamLine << "\n";
            std::ofstream(m_conf) << "# dir = /nonexistent\ndir = " << (m_tempDir / "faillock").string() << "\n";
        }

        /// @brief Writes a tally file, one 64-byte record per {status, time}.
        void writeTally(const std::string& user, const std::vector<std::pair<uint16_t, uint64_t>>& records) const
        {
            std::ofstream file(m_tempDir / "faillock" / user, std::ios::binary);

            for (const auto& record : records)
            {
                char raw[64] = {};
                std::strcpy(raw, "127.0.0.1");
                std::memcpy(raw + 54, &record.first, sizeof(record.first));
                std::memcpy(raw + 56, &record.second, sizeof(record.second));
                file.write(raw, sizeof(raw));
            }
        }

        /// @brief Writes btmp with one record per {user, time}, then appends a truncated record.
        void writeBtmp(const std::vector<std::pair<std::string, int32_t>>& records, bool partialTail = false) const
        {
            std::ofstream file(m_btmp, std::ios::binary);

            for (const auto& record : records)
            {
                struct utmpx entry {};
                entry.ut_type = LOGIN_PROCESS;
                std::strncpy(entry.ut_user, record.first.c_str(), sizeof(entry.ut_user) - 1);
                entry.ut_tv.tv_sec = record.second;
                file.write(reinterpret_cast<const char*>(&entry), sizeof(entry));
            }

            if (partialTail)
            {
                const std::string junk(sizeof(struct utmpx) / 2, 'x');
                file.write(junk.data(), static_cast<std::streamsize>(junk.size()));
            }
        }

        AuthFailuresProvider makeProvider(size_t tailBytes = 1024 * 1024) const
        {
            return AuthFailuresProvider(m_conf, m_pamDir, m_btmp, tailBytes);
        }

        std::filesystem::path m_tempDir;
        std::string m_conf;
        std::string m_pamDir;
        std::string m_btmp;
};

TEST_F(AuthFailuresProviderTests, FaillockCountsValidRecords)
{
    enableFaillock();
    // Three valid records in any order and one already expired.
    writeTally("alice", {{1, 100}, {1, 300}, {0, 999}, {1, 200}});

    auto provider = makeProvider();
    provider.load({{"alice", 0}});

    const auto failures = provider.get("alice");
    EXPECT_TRUE(failures.known);
    EXPECT_EQ(failures.count, 3u);
    EXPECT_EQ(failures.latest, 300u);
}

TEST_F(AuthFailuresProviderTests, FaillockWithoutTallyFileMeansNoFailures)
{
    enableFaillock();

    auto provider = makeProvider();
    provider.load({{"alice", 0}});

    const auto failures = provider.get("alice");
    EXPECT_TRUE(failures.known);
    EXPECT_EQ(failures.count, 0u);
    EXPECT_EQ(failures.latest, 0u);
}

TEST_F(AuthFailuresProviderTests, FaillockWinsOverBtmp)
{
    enableFaillock();
    writeTally("alice", {{1, 100}});
    writeBtmp({{"alice", 500}, {"alice", 600}});

    auto provider = makeProvider();
    provider.load({{"alice", 0}});

    EXPECT_EQ(provider.get("alice").count, 1u);
}

TEST_F(AuthFailuresProviderTests, CommentedFaillockIsNotActive)
{
    enableFaillock("# auth required pam_faillock.so preauth");
    writeTally("alice", {{1, 100}, {1, 200}, {1, 300}});
    writeBtmp({{"alice", 500}});

    auto provider = makeProvider();
    provider.load({{"alice", 0}});

    // btmp answers, not the tally.
    const auto failures = provider.get("alice");
    EXPECT_TRUE(failures.known);
    EXPECT_EQ(failures.count, 1u);
    EXPECT_EQ(failures.latest, 500u);
}

TEST_F(AuthFailuresProviderTests, FaillockWithoutTallyDirectoryFallsBackToBtmp)
{
    enableFaillock();
    std::filesystem::remove_all(m_tempDir / "faillock");
    writeBtmp({{"alice", 500}});

    auto provider = makeProvider();
    provider.load({{"alice", 0}});

    EXPECT_EQ(provider.get("alice").count, 1u);
}

TEST_F(AuthFailuresProviderTests, BtmpCountsFailuresSinceTheLastLogin)
{
    writeBtmp({{"alice", 500}, {"alice", 1500}, {"alice", 2000}, {"mallory", 1600}, {"bob", 100}}, true);

    auto provider = makeProvider();
    provider.load({{"alice", 1000}, {"bob", 0}, {"dave", 0}});

    const auto alice = provider.get("alice");
    EXPECT_TRUE(alice.known);
    EXPECT_EQ(alice.count, 2u);
    EXPECT_EQ(alice.latest, 2000u);

    // Never logged in, so every failure counts.
    EXPECT_EQ(provider.get("bob").count, 1u);

    // A source exists and recorded nothing.
    const auto dave = provider.get("dave");
    EXPECT_TRUE(dave.known);
    EXPECT_EQ(dave.count, 0u);
    EXPECT_EQ(dave.latest, 0u);

    // Attempts on a name that is not a collected account are not attributed.
    EXPECT_EQ(provider.get("mallory").count, 0u);
}

TEST_F(AuthFailuresProviderTests, BtmpIsReadFromTheTailOnly)
{
    writeBtmp({{"alice", 100}, {"alice", 200}, {"alice", 300}, {"alice", 400}, {"alice", 500}});

    // Room for the last two records only.
    auto provider = makeProvider(2 * sizeof(struct utmpx));
    provider.load({{"alice", 0}});

    const auto failures = provider.get("alice");
    EXPECT_EQ(failures.count, 2u);
    EXPECT_EQ(failures.latest, 500u);
}

TEST_F(AuthFailuresProviderTests, EmptyBtmpMeansNoFailures)
{
    writeBtmp({});

    auto provider = makeProvider();
    provider.load({{"alice", 0}});

    const auto failures = provider.get("alice");
    EXPECT_TRUE(failures.known);
    EXPECT_EQ(failures.count, 0u);
}

TEST_F(AuthFailuresProviderTests, NoSourceIsUnknown)
{
    auto provider = makeProvider();
    provider.load({{"alice", 0}});

    EXPECT_FALSE(provider.get("alice").known);
}

TEST_F(AuthFailuresProviderTests, BtmpThatIsNotAFileIsUnknown)
{
    std::filesystem::create_directories(m_btmp);

    auto provider = makeProvider();
    provider.load({{"alice", 0}});

    EXPECT_FALSE(provider.get("alice").known);
}
