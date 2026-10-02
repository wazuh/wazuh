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
            std::filesystem::create_directories(m_tempDir);
            m_btmp = (m_tempDir / "btmp").string();
        }

        void TearDown() override
        {
            std::filesystem::remove_all(m_tempDir);
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

        /// @brief Writes the rotated generation that logrotate keeps beside btmp.
        void writeRotatedBtmp(const std::vector<std::pair<std::string, int32_t>>& records) const
        {
            std::ofstream file(m_btmp + ".1", std::ios::binary);

            for (const auto& record : records)
            {
                struct utmpx entry {};
                entry.ut_type = LOGIN_PROCESS;
                std::strncpy(entry.ut_user, record.first.c_str(), sizeof(entry.ut_user) - 1);
                entry.ut_tv.tv_sec = record.second;
                file.write(reinterpret_cast<const char*>(&entry), sizeof(entry));
            }
        }

        AuthFailuresProvider makeProvider(size_t tailBytes = 1024 * 1024) const
        {
            return AuthFailuresProvider(m_btmp, tailBytes);
        }

        std::filesystem::path m_tempDir;
        std::string m_btmp;
};

TEST_F(AuthFailuresProviderTests, BtmpCountsFailuresSinceTheLastLogin)
{
    writeBtmp({{"alice", 500}, {"alice", 1500}, {"alice", 2000}, {"mallory", 1600}, {"bob", 100}}, true);

    auto provider = makeProvider();
    provider.load({{"alice", 1000}, {"bob", 0}, {"dave", 0}}, true);

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
    provider.load({{"alice", 0}}, true);

    const auto failures = provider.get("alice");
    EXPECT_EQ(failures.count, 2u);
    EXPECT_EQ(failures.latest, 500u);
}

TEST_F(AuthFailuresProviderTests, EmptyBtmpIsUnknownNotZero)
{
    // Every distribution ships /var/log/btmp empty, and it stays that way where nothing records
    // failures into it. Answering zero there would report a confident "no failed logins" for every
    // account on the host, which is the false zero this collector exists to avoid.
    writeBtmp({});

    auto provider = makeProvider();
    provider.load({{"alice", 0}}, true);

    EXPECT_FALSE(provider.get("alice").known);
}

TEST_F(AuthFailuresProviderTests, BtmpWithOnlyUnattributableRecordsIsKnown)
{
    // The file is being written, so a count of zero for an account with no entry is a real zero.
    writeBtmp({{"mallory", 500}});

    auto provider = makeProvider();
    provider.load({{"alice", 0}}, true);

    const auto failures = provider.get("alice");
    EXPECT_TRUE(failures.known);
    EXPECT_EQ(failures.count, 0u);
}

TEST_F(AuthFailuresProviderTests, NoSourceIsUnknown)
{
    auto provider = makeProvider();
    provider.load({{"alice", 0}}, true);

    EXPECT_FALSE(provider.get("alice").known);
}

TEST_F(AuthFailuresProviderTests, BtmpThatIsNotAFileIsUnknown)
{
    std::filesystem::create_directories(m_btmp);

    auto provider = makeProvider();
    provider.load({{"alice", 0}}, true);

    EXPECT_FALSE(provider.get("alice").known);
}

TEST_F(AuthFailuresProviderTests, WithoutALastLoginSourceTheCountIsUnknown)
{
    // Debian 13 ships no /var/log/lastlog. Without one every account reads as never having logged in,
    // so every failure btmp still holds would be counted against it however long ago it happened.
    writeBtmp({{"alice", 100}, {"alice", 200}, {"alice", 300}});

    auto provider = makeProvider();
    provider.load({{"alice", 0}}, false);

    EXPECT_FALSE(provider.get("alice").known);
}

TEST_F(AuthFailuresProviderTests, RotatedBtmpIsCountedToo)
{
    // logrotate replaces btmp with an empty file monthly and keeps one generation beside it. Reading
    // only the live file would lose those failures and flip every account to unknown until the next one.
    writeBtmp({});
    writeRotatedBtmp({{"alice", 500}, {"alice", 600}});

    auto provider = makeProvider();
    provider.load({{"alice", 100}}, true);

    const auto failures = provider.get("alice");
    EXPECT_TRUE(failures.known);
    EXPECT_EQ(failures.count, 2u);
    EXPECT_EQ(failures.latest, 600u);
}

TEST_F(AuthFailuresProviderTests, LiveAndRotatedBtmpAreCombined)
{
    writeBtmp({{"alice", 700}});
    writeRotatedBtmp({{"alice", 500}, {"alice", 600}});

    auto provider = makeProvider();
    provider.load({{"alice", 100}}, true);

    const auto failures = provider.get("alice");
    EXPECT_EQ(failures.count, 3u);
    EXPECT_EQ(failures.latest, 700u);
}

TEST_F(AuthFailuresProviderTests, RotatedBtmpStillRespectsTheLastLoginFilter)
{
    writeBtmp({});
    writeRotatedBtmp({{"alice", 500}, {"alice", 600}});

    auto provider = makeProvider();
    // The account logged in after both failures, so neither counts.
    provider.load({{"alice", 900}}, true);

    const auto failures = provider.get("alice");
    EXPECT_TRUE(failures.known);
    EXPECT_EQ(failures.count, 0u);
}

TEST_F(AuthFailuresProviderTests, BothBtmpFilesEmptyIsUnknown)
{
    writeBtmp({});
    writeRotatedBtmp({});

    auto provider = makeProvider();
    provider.load({{"alice", 0}}, true);

    EXPECT_FALSE(provider.get("alice").known);
}
