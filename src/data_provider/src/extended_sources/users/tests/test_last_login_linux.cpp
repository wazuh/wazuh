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

#include "last_login_linux.hpp"
#include "pread_wrapper.hpp"

#include <sqlite3.h>

#include <cstring>
#include <filesystem>
#include <fstream>

class MockPreadWrapper : public IPreadWrapper
{
    public:
        MOCK_METHOD(int, open, (const char* path), (override));
        MOCK_METHOD(ssize_t, pread, (int fd, void* buffer, size_t count, uint64_t offset), (override));
        MOCK_METHOD(void, close, (int fd), (override));
};

class LastLoginProviderTests : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            m_tempDir = std::filesystem::temp_directory_path() / "last_login_provider_test";
            std::filesystem::remove_all(m_tempDir);
            std::filesystem::create_directories(m_tempDir);
            m_lastlog = (m_tempDir / "lastlog").string();
            m_lastlog2 = (m_tempDir / "lastlog2.db").string();
        }

        void TearDown() override
        {
            std::filesystem::remove_all(m_tempDir);
        }

        /// @brief Writes the 292-byte record of a uid, leaving a hole before it when the file is shorter.
        void writeLastlog(uint32_t uid, int32_t time) const
        {
            char record[292] = {};
            std::memcpy(record, &time, sizeof(time));
            std::fstream file(m_lastlog, std::ios::in | std::ios::out | std::ios::binary);

            if (!file.is_open())
            {
                file.open(m_lastlog, std::ios::out | std::ios::binary);
            }

            file.seekp(static_cast<std::streamoff>(uid) * 292);
            file.write(record, sizeof(record));
        }

        /// @brief Creates a lastlog2 database with the upstream schema and one row per entry.
        void writeLastlog2(const std::vector<std::pair<std::string, int64_t>>& rows) const
        {
            sqlite3* db = nullptr;
            ASSERT_EQ(sqlite3_open(m_lastlog2.c_str(), &db), SQLITE_OK);
            ASSERT_EQ(sqlite3_exec(db, "CREATE TABLE Lastlog2(Name TEXT PRIMARY KEY, Time INTEGER, TTY TEXT, RemoteHost TEXT, Service TEXT)", nullptr, nullptr, nullptr), SQLITE_OK);

            for (const auto& row : rows)
            {
                const auto sql = "INSERT INTO Lastlog2 VALUES ('" + row.first + "', " + std::to_string(row.second) + ", 'pts/0', '', 'sshd')";
                ASSERT_EQ(sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr), SQLITE_OK);
            }

            sqlite3_close(db);
        }

        LastLoginProvider makeProvider() const
        {
            return LastLoginProvider(m_lastlog, m_lastlog2, std::make_shared<PreadWrapper>());
        }

        std::filesystem::path m_tempDir;
        std::string m_lastlog;
        std::string m_lastlog2;
};

TEST_F(LastLoginProviderTests, MissingSourcesGiveNoLogin)
{
    auto provider = makeProvider();
    EXPECT_EQ(provider.lastLogin(1000, "alice"), 0u);
}

TEST_F(LastLoginProviderTests, ReadsTheRecordOfTheUid)
{
    writeLastlog(0, 1000);
    writeLastlog(1000, 2000);

    auto provider = makeProvider();
    EXPECT_EQ(provider.lastLogin(0, "root"), 1000u);
    EXPECT_EQ(provider.lastLogin(1000, "alice"), 2000u);
}

TEST_F(LastLoginProviderTests, HoleZeroTimeAndPastEndGiveNoLogin)
{
    writeLastlog(0, 1000);
    writeLastlog(1000, 2000);
    writeLastlog(1001, 0);

    auto provider = makeProvider();
    // Inside the hole between the two records.
    EXPECT_EQ(provider.lastLogin(500, "nobody"), 0u);
    // A record whose time is zero.
    EXPECT_EQ(provider.lastLogin(1001, "bob"), 0u);
    // Past the end of the file.
    EXPECT_EQ(provider.lastLogin(5000, "carol"), 0u);
}

TEST_F(LastLoginProviderTests, TimeAfter2038IsNotNegative)
{
    writeLastlog(1000, static_cast<int32_t>(0x80000000u));

    auto provider = makeProvider();
    EXPECT_EQ(provider.lastLogin(1000, "alice"), 2147483648u);
}

TEST(LastLoginProviderOffsetTests, HighestUidIsRequestedAsA64BitOffset)
{
    auto reader = std::make_shared<MockPreadWrapper>();

    EXPECT_CALL(*reader, open(::testing::_)).WillOnce(::testing::Return(3));
    // 4294967294 * 292, which does not fit in 32 bits.
    EXPECT_CALL(*reader, pread(3, ::testing::_, 292u, 1254130449848ull)).WillOnce(::testing::Return(0));
    EXPECT_CALL(*reader, close(3)).Times(1);

    LastLoginProvider provider("lastlog", "/nonexistent/lastlog2.db", reader);
    EXPECT_EQ(provider.lastLogin(4294967294u, "nfsnobody"), 0u);
}

TEST(LastLoginProviderOffsetTests, ShortReadGivesNoLogin)
{
    auto reader = std::make_shared<MockPreadWrapper>();

    EXPECT_CALL(*reader, open(::testing::_)).WillOnce(::testing::Return(3));
    EXPECT_CALL(*reader, pread(3, ::testing::_, 292u, 292000ull)).WillOnce(::testing::Return(100));
    EXPECT_CALL(*reader, close(3)).Times(1);

    LastLoginProvider provider("lastlog", "/nonexistent/lastlog2.db", reader);
    EXPECT_EQ(provider.lastLogin(1000, "alice"), 0u);
}

TEST_F(LastLoginProviderTests, Lastlog2WinsWhenNewer)
{
    writeLastlog(1000, 2000);
    writeLastlog2({{"alice", 3000}});

    auto provider = makeProvider();
    EXPECT_EQ(provider.lastLogin(1000, "alice"), 3000u);
}

TEST_F(LastLoginProviderTests, LastlogWinsWhenNewerThanLastlog2)
{
    writeLastlog(1000, 4000);
    writeLastlog2({{"alice", 3000}});

    auto provider = makeProvider();
    EXPECT_EQ(provider.lastLogin(1000, "alice"), 4000u);
}

TEST_F(LastLoginProviderTests, Lastlog2AnswersWhenLastlogIsEmpty)
{
    writeLastlog2({{"bob", 5000}});

    auto provider = makeProvider();
    EXPECT_EQ(provider.lastLogin(1001, "bob"), 5000u);
    EXPECT_EQ(provider.lastLogin(1002, "carol"), 0u);
}

TEST_F(LastLoginProviderTests, CorruptLastlog2IsIgnored)
{
    writeLastlog(1000, 2000);
    std::ofstream(m_lastlog2) << "this is not a database, only text that is long enough to be read as a header";

    auto provider = makeProvider();
    EXPECT_EQ(provider.lastLogin(1000, "alice"), 2000u);
    EXPECT_EQ(provider.lastLogin(1001, "bob"), 0u);
}
