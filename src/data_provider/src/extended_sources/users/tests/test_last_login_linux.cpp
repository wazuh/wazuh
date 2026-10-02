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

#include <lastlog.h>

#include <cstring>
#include <utility>
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

        /// @brief Writes the record of a uid, leaving a hole before it when the file is shorter.
        void writeLastlog(uint32_t uid, int64_t time) const
        {
            // Sized from the system struct on purpose: glibc picks ll_time's width per platform, so a
            // fixture hardcoded to one width would read back correctly under a stride that does not
            // match what shadow and pam actually write on this architecture.
            char record[sizeof(struct lastlog)] = {};
            const auto onDisk = static_cast<decltype(std::declval<struct lastlog>().ll_time)>(time);
            std::memcpy(record, &onDisk, sizeof(onDisk));
            std::fstream file(m_lastlog, std::ios::in | std::ios::out | std::ios::binary);

            if (!file.is_open())
            {
                file.open(m_lastlog, std::ios::out | std::ios::binary);
            }

            file.seekp(static_cast<std::streamoff>(uid) * static_cast<std::streamoff>(sizeof(struct lastlog)));
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
    // 2038-01-19 03:14:08 UTC. On a 32-bit ll_time this is stored negative and has to read back
    // unsigned; on a 64-bit one it is stored as-is. Either way the reported value is the same.
    writeLastlog(1000, 2147483648LL);

    auto provider = makeProvider();
    EXPECT_EQ(provider.lastLogin(1000, "alice"), 2147483648u);
}

TEST(LastLoginProviderOffsetTests, HighestUidIsRequestedAsA64BitOffset)
{
    auto reader = std::make_shared<MockPreadWrapper>();

    EXPECT_CALL(*reader, open(::testing::_)).WillOnce(::testing::Return(3));
    // 4294967294 records in, which does not fit in 32 bits whichever stride the platform uses.
    constexpr auto RECORD = sizeof(struct lastlog);
    EXPECT_CALL(*reader, pread(3, ::testing::_, RECORD, 4294967294ull * RECORD)).WillOnce(::testing::Return(0));
    EXPECT_CALL(*reader, close(3)).Times(1);

    LastLoginProvider provider("lastlog", "/nonexistent/lastlog2.db", reader);
    EXPECT_EQ(provider.lastLogin(4294967294u, "nfsnobody"), 0u);
}

TEST(LastLoginProviderOffsetTests, ShortReadGivesNoLogin)
{
    auto reader = std::make_shared<MockPreadWrapper>();

    EXPECT_CALL(*reader, open(::testing::_)).WillOnce(::testing::Return(3));
    EXPECT_CALL(*reader, pread(3, ::testing::_, sizeof(struct lastlog), 1000ull * sizeof(struct lastlog)))
    .WillOnce(::testing::Return(100));
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

// The production branch is chosen at compile time, so CI on x86_64 never reaches the 64-bit path.
// These exercise both widths on whatever architecture runs them.
TEST(LastLoginRecordTimeTests, ThirtyTwoBitWrapsForwardPast2038)
{
    EXPECT_EQ(lastLoginFromRecordTime(static_cast<int32_t>(0)), 0u);
    EXPECT_EQ(lastLoginFromRecordTime(static_cast<int32_t>(1700000000)), 1700000000u);
    // 2038-01-19 03:14:08 UTC, stored negative in a signed 32-bit field.
    EXPECT_EQ(lastLoginFromRecordTime(static_cast<int32_t>(0x80000000)), 2147483648u);
    EXPECT_EQ(lastLoginFromRecordTime(static_cast<int32_t>(-1)), 4294967295u);
}

TEST(LastLoginRecordTimeTests, SixtyFourBitRejectsNegativesAndHoldsTheMaximum)
{
    EXPECT_EQ(lastLoginFromRecordTime(static_cast<int64_t>(0)), 0u);
    EXPECT_EQ(lastLoginFromRecordTime(static_cast<int64_t>(1700000000)), 1700000000u);
    EXPECT_EQ(lastLoginFromRecordTime(static_cast<int64_t>(2147483648LL)), 2147483648u);
    // A negative time cannot be a login where the field does not wrap.
    EXPECT_EQ(lastLoginFromRecordTime(static_cast<int64_t>(-1)), 0u);
    EXPECT_EQ(lastLoginFromRecordTime(static_cast<int64_t>(-2147483648LL)), 0u);
    // Past what the reported field can hold, kept at the maximum rather than wrapping round.
    EXPECT_EQ(lastLoginFromRecordTime(static_cast<int64_t>(4294967296LL)), 4294967295u);
    EXPECT_EQ(lastLoginFromRecordTime(INT64_MAX), 4294967295u);
}
