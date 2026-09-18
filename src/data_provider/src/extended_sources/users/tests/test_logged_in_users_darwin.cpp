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

#include "logged_in_users_darwin.hpp"
#include "iutmpx_wrapper.hpp"

class MockUtmpxWrapper : public IUtmpxWrapper
{
    public:
        MOCK_METHOD(void, utmpxname, (const char* file), (override));
        MOCK_METHOD(void, setutxent, (), (override));
        MOCK_METHOD(void, endutxent, (), (override));
        MOCK_METHOD(struct utmpx*, getutxent, (), (override));
};

TEST(LoggedInUsersProviderTest, CollectReturnsExpectedJson)
{
    auto mockWrapper = std::make_shared<MockUtmpxWrapper>();

    struct utmpx fakeEntry = {};
    fakeEntry.ut_type = USER_PROCESS;
    fakeEntry.ut_pid = 1234;
    strncpy(fakeEntry.ut_user, "darwinuser", sizeof(fakeEntry.ut_user));
    strncpy(fakeEntry.ut_line, "pts/0", sizeof(fakeEntry.ut_line));
    strncpy(fakeEntry.ut_host, "localhost", sizeof(fakeEntry.ut_host));
    fakeEntry.ut_tv.tv_sec = 1715520000;

    EXPECT_CALL(*mockWrapper, utmpxname(::testing::_)).Times(1);
    EXPECT_CALL(*mockWrapper, setutxent()).Times(1);
    EXPECT_CALL(*mockWrapper, getutxent())
    .WillOnce(::testing::Return(&fakeEntry))
    .WillOnce(::testing::Return(nullptr));
    EXPECT_CALL(*mockWrapper, endutxent()).Times(1);

    LoggedInUsersProvider provider(mockWrapper);
    auto result = provider.collect();

    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["user"], "darwinuser");
    EXPECT_EQ(result[0]["type"], "user");
    EXPECT_EQ(result[0]["tty"], "pts/0");
    EXPECT_EQ(result[0]["host"], "localhost");
    EXPECT_EQ(result[0]["time"], 1715520000);
    EXPECT_EQ(result[0]["pid"], 1234);
}

TEST(LoggedInUsersProviderTest, CollectFiltersOutDeadProcessEntries)
{
    auto mockWrapper = std::make_shared<MockUtmpxWrapper>();

    struct utmpx deadEntry = {};
    deadEntry.ut_type = DEAD_PROCESS;
    deadEntry.ut_pid = 1880;
    strncpy(deadEntry.ut_user, "vagrant", sizeof(deadEntry.ut_user));
    strncpy(deadEntry.ut_line, "ttys001", sizeof(deadEntry.ut_line));
    deadEntry.ut_tv.tv_sec = 1715520000;

    EXPECT_CALL(*mockWrapper, utmpxname(::testing::_)).Times(1);
    EXPECT_CALL(*mockWrapper, setutxent()).Times(1);
    EXPECT_CALL(*mockWrapper, getutxent())
    .WillOnce(::testing::Return(&deadEntry))
    .WillOnce(::testing::Return(nullptr));
    EXPECT_CALL(*mockWrapper, endutxent()).Times(1);

    LoggedInUsersProvider provider(mockWrapper);
    auto result = provider.collect();

    EXPECT_TRUE(result.empty());
}

TEST(LoggedInUsersProviderTest, CollectKeepsLiveSessionAmongDeadOnes)
{
    auto mockWrapper = std::make_shared<MockUtmpxWrapper>();

    struct utmpx deadEntry = {};
    deadEntry.ut_type = DEAD_PROCESS;
    deadEntry.ut_pid = 1880;
    strncpy(deadEntry.ut_user, "vagrant", sizeof(deadEntry.ut_user));
    strncpy(deadEntry.ut_line, "ttys001", sizeof(deadEntry.ut_line));
    deadEntry.ut_tv.tv_sec = 1715520000;

    struct utmpx liveEntry = {};
    liveEntry.ut_type = USER_PROCESS;
    liveEntry.ut_pid = 4242;
    strncpy(liveEntry.ut_user, "darwinuser", sizeof(liveEntry.ut_user));
    strncpy(liveEntry.ut_line, "ttys002", sizeof(liveEntry.ut_line));
    liveEntry.ut_tv.tv_sec = 1715520500;

    EXPECT_CALL(*mockWrapper, utmpxname(::testing::_)).Times(1);
    EXPECT_CALL(*mockWrapper, setutxent()).Times(1);
    EXPECT_CALL(*mockWrapper, getutxent())
    .WillOnce(::testing::Return(&deadEntry))
    .WillOnce(::testing::Return(&liveEntry))
    .WillOnce(::testing::Return(nullptr));
    EXPECT_CALL(*mockWrapper, endutxent()).Times(1);

    LoggedInUsersProvider provider(mockWrapper);
    auto result = provider.collect();

    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["user"], "darwinuser");
    EXPECT_EQ(result[0]["type"], "user");
    EXPECT_EQ(result[0]["tty"], "ttys002");
    EXPECT_EQ(result[0]["pid"], 4242);
}
