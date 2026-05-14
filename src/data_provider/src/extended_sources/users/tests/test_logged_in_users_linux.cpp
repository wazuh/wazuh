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

#include "logged_in_users_linux.hpp"
#include "iutmpx_wrapper.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstring>

class MockUtmpxWrapper : public IUtmpxWrapper
{
    public:
        MOCK_METHOD(void, utmpxname, (const char* file), (override));
        MOCK_METHOD(void, setutxent, (), (override));
        MOCK_METHOD(void, endutxent, (), (override));
        MOCK_METHOD(struct utmpx*, getutxent, (), (override));
};

void fillCommonFields(struct utmpx& entry)
{
    entry.ut_type = USER_PROCESS;
    entry.ut_pid = 1234;
    strncpy(entry.ut_user, "testuser", sizeof(entry.ut_user));
    strncpy(entry.ut_line, "pts/0", sizeof(entry.ut_line));
    entry.ut_tv.tv_sec = 1715520000;
}

TEST(LoggedInUsersProviderTestLocalhost, CollectReturnsExpectedJson)
{
    auto mockWrapper = std::make_shared<MockUtmpxWrapper>();

    struct utmpx fakeEntry = {};
    fakeEntry.ut_type = USER_PROCESS;
    fakeEntry.ut_pid = 1234;
    strncpy(fakeEntry.ut_user, "testuser", sizeof(fakeEntry.ut_user));
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
    EXPECT_EQ(result[0]["user"], "testuser");
    EXPECT_EQ(result[0]["type"], "user");
    EXPECT_EQ(result[0]["tty"], "pts/0");
    EXPECT_EQ(result[0]["host"], "0.0.0.0");
    EXPECT_EQ(result[0]["time"], 1715520000);
    EXPECT_EQ(result[0]["pid"], 1234);
}

TEST(LoggedInUsersProviderTestIPv4, CollectReturnsExpectedIPv4)
{
    auto mockWrapper = std::make_shared<MockUtmpxWrapper>();
    struct utmpx fakeEntry = {};
    fillCommonFields(fakeEntry);

    struct in_addr ipv4;
    inet_pton(AF_INET, "192.168.100.100", &ipv4);
    fakeEntry.ut_addr_v6[0] = ipv4.s_addr;
    fakeEntry.ut_addr_v6[1] = 0;
    fakeEntry.ut_addr_v6[2] = 0;
    fakeEntry.ut_addr_v6[3] = 0;

    EXPECT_CALL(*mockWrapper, utmpxname(::testing::_)).Times(1);
    EXPECT_CALL(*mockWrapper, setutxent()).Times(1);
    EXPECT_CALL(*mockWrapper, getutxent())
    .WillOnce(::testing::Return(&fakeEntry))
    .WillOnce(::testing::Return(nullptr));
    EXPECT_CALL(*mockWrapper, endutxent()).Times(1);

    LoggedInUsersProvider provider(mockWrapper);
    auto result = provider.collect();

    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0]["host"], "192.168.100.100");
}

TEST(LoggedInUsersProviderTestIPv6, CollectReturnsExpectedIPv6)
{
    auto mockWrapper = std::make_shared<MockUtmpxWrapper>();
    struct utmpx fakeEntry = {};
    fillCommonFields(fakeEntry);

    struct in6_addr ipv6;
    inet_pton(AF_INET6, "2001:db8::1", &ipv6);
    std::memcpy(fakeEntry.ut_addr_v6, &ipv6, sizeof(ipv6));

    EXPECT_CALL(*mockWrapper, utmpxname(::testing::_)).Times(1);
    EXPECT_CALL(*mockWrapper, setutxent()).Times(1);
    EXPECT_CALL(*mockWrapper, getutxent())
    .WillOnce(::testing::Return(&fakeEntry))
    .WillOnce(::testing::Return(nullptr));
    EXPECT_CALL(*mockWrapper, endutxent()).Times(1);

    LoggedInUsersProvider provider(mockWrapper);
    auto result = provider.collect();

    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0]["host"], "2001:db8::1");
}
