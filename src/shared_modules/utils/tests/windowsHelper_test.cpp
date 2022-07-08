/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * November 10, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifdef WIN32
#include "windowsHelper_test.h"
#include "windowsHelper.h"

void WindowsHelperTest::SetUp() {};

void WindowsHelperTest::TearDown() {};

TEST_F(WindowsHelperTest, ipv6NetMask_64)
{
    const int addressPrefixLength { 64 };
    const std::string expectedNetMask { "ffff:ffff:ffff:ffff::" };
    std::string netMask { Utils::NetworkWindowsHelper::ipv6Netmask(addressPrefixLength) };
    EXPECT_EQ(expectedNetMask, netMask);
}

TEST_F(WindowsHelperTest, ipv6NetMask_127)
{
    const int addressPrefixLength { 127 };
    const std::string expectedNetMask { "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe" };
    std::string netMask { Utils::NetworkWindowsHelper::ipv6Netmask(addressPrefixLength) };
    EXPECT_EQ(expectedNetMask, netMask);
}

TEST_F(WindowsHelperTest, ipv6NetMask_55)
{
    const int addressPrefixLength { 55 };
    const std::string expectedNetMask { "ffff:ffff:ffff:fe::" };
    std::string netMask { Utils::NetworkWindowsHelper::ipv6Netmask(addressPrefixLength) };
    EXPECT_EQ(expectedNetMask, netMask);
}

TEST_F(WindowsHelperTest, ipv6NetMask_77)
{
    const int addressPrefixLength { 77 };
    const std::string expectedNetMask { "ffff:ffff:ffff:ffff:fff8::" };
    std::string netMask { Utils::NetworkWindowsHelper::ipv6Netmask(addressPrefixLength) };
    EXPECT_EQ(expectedNetMask, netMask);
}

TEST_F(WindowsHelperTest, ipv6NetMask_72)
{
    const int addressPrefixLength { 72 };
    const std::string expectedNetMask { "ffff:ffff:ffff:ffff:ff00::" };
    std::string netMask { Utils::NetworkWindowsHelper::ipv6Netmask(addressPrefixLength) };
    EXPECT_EQ(expectedNetMask, netMask);
}

TEST_F(WindowsHelperTest, ipv6NetMask_INVALID)
{
    const int addressPrefixLength { 130 };
    std::string netMask { Utils::NetworkWindowsHelper::ipv6Netmask(addressPrefixLength) };
    EXPECT_TRUE(netMask.empty());
}

TEST_F(WindowsHelperTest, normalizeTimestampSortValue)
{
    std::string value = "202202";
    std::string timestamp = "2022/02/15 14:04:50";
    std::string expected = UNKNOWN_VALUE;

    std::string result = Utils::normalizeTimestamp(value, timestamp);

    EXPECT_EQ(expected, result);
}

TEST_F(WindowsHelperTest, normalizeTimestampLongValue)
{
    std::string value = "2022021516";
    std::string timestamp = "2022/02/15 14:04:50";
    std::string expected = UNKNOWN_VALUE;

    std::string result = Utils::normalizeTimestamp(value, timestamp);

    EXPECT_EQ(expected, result);
}

TEST_F(WindowsHelperTest, normalizeTimestampUnknownValue)
{
    std::string value = UNKNOWN_VALUE;
    std::string timestamp = "2022/02/15 14:04:50";
    std::string expected = UNKNOWN_VALUE;

    std::string result = Utils::normalizeTimestamp(value, timestamp);

    EXPECT_EQ(expected, result);
}

TEST_F(WindowsHelperTest, normalizeTimestampNotEqual)
{
    std::string value = "20220214";
    std::string timestamp = "2022/02/15 14:04:50";
    std::string expected = "2022/02/14 00:00:00";

    std::string result = Utils::normalizeTimestamp(value, timestamp);

    EXPECT_EQ(expected, result);
}

TEST_F(WindowsHelperTest, normalizeTimestampEqual1)
{
    std::string value = "20220215";
    std::string timestamp = "2022/02/15 14:04:50";
    std::string expected = "2022/02/15 17:04:50";

    std::string result = Utils::normalizeTimestamp(value, timestamp);

    EXPECT_EQ(expected, result);
}

TEST_F(WindowsHelperTest, normalizeTimestampEqual2)
{
    std::string value = "20220215";
    std::string timestamp = "2022/02/15 23:59:59";
    std::string expected = "2022/02/16 02:59:59";

    std::string result = Utils::normalizeTimestamp(value, timestamp);

    EXPECT_EQ(expected, result);
}

TEST_F(WindowsHelperTest, normalizeTimestampWrongTimestamp1)
{
    std::string value = "a0220215";
    std::string timestamp = "2022/02/15 23:59:59";
    std::string expected = UNKNOWN_VALUE;

    std::string result = Utils::normalizeTimestamp(value, timestamp);

    EXPECT_EQ(expected, result);
}

TEST_F(WindowsHelperTest, normalizeTimestampWrongTimestamp2)
{
    std::string value = "20220215";
    std::string timestamp = "a022/02/15 23:59:59";
    std::string expected = UNKNOWN_VALUE;

    std::string result = Utils::normalizeTimestamp(value, timestamp);

    EXPECT_EQ(expected, result);
}

#endif
