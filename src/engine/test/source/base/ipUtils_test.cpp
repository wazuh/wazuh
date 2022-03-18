/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>

#include <utils/ipUtils.hpp>

TEST(IPv4ToUInt, Invalid_format)
{
    EXPECT_THROW(utils::ip::IPv4ToUInt(""), std::invalid_argument);
    EXPECT_THROW(utils::ip::IPv4ToUInt("1"), std::invalid_argument);
    EXPECT_THROW(utils::ip::IPv4ToUInt("1.2"), std::invalid_argument);
    EXPECT_THROW(utils::ip::IPv4ToUInt("1.2.3"), std::invalid_argument);
    EXPECT_THROW(utils::ip::IPv4ToUInt("1.2.3.4."), std::invalid_argument);
    EXPECT_THROW(utils::ip::IPv4ToUInt("1.2.3.255."), std::invalid_argument);
    EXPECT_THROW(utils::ip::IPv4ToUInt("1.2.3.4.5"), std::invalid_argument);
    EXPECT_THROW(utils::ip::IPv4ToUInt(" 1.1.1.1 "), std::invalid_argument);
}

TEST(IPv4ToUInt, Invalid_range)
{
    EXPECT_THROW(utils::ip::IPv4ToUInt("-1.1.1.1"), std::invalid_argument);
    EXPECT_THROW(utils::ip::IPv4ToUInt("1.-1.1.1"), std::invalid_argument);
    EXPECT_THROW(utils::ip::IPv4ToUInt("1.1.-1.1"), std::invalid_argument);
    EXPECT_THROW(utils::ip::IPv4ToUInt("1.1.1.-1"), std::invalid_argument);
    EXPECT_THROW(utils::ip::IPv4ToUInt("256.1.1.1"), std::invalid_argument);
    EXPECT_THROW(utils::ip::IPv4ToUInt("1.256.1.1"), std::invalid_argument);
    EXPECT_THROW(utils::ip::IPv4ToUInt("1.1.256.1"), std::invalid_argument);
    EXPECT_THROW(utils::ip::IPv4ToUInt("1.1.1.256"), std::invalid_argument);

}

TEST(IPv4ToUInt, Valid_range)
{
    EXPECT_EQ(utils::ip::IPv4ToUInt("0.0.0.0"), 0x0);
    EXPECT_EQ(utils::ip::IPv4ToUInt("127.0.0.1"), 0x7F'00'00'01);
    EXPECT_EQ(utils::ip::IPv4ToUInt("192.168.0.1"), 0b11000000'10101000'00000000'00000001);
    EXPECT_EQ(utils::ip::IPv4ToUInt("255.255.255.255"), 0xFFFFFFFF);
}
