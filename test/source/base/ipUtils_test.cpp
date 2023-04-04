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
    EXPECT_EQ(utils::ip::IPv4ToUInt("192.168.0.1"),
              0b11000000'10101000'00000000'00000001);
    EXPECT_EQ(utils::ip::IPv4ToUInt("255.255.255.255"), 0xFFFFFFFF);
}

TEST(checkStrIsIPv4, Invalid_format)
{
    EXPECT_FALSE(utils::ip::checkStrIsIPv4(""));
    EXPECT_FALSE(utils::ip::checkStrIsIPv4("1"));
    EXPECT_FALSE(utils::ip::checkStrIsIPv4("1.2"));
    EXPECT_FALSE(utils::ip::checkStrIsIPv4("1.2.3"));
    EXPECT_FALSE(utils::ip::checkStrIsIPv4(" 1.2.3.4 "));
    EXPECT_FALSE(utils::ip::checkStrIsIPv4(".1.2.3.4."));
    EXPECT_FALSE(utils::ip::checkStrIsIPv4("1.2.3.4."));
    EXPECT_FALSE(utils::ip::checkStrIsIPv4(""));
    EXPECT_FALSE(utils::ip::checkStrIsIPv4("only text"));
    EXPECT_FALSE(utils::ip::checkStrIsIPv4("1233.1.1.1"));
}

TEST(checkStrIsIPv4, Invalid_range)
{
    EXPECT_FALSE(utils::ip::checkStrIsIPv4("-1.1.1.1"));
    EXPECT_FALSE(utils::ip::checkStrIsIPv4("1.-1.1.1"));
    EXPECT_FALSE(utils::ip::checkStrIsIPv4("1.1.-1.1"));
    EXPECT_FALSE(utils::ip::checkStrIsIPv4("1.1.1.-1"));
    EXPECT_FALSE(utils::ip::checkStrIsIPv4("256.1.1.1"));
    EXPECT_FALSE(utils::ip::checkStrIsIPv4("1.256.1.1"));
    EXPECT_FALSE(utils::ip::checkStrIsIPv4("1.1.256.1"));
    EXPECT_FALSE(utils::ip::checkStrIsIPv4("1.1.1.256"));
}

TEST(checkStrIsIPv4, Valid_range)
{
    EXPECT_TRUE(utils::ip::checkStrIsIPv4("0.0.0.0"));
    EXPECT_TRUE(utils::ip::checkStrIsIPv4("127.0.0.1"));
    EXPECT_TRUE(utils::ip::checkStrIsIPv4("192.168.0.1"));
    EXPECT_TRUE(utils::ip::checkStrIsIPv4("255.255.255.255"));
}



TEST(checkStrIsIPv6, Invalid_format)
{
    EXPECT_FALSE(utils::ip::checkStrIsIPv6(""));
    EXPECT_FALSE(utils::ip::checkStrIsIPv6("1"));
    EXPECT_FALSE(utils::ip::checkStrIsIPv6("1.2"));
    EXPECT_FALSE(utils::ip::checkStrIsIPv6("1.2.3"));
    EXPECT_FALSE(utils::ip::checkStrIsIPv6(" 1.2.3.4 "));
    EXPECT_FALSE(utils::ip::checkStrIsIPv6(".1.2.3.4."));
    EXPECT_FALSE(utils::ip::checkStrIsIPv6("1.2.3.4."));
    EXPECT_FALSE(utils::ip::checkStrIsIPv6(""));
    EXPECT_FALSE(utils::ip::checkStrIsIPv6("only text"));
    EXPECT_FALSE(utils::ip::checkStrIsIPv6("1233.1.1.1"));
    EXPECT_FALSE(utils::ip::checkStrIsIPv6("x:x:x:x:x:x:x:x"));
}

TEST(checkStrIsIPv6, Invalid_range)
{
    EXPECT_FALSE(utils::ip::checkStrIsIPv6("1:1:1:1:1:1:1:G"));
    EXPECT_FALSE(utils::ip::checkStrIsIPv6("::G"));
    EXPECT_FALSE(utils::ip::checkStrIsIPv6("56FE::2159:5BBC::6594"));


    EXPECT_FALSE(utils::ip::checkStrIsIPv6("x:x:x:x:x:x:x:x"));
    EXPECT_FALSE(utils::ip::checkStrIsIPv6("x:x:x:x:x:x:x:x"));
    EXPECT_FALSE(utils::ip::checkStrIsIPv6("x:x:x:x:x:x:x:x"));
    EXPECT_FALSE(utils::ip::checkStrIsIPv6("x:x:x:x:x:x:x:x"));
    EXPECT_FALSE(utils::ip::checkStrIsIPv6("x:x:x:x:x:x:x:x"));
    EXPECT_FALSE(utils::ip::checkStrIsIPv6("x:x:x:x:x:x:x:x"));
    EXPECT_FALSE(utils::ip::checkStrIsIPv6("x:x:x:x:x:x:x:x"));
}

TEST(checkStrIsIPv6, Valid_range)
{
    EXPECT_TRUE(utils::ip::checkStrIsIPv6("0:0:0:0:0:0:0:0"));
    EXPECT_TRUE(utils::ip::checkStrIsIPv6("::1"));
    EXPECT_TRUE(utils::ip::checkStrIsIPv6("1:1:1:1:1:1:1:1"));
    EXPECT_TRUE(utils::ip::checkStrIsIPv6("::255.255.255.255"));
    EXPECT_TRUE(utils::ip::checkStrIsIPv6("::"));
    EXPECT_TRUE(utils::ip::checkStrIsIPv6("::FFFF:204.152.189.116"));
    EXPECT_TRUE(utils::ip::checkStrIsIPv6("59FB::1005:CC57:6571"));
    EXPECT_TRUE(utils::ip::checkStrIsIPv6("21E5:69AA:FFFF:1:E100:B691:1285:F56E"));
    EXPECT_TRUE(utils::ip::checkStrIsIPv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
    EXPECT_TRUE(utils::ip::checkStrIsIPv6("2001:db8:85a3:0:0:8a2e:370:7334"));
}
