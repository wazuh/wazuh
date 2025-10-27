#include <gtest/gtest.h>

#include <base/utils/ipUtils.hpp>

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

TEST(IPv4MaskUInt, Invalid_format)
{
    EXPECT_THROW(utils::ip::IPv4MaskUInt(""), std::invalid_argument);
    EXPECT_THROW(utils::ip::IPv4MaskUInt("1.2"), std::invalid_argument);
    EXPECT_THROW(utils::ip::IPv4MaskUInt("1.2.3"), std::invalid_argument);
    EXPECT_THROW(utils::ip::IPv4MaskUInt("1.2.3.4."), std::invalid_argument);
    EXPECT_THROW(utils::ip::IPv4MaskUInt("1.2.3.255."), std::invalid_argument);
    EXPECT_THROW(utils::ip::IPv4MaskUInt("1.2.3.4.5"), std::invalid_argument);
    EXPECT_THROW(utils::ip::IPv4MaskUInt(" 1.1.1.1 "), std::invalid_argument);
}

TEST(IPv4MaskUInt, Invalid_range)
{
    EXPECT_THROW(utils::ip::IPv4MaskUInt("-1.1.1.1"), std::invalid_argument);
    EXPECT_THROW(utils::ip::IPv4MaskUInt("1.-1.1.1"), std::invalid_argument);
    EXPECT_THROW(utils::ip::IPv4MaskUInt("1.1.-1.1"), std::invalid_argument);
    EXPECT_THROW(utils::ip::IPv4MaskUInt("1.1.1.-1"), std::invalid_argument);
    EXPECT_THROW(utils::ip::IPv4MaskUInt("256.1.1.1"), std::invalid_argument);
    EXPECT_THROW(utils::ip::IPv4MaskUInt("1.256.1.1"), std::invalid_argument);
    EXPECT_THROW(utils::ip::IPv4MaskUInt("1.1.256.1"), std::invalid_argument);
    EXPECT_THROW(utils::ip::IPv4MaskUInt("1.1.1.256"), std::invalid_argument);
}

TEST(IPv4MaskUInt, Valid_range)
{
    EXPECT_EQ(utils::ip::IPv4MaskUInt("255.255.255.0"), 0xFFFFFF00);
    EXPECT_EQ(utils::ip::IPv4MaskUInt("255.255.0.0"), 0xFFFF0000);
    EXPECT_EQ(utils::ip::IPv4MaskUInt("255.0.0.0"), 0xFF000000);
    EXPECT_EQ(utils::ip::IPv4MaskUInt("8"), 0xFF000000);
    EXPECT_EQ(utils::ip::IPv4MaskUInt("16"), 0xFFFF0000);
    EXPECT_EQ(utils::ip::IPv4MaskUInt("24"), 0xFFFFFF00);
    EXPECT_EQ(utils::ip::IPv4MaskUInt("32"), 0xFFFFFFFF);
    EXPECT_EQ(utils::ip::IPv4MaskUInt("0"), 0x0);
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

TEST(isSpecialIPv4Address, Invalid_format)
{
    EXPECT_THROW(utils::ip::isSpecialIPv4Address(""), std::invalid_argument);
    EXPECT_THROW(utils::ip::isSpecialIPv4Address("1"), std::invalid_argument);
    EXPECT_THROW(utils::ip::isSpecialIPv4Address("1.2"), std::invalid_argument);
    EXPECT_THROW(utils::ip::isSpecialIPv4Address("1.2.3"), std::invalid_argument);
    EXPECT_THROW(utils::ip::isSpecialIPv4Address("1.2.3.4.5"), std::invalid_argument);
    EXPECT_THROW(utils::ip::isSpecialIPv4Address(".1.2.3.4"), std::invalid_argument);
}

TEST(isSpecialIPv4Address, Invalid_range)
{
    EXPECT_THROW(utils::ip::isSpecialIPv4Address("-1.1.1.1"), std::invalid_argument);
    EXPECT_THROW(utils::ip::isSpecialIPv4Address("1.-1.1.1"), std::invalid_argument);
    EXPECT_THROW(utils::ip::isSpecialIPv4Address("1.1.-1.1"), std::invalid_argument);
    EXPECT_THROW(utils::ip::isSpecialIPv4Address("1.1.1.-1"), std::invalid_argument);
    EXPECT_THROW(utils::ip::isSpecialIPv4Address("256.1.1.1"), std::invalid_argument);
    EXPECT_THROW(utils::ip::isSpecialIPv4Address("1.256.1.1"), std::invalid_argument);
    EXPECT_THROW(utils::ip::isSpecialIPv4Address("1.1.256.1"), std::invalid_argument);
    EXPECT_THROW(utils::ip::isSpecialIPv4Address("1.1.1.256"), std::invalid_argument);
}

TEST(isSpecialIPv4Address, Valid_range)
{
    EXPECT_FALSE(utils::ip::isSpecialIPv4Address("1.1.1.1"));
    EXPECT_FALSE(utils::ip::isSpecialIPv4Address("8.8.8.8"));

    EXPECT_FALSE(utils::ip::isSpecialIPv4Address("192.167.255.255"));
    EXPECT_TRUE(utils::ip::isSpecialIPv4Address("192.168.0.0"));
    EXPECT_TRUE(utils::ip::isSpecialIPv4Address("192.168.0.1"));
    EXPECT_TRUE(utils::ip::isSpecialIPv4Address("192.168.255.254"));
    EXPECT_TRUE(utils::ip::isSpecialIPv4Address("192.168.255.255"));
    EXPECT_FALSE(utils::ip::isSpecialIPv4Address("192.169.0.0"));

    EXPECT_FALSE(utils::ip::isSpecialIPv4Address("9.255.255.255"));
    EXPECT_TRUE(utils::ip::isSpecialIPv4Address("10.0.0.0"));
    EXPECT_TRUE(utils::ip::isSpecialIPv4Address("10.0.0.1"));
    EXPECT_TRUE(utils::ip::isSpecialIPv4Address("10.255.255.254"));
    EXPECT_TRUE(utils::ip::isSpecialIPv4Address("10.255.255.255"));
    EXPECT_FALSE(utils::ip::isSpecialIPv4Address("11.0.0.0"));

    EXPECT_FALSE(utils::ip::isSpecialIPv4Address("172.15.255.255"));
    EXPECT_TRUE(utils::ip::isSpecialIPv4Address("172.16.0.0"));
    EXPECT_TRUE(utils::ip::isSpecialIPv4Address("172.16.0.1"));
    EXPECT_TRUE(utils::ip::isSpecialIPv4Address("172.31.255.254"));
    EXPECT_TRUE(utils::ip::isSpecialIPv4Address("172.31.255.255"));
    EXPECT_FALSE(utils::ip::isSpecialIPv4Address("172.32.0.0"));
}

TEST(isSpecialIPv6Address, Invalid_format)
{
    EXPECT_THROW(utils::ip::isSpecialIPv6Address(""), std::invalid_argument);
    EXPECT_THROW(utils::ip::isSpecialIPv6Address("1"), std::invalid_argument);
    EXPECT_THROW(utils::ip::isSpecialIPv6Address("1.2"), std::invalid_argument);
    EXPECT_THROW(utils::ip::isSpecialIPv6Address("1.2.3"), std::invalid_argument);
    EXPECT_THROW(utils::ip::isSpecialIPv6Address(" 1.2.3.4 "), std::invalid_argument);
    EXPECT_THROW(utils::ip::isSpecialIPv6Address(".1.2.3.4."), std::invalid_argument);
    EXPECT_THROW(utils::ip::isSpecialIPv6Address("1.2.3.4."), std::invalid_argument);
    EXPECT_THROW(utils::ip::isSpecialIPv6Address(""), std::invalid_argument);
    EXPECT_THROW(utils::ip::isSpecialIPv6Address("only text"), std::invalid_argument);
    EXPECT_THROW(utils::ip::isSpecialIPv6Address("1233.1.1.1"), std::invalid_argument);
    EXPECT_THROW(utils::ip::isSpecialIPv6Address("x:x:x:x:x:x:x:x"), std::invalid_argument);
}

TEST(isSpecialIPv6Address, Invalid_range)
{
    EXPECT_THROW(utils::ip::isSpecialIPv6Address("1:1:1:1:1:1:1:G"), std::invalid_argument);
    EXPECT_THROW(utils::ip::isSpecialIPv6Address("::G"), std::invalid_argument);
    EXPECT_THROW(utils::ip::isSpecialIPv6Address("56FE::2159:5BBC::6594"), std::invalid_argument);
}

TEST(isSpecialIPv6Address, Valid_range)
{
    // Loopback
    EXPECT_TRUE(utils::ip::isSpecialIPv6Address("::1"));
    EXPECT_TRUE(utils::ip::isSpecialIPv6Address("fe80::"));
    // Link-local
    EXPECT_TRUE(utils::ip::isSpecialIPv6Address("fe80::1"));
    EXPECT_TRUE(utils::ip::isSpecialIPv6Address("fe80::1:1"));
    EXPECT_TRUE(utils::ip::isSpecialIPv6Address("fc00::"));
    // ULA
    EXPECT_TRUE(utils::ip::isSpecialIPv6Address("fc00::1"));
    EXPECT_TRUE(utils::ip::isSpecialIPv6Address("fc00::1:1"));

    EXPECT_FALSE(utils::ip::isSpecialIPv6Address("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
    EXPECT_FALSE(utils::ip::isSpecialIPv6Address("1:1:1:1:1:1:1:1"));
    EXPECT_FALSE(utils::ip::isSpecialIPv6Address("2001:0db8:1234:0000:0000:0000:0000:0001"));
    EXPECT_FALSE(utils::ip::isSpecialIPv6Address("2001:db8:1234::1"));
    EXPECT_FALSE(utils::ip::isSpecialIPv6Address("2001:db8:1234:0:0:0:0:1"));
    EXPECT_FALSE(utils::ip::isSpecialIPv6Address("2001:0db8:1234:ffff:ffff:ffff:ffff:ffff"));
}

TEST(IanaProtocolNormalize, BasicAndAliases)
{
    using utils::ip::normalizeIanaProtocolName;

    EXPECT_EQ(normalizeIanaProtocolName("TCP"), "tcp");
    EXPECT_EQ(normalizeIanaProtocolName("ipv6 icmp"), "ipv6-icmp"); // space -> '-'
    EXPECT_EQ(normalizeIanaProtocolName("udp_lite"), "udplite");    // '_' -> '-' -> alias
    EXPECT_EQ(normalizeIanaProtocolName("UDP-LITE"), "udplite");    // alias
    EXPECT_EQ(normalizeIanaProtocolName("IP-in-IP"), "ipip");       // alias
}

// -------- ianaProtocolNameToNumber --------
TEST(IanaProtocolNameToNumber, ValidBasics)
{
    using utils::ip::ianaProtocolNameToNumber;

    auto tcp = ianaProtocolNameToNumber("tcp");
    ASSERT_TRUE(tcp.has_value());
    EXPECT_EQ(*tcp, 6);

    auto udp = ianaProtocolNameToNumber("UDP"); // case-insensitive
    ASSERT_TRUE(udp.has_value());
    EXPECT_EQ(*udp, 17);

    auto ipv4 = ianaProtocolNameToNumber("ipv4");
    ASSERT_TRUE(ipv4.has_value());
    EXPECT_EQ(*ipv4, 4);

    auto ipv6 = ianaProtocolNameToNumber("IPv6");
    ASSERT_TRUE(ipv6.has_value());
    EXPECT_EQ(*ipv6, 41);

    auto icmpv6 = ianaProtocolNameToNumber("ipv6-icmp");
    ASSERT_TRUE(icmpv6.has_value());
    EXPECT_EQ(*icmpv6, 58);
}

TEST(IanaProtocolNameToNumber, AliasesAndNormalization)
{
    using utils::ip::ianaProtocolNameToNumber;

    // udplite aliases
    auto udplite = ianaProtocolNameToNumber("udplite");
    ASSERT_TRUE(udplite.has_value());
    EXPECT_EQ(*udplite, 136);

    auto udpLiteHyphen = ianaProtocolNameToNumber("udp-lite");
    ASSERT_TRUE(udpLiteHyphen.has_value());
    EXPECT_EQ(*udpLiteHyphen, 136);

    auto udpLiteUnderscore = ianaProtocolNameToNumber("udp_lite");
    ASSERT_TRUE(udpLiteUnderscore.has_value());
    EXPECT_EQ(*udpLiteUnderscore, 136);

    // icmpv6 alias
    auto icmpv6Alias = ianaProtocolNameToNumber("icmpv6");
    ASSERT_TRUE(icmpv6Alias.has_value());
    EXPECT_EQ(*icmpv6Alias, 58);

    // ip-in-ip alias
    auto ipInIpAlias = ianaProtocolNameToNumber("ip-in-ip");
    ASSERT_TRUE(ipInIpAlias.has_value());
    EXPECT_EQ(*ipInIpAlias, 94);
}

TEST(IanaProtocolNameToNumber, UnknownNames)
{
    using utils::ip::ianaProtocolNameToNumber;

    // Not IANA protocol keywords
    EXPECT_FALSE(ianaProtocolNameToNumber("smtp").has_value());
    EXPECT_FALSE(ianaProtocolNameToNumber("http").has_value());

    // Leading/trailing whitespace currently not trimmed in normalize -> should fail
    EXPECT_FALSE(ianaProtocolNameToNumber(" tcp ").has_value());
}

// -------- ianaProtocolNumberToName --------
TEST(IanaProtocolNumberToName, ValidBasics)
{
    using utils::ip::ianaProtocolNumberToName;

    auto tcp = ianaProtocolNumberToName(6);
    ASSERT_TRUE(tcp.has_value());
    EXPECT_EQ(*tcp, "tcp");

    auto ipv6 = ianaProtocolNumberToName(41);
    ASSERT_TRUE(ipv6.has_value());
    EXPECT_EQ(*ipv6, "ipv6");

    auto icmpv6 = ianaProtocolNumberToName(58);
    ASSERT_TRUE(icmpv6.has_value());
    EXPECT_EQ(*icmpv6, "ipv6-icmp");

    auto udplite = ianaProtocolNumberToName(136);
    ASSERT_TRUE(udplite.has_value());
    EXPECT_EQ(*udplite, "udplite");

    auto bitEmu = ianaProtocolNumberToName(147);
    ASSERT_TRUE(bitEmu.has_value());
    EXPECT_EQ(*bitEmu, "bit-emu");
}

TEST(IanaProtocolNumberToName, UnassignedExperimentalReserved)
{
    using utils::ip::ianaProtocolNumberToName;

    // Unassigned examples (according to current table content)
    EXPECT_FALSE(ianaProtocolNumberToName(148).has_value());
    EXPECT_FALSE(ianaProtocolNumberToName(200).has_value());

    // Experimental
    EXPECT_FALSE(ianaProtocolNumberToName(253).has_value());
    EXPECT_FALSE(ianaProtocolNumberToName(254).has_value());

    // Reserved
    EXPECT_FALSE(ianaProtocolNumberToName(255).has_value());
}
