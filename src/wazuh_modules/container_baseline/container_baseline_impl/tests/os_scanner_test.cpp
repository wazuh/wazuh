#include "os_scanner.hpp"

#include <gtest/gtest.h>

using wazuh::container_baseline::ParseOsReleaseLine;

TEST(ParseOsReleaseLine, ParsesBareValue)
{
    std::string key, value;
    ASSERT_TRUE(ParseOsReleaseLine("ID=debian", key, value));
    EXPECT_EQ(key, "ID");
    EXPECT_EQ(value, "debian");
}

TEST(ParseOsReleaseLine, ParsesDoubleQuotedValue)
{
    std::string key, value;
    ASSERT_TRUE(ParseOsReleaseLine("PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"", key, value));
    EXPECT_EQ(key, "PRETTY_NAME");
    EXPECT_EQ(value, "Debian GNU/Linux 12 (bookworm)");
}

TEST(ParseOsReleaseLine, ParsesSingleQuotedValue)
{
    std::string key, value;
    ASSERT_TRUE(ParseOsReleaseLine("NAME='Alpine Linux'", key, value));
    EXPECT_EQ(value, "Alpine Linux");
}

TEST(ParseOsReleaseLine, UnescapesDoubleQuotedValue)
{
    std::string key, value;
    ASSERT_TRUE(ParseOsReleaseLine("NAME=\"a \\\"b\\\" \\\\c\"", key, value));
    EXPECT_EQ(value, "a \"b\" \\c");
}

TEST(ParseOsReleaseLine, ParsesEmptyValue)
{
    std::string key, value;
    ASSERT_TRUE(ParseOsReleaseLine("VERSION_ID=", key, value));
    EXPECT_EQ(key, "VERSION_ID");
    EXPECT_TRUE(value.empty());
}

TEST(ParseOsReleaseLine, SkipsLeadingWhitespace)
{
    std::string key, value;
    ASSERT_TRUE(ParseOsReleaseLine("  ID=alpine", key, value));
    EXPECT_EQ(value, "alpine");
}

TEST(ParseOsReleaseLine, RejectsBlankLine)
{
    std::string key, value;
    EXPECT_FALSE(ParseOsReleaseLine("", key, value));
    EXPECT_FALSE(ParseOsReleaseLine("   ", key, value));
}

TEST(ParseOsReleaseLine, RejectsComment)
{
    std::string key, value;
    EXPECT_FALSE(ParseOsReleaseLine("# comment", key, value));
}

TEST(ParseOsReleaseLine, RejectsLineWithoutEquals)
{
    std::string key, value;
    EXPECT_FALSE(ParseOsReleaseLine("NOEQUALS", key, value));
    EXPECT_FALSE(ParseOsReleaseLine("=value", key, value));
}
