/*
 * Wazuh shared modules utils
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 14, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "stringHelper_test.h"
#include "stringHelper.h"

void StringUtilsTest::SetUp() {};

void StringUtilsTest::TearDown() {};

TEST_F(StringUtilsTest, CheckReplacement)
{
    std::string string_base { "hello_world" };
    const auto retVal { Utils::replaceAll(string_base, "hello_", "bye_") };
    EXPECT_EQ(string_base, "bye_world");
    EXPECT_TRUE(retVal);
}

TEST_F(StringUtilsTest, CheckNotReplacement)
{
    std::string string_base {"hello_world" };
    const auto retVal { Utils::replaceAll(string_base, "nothing_", "bye_") };
    EXPECT_EQ(string_base, "hello_world");
    EXPECT_FALSE(retVal);
}

TEST_F(StringUtilsTest, SplitEmptyString)
{
    auto splitTextVector { Utils::split("", '.') };
    EXPECT_EQ(0ull, splitTextVector.size());
}

TEST_F(StringUtilsTest, SplitDelimiterNoCoincidence)
{
    const auto splitTextVector { Utils::split("hello_world", '.') };
    EXPECT_EQ(1ull, splitTextVector.size());
}

TEST_F(StringUtilsTest, SplitDelimiterCoincidence)
{
    const auto splitTextVector { Utils::split("hello.world", '.') };
    EXPECT_EQ(2ull, splitTextVector.size());
    EXPECT_EQ(splitTextVector[0], "hello");
    EXPECT_EQ(splitTextVector[1], "world");
}

TEST_F(StringUtilsTest, SplitIndex)
{
    const auto splitTextVector { Utils::splitIndex("hello.world", '.', 0) };
    EXPECT_EQ(5ull, splitTextVector.size());
    EXPECT_EQ(splitTextVector, "hello");
}

TEST_F(StringUtilsTest, AsciiToHexString)
{
    const std::vector<unsigned char> data{0x2d, 0x53, 0x3b, 0x9d, 0x9f, 0x0f, 0x06, 0xef, 0x4e, 0x3c, 0x23, 0xfd, 0x49, 0x6c, 0xfe, 0xb2, 0x78, 0x0e, 0xda, 0x7f};
    const std::string expected { "2d533b9d9f0f06ef4e3c23fd496cfeb2780eda7f" };
    const auto result {Utils::asciiToHex(data)};
    EXPECT_EQ(expected, result);
}

TEST_F(StringUtilsTest, CheckFirstReplacement)
{
    std::string string_base { "bye_bye" };
    const auto retVal { Utils::replaceFirst(string_base, "bye", "hello") };
    EXPECT_EQ(string_base, "hello_bye");
    EXPECT_TRUE(retVal);
}

TEST_F(StringUtilsTest, CheckNotFirstReplacement)
{
    std::string string_base {"hello_world" };
    const auto retVal { Utils::replaceFirst(string_base, "nothing_", "bye_") };
    EXPECT_EQ(string_base, "hello_world");
    EXPECT_FALSE(retVal);
}

TEST_F(StringUtilsTest, RightTrim)
{
    EXPECT_EQ("Hello", Utils::rightTrim("Hello"));
    EXPECT_EQ("Hello", Utils::rightTrim("Hello "));
    EXPECT_EQ("Hello", Utils::rightTrim("Hello  "));
    EXPECT_EQ("Hello", Utils::rightTrim("Hello            "));
    EXPECT_EQ(" Hello", Utils::rightTrim(" Hello"));
    EXPECT_EQ("\tHello", Utils::rightTrim("\tHello\t", "\t"));
    EXPECT_EQ(" \t\nHello", Utils::rightTrim(" \t\nHello \t\n ", "\t\n "));
    EXPECT_EQ(" \t\nHello \t\n", Utils::rightTrim(" \t\nHello \t\n "));
    EXPECT_EQ("", Utils::rightTrim(""));
}

TEST_F(StringUtilsTest, LeftTrim)
{
    EXPECT_EQ("Hello", Utils::leftTrim("Hello"));
    EXPECT_EQ("Hello", Utils::leftTrim(" Hello"));
    EXPECT_EQ("Hello", Utils::leftTrim(" Hello"));
    EXPECT_EQ("Hello", Utils::leftTrim("          Hello"));
    EXPECT_EQ("Hello\t ", Utils::leftTrim(" \tHello\t ", " \t"));
    EXPECT_EQ("Hello\t\n ", Utils::leftTrim(" \t\nHello\t\n ", " \t\n"));
    EXPECT_EQ("\t\nHello\t\n ", Utils::leftTrim(" \t\nHello\t\n "));
    EXPECT_EQ("", Utils::leftTrim(""));
}

TEST_F(StringUtilsTest, Trim)
{
    EXPECT_EQ("Hello", Utils::trim("Hello"));
    EXPECT_EQ("Hello", Utils::trim(" Hello "));
    EXPECT_EQ("Hello", Utils::trim(" Hello "));
    EXPECT_EQ("Hello", Utils::trim("          Hello      "));
    EXPECT_EQ("Hello", Utils::trim(" \tHello\t ", " \t"));
    EXPECT_EQ("Hello", Utils::trim(" \t\nHello\t\n ", " \t\n"));
}

TEST_F(StringUtilsTest, ToUpper)
{
    EXPECT_EQ("", Utils::toUpperCase(""));
    EXPECT_EQ("HELLO WORLD", Utils::toUpperCase("HeLlO WoRlD"));
    EXPECT_EQ("123", Utils::toUpperCase("123"));
}

TEST_F(StringUtilsTest, StartsWith)
{
    const std::string start{"Package_"};
    const std::string item1{"Package_6_for_KB4565554~31bf3856ad364e35~amd64~~18362.957.1.3"};
    const std::string item2{"Package_5_for_KB4569073~31bf3856ad364e35~amd64~~18362.1012.1.1"};
    const std::string item3{"Microsoft-Windows-IIS-WebServer-AddOn-Package~31bf3856ad364e35~amd64~~10.0.18362.815"};
    const std::string item4{"Microsoft-Windows-HyperV-OptionalFeature-VirtualMachinePlatform-Package_31bf3856ad364e35~amd64~~10.0.18362.1139.mum"};
    EXPECT_TRUE(Utils::startsWith(start, start));
    EXPECT_TRUE(Utils::startsWith(item1, start));
    EXPECT_TRUE(Utils::startsWith(item2, start));
    EXPECT_FALSE(Utils::startsWith("", start));
    EXPECT_FALSE(Utils::startsWith(item3, start));
    EXPECT_FALSE(Utils::startsWith(item4, start));
}

TEST_F(StringUtilsTest, EndsWith)
{
    const std::string end{"_package"};
    const std::string item1{"KB4565554~31bf3856ad364e35~amd64~~18362.957.1.3_package"};
    const std::string item2{"KB4569073~31bf3856ad364e35~amd64~~18362.1012.1.1_package"};
    const std::string item3{"Microsoft-Windows-IIS-WebServer-AddOn-Package~31bf3856ad364e35~amd64~~10.0.18362.815"};
    const std::string item4{"Microsoft-Windows-HyperV-OptionalFeature-VirtualMachinePlatform-Package_31bf3856ad364e35~amd64~~10.0.18362.1139.mum"};
    EXPECT_TRUE(Utils::endsWith(end, end));
    EXPECT_TRUE(Utils::endsWith(item1, end));
    EXPECT_TRUE(Utils::endsWith(item2, end));
    EXPECT_FALSE(Utils::endsWith("", end));
    EXPECT_FALSE(Utils::endsWith(item3, end));
    EXPECT_FALSE(Utils::endsWith(item4, end));
}

TEST_F(StringUtilsTest, SplitDelimiterNullTerminated)
{
    const char buffer[]{'h','e','l','l','o','\0','w','o','r','l','d','\0','\0'};
    const auto tokens{Utils::splitNullTerminatedStrings(buffer)};
    EXPECT_EQ(2ull, tokens.size());
    EXPECT_EQ(tokens[0], "hello");
    EXPECT_EQ(tokens[1], "world");
}

TEST_F(StringUtilsTest, CheckMultiReplacement)
{
    std::string string_base { "hello         world" };
    const auto retVal { Utils::replaceAll(string_base, "  ", " ") };
    EXPECT_EQ(string_base, "hello world");
    EXPECT_TRUE(retVal);
}

TEST_F(StringUtilsTest, substrOnFirstOccurrenceCorrect)
{
    EXPECT_EQ(Utils::substrOnFirstOccurrence("hello         world", "         "), "hello");
}

TEST_F(StringUtilsTest, substrOnFirstOccurrenceCorrectEmpty)
{
    EXPECT_EQ(Utils::substrOnFirstOccurrence("", " "), "");
}

TEST_F(StringUtilsTest, substrOnFirstOccurrenceNoOccurrences)
{
    EXPECT_EQ(Utils::substrOnFirstOccurrence("hello         world", "bye"), "hello         world");
}

TEST_F(StringUtilsTest, substrOnFirstOccurrenceCorrectEndText)
{
    EXPECT_EQ(Utils::substrOnFirstOccurrence("hello         world", "world"), "hello         ");
}

TEST_F(StringUtilsTest, substrOnFirstOccurrenceCorrectFirstText)
{
    EXPECT_EQ(Utils::substrOnFirstOccurrence("hello         world", "hello"), "");
}

TEST_F(StringUtilsTest, substrOnFirstOccurrenceCorrectEscapeCharacter)
{
    EXPECT_EQ(Utils::substrOnFirstOccurrence("hello\nworld", "\n"), "hello");
}

TEST_F(StringUtilsTest, substrOnFirstOccurrenceCorrectEscapeCharacterEmptyResult)
{
    EXPECT_EQ(Utils::substrOnFirstOccurrence("\n", "\n"), "");
}