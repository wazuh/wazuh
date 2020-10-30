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
    const auto ret_val { Utils::replaceAll(string_base, "hello_", "bye_") };
    EXPECT_EQ(string_base, "bye_world");
    EXPECT_TRUE(ret_val);
}

TEST_F(StringUtilsTest, CheckNotReplacement) 
{
    std::string string_base {"hello_world" };
    const auto ret_val { Utils::replaceAll(string_base, "nothing_", "bye_") };
    EXPECT_EQ(string_base, "hello_world");
    EXPECT_FALSE(ret_val);
}

TEST_F(StringUtilsTest, SplitEmptyString) 
{
    auto split_text_vector { Utils::split("", '.') };
    EXPECT_EQ(0ull, split_text_vector.size());
}

TEST_F(StringUtilsTest, SplitDelimiterNoCoincidence) 
{
    const auto split_text_vector { Utils::split("hello_world", '.') };
    EXPECT_EQ(1ull, split_text_vector.size());
}

TEST_F(StringUtilsTest, SplitDelimiterCoincidence) 
{
    const auto split_text_vector { Utils::split("hello.world", '.') };
    EXPECT_EQ(2ull, split_text_vector.size());
    EXPECT_EQ(split_text_vector[0], "hello");
    EXPECT_EQ(split_text_vector[1], "world");
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
    const auto ret_val { Utils::replaceFirst(string_base, "bye", "hello") };
    EXPECT_EQ(string_base, "hello_bye");
    EXPECT_TRUE(ret_val);
}

TEST_F(StringUtilsTest, CheckNotFirstReplacement) 
{
    std::string string_base {"hello_world" };
    const auto ret_val { Utils::replaceFirst(string_base, "nothing_", "bye_") };
    EXPECT_EQ(string_base, "hello_world");
    EXPECT_FALSE(ret_val);
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
}

TEST_F(StringUtilsTest, LeftTrim)
{
    EXPECT_EQ("Hello", Utils::leftTrim("Hello"));
    EXPECT_EQ("Hello", Utils::leftTrim(" Hello"));
    EXPECT_EQ("Hello", Utils::leftTrim(" Hello"));
    EXPECT_EQ("Hello", Utils::leftTrim("          Hello"));
    EXPECT_EQ("Hello\t ", Utils::leftTrim(" \tHello\t ", " \t"));
    EXPECT_EQ("Hello\t\n ", Utils::leftTrim(" \t\nHello\t\n ", " \t\n"));
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
    EXPECT_FALSE(Utils::startsWith(item3, start));
    EXPECT_FALSE(Utils::startsWith(item4, start));
}

TEST_F(StringUtilsTest, SplitDelimiterNullTerminated)
{
    const char buffer[]{'h','e','l','l','o','\0','w','o','r','l','d','\0','\0'};
    const auto tokens{Utils::splitNullTerminatedStrings(buffer)};
    EXPECT_EQ(2ull, tokens.size());
    EXPECT_EQ(tokens[0], "hello");
    EXPECT_EQ(tokens[1], "world");
}