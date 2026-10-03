/*
 * Wazuh indexer client
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "indexer_client/keyValueConfigSource.hpp"

using indexer_client::Cause;
using indexer_client::KeyValueConfigSource;

TEST(KeyValueConfigSourceTest, ParsesAndTrims)
{
    const auto result = KeyValueConfigSource::parse("a.b=1\nc.d  =  two words \t\r\nf= =x\n", R"({"hosts":["h"]})");
    ASSERT_TRUE(result.ok()) << result.reason;
    const auto& source = result.value;
    EXPECT_EQ(source.raw("a.b"), "1");
    EXPECT_EQ(source.raw("c.d"), "two words");
    EXPECT_EQ(source.raw("f"), "=x") << "only the first '=' separates key and value";
    EXPECT_EQ(source.raw("missing"), std::nullopt);
    EXPECT_EQ(source.indexerSectionJson(), R"({"hosts":["h"]})");
}

TEST(KeyValueConfigSourceTest, CommentsAndBlankLines)
{
    const auto result = KeyValueConfigSource::parse("# header\n\n   \n  # indented comment = not a key\nk=v\n#k=w", "");
    ASSERT_TRUE(result.ok()) << result.reason;
    EXPECT_EQ(result.value.raw("k"), "v");
    EXPECT_EQ(result.value.keysWithPrefix(""), (std::vector<std::string> {"k"}));
}

TEST(KeyValueConfigSourceTest, MalformedLineFails)
{
    const auto noEquals = KeyValueConfigSource::parse("a=1\n# ok\nnot a pair\n", "");
    EXPECT_FALSE(noEquals.ok());
    EXPECT_EQ(noEquals.cause, Cause::InvalidConfig);
    EXPECT_NE(noEquals.reason.find("line 3"), std::string::npos) << noEquals.reason;

    const auto emptyKey = KeyValueConfigSource::parse("a=1\n= 5\n", "");
    EXPECT_FALSE(emptyKey.ok());
    EXPECT_EQ(emptyKey.cause, Cause::InvalidConfig);
    EXPECT_NE(emptyKey.reason.find("line 2"), std::string::npos) << emptyKey.reason;
}

// The C internal-options reader returns on the first matching line: the first occurrence wins and a later duplicate
// is never read (not even validated).
TEST(KeyValueConfigSourceTest, FirstDuplicateWins)
{
    const auto result = KeyValueConfigSource::parse("k=1\nother=x\nk = 2\nk=\n", "");
    ASSERT_TRUE(result.ok()) << result.reason;
    EXPECT_EQ(result.value.raw("k"), "1");
    EXPECT_EQ(result.value.keysWithPrefix("k"), (std::vector<std::string> {"k"}));
}

// For the C reader a line whose first character is a space is a comment, whatever follows.
TEST(KeyValueConfigSourceTest, LeadingSpaceIsComment)
{
    const auto result = KeyValueConfigSource::parse(" a.b=1\n  not a pair\na.b=2\n\r\n", "");
    ASSERT_TRUE(result.ok()) << result.reason;
    EXPECT_EQ(result.value.raw("a.b"), "2") << "the indented line is a comment, not the first occurrence";
    EXPECT_EQ(result.value.keysWithPrefix(""), (std::vector<std::string> {"a.b"}));
}

// The C reader refuses a key written with no value (an unfinished edit, not an unset option).
TEST(KeyValueConfigSourceTest, EmptyValueFails)
{
    for (const char* text : {"a=1\nb=\n", "a=1\nb=   \n", "a=1\nb = \t\r\n"})
    {
        SCOPED_TRACE(text);
        const auto result = KeyValueConfigSource::parse(text, "");
        EXPECT_FALSE(result.ok());
        EXPECT_EQ(result.cause, Cause::InvalidConfig);
        EXPECT_NE(result.reason.find("line 2"), std::string::npos) << result.reason;
        EXPECT_NE(result.reason.find("'b'"), std::string::npos) << result.reason;
    }
}

TEST(KeyValueConfigSourceTest, KeysWithPrefix)
{
    const auto result = KeyValueConfigSource::parse("analysisd.indexer_client_cpu_threads=2\n"
                                                    "analysisd.indexer_client_bogus=1\n"
                                                    "analysisd.other=3\n"
                                                    "wazuh_modules.indexer_client_cpu_threads=4\n"
                                                    "analysisd.indexer_clien=5\n",
                                                    "");
    ASSERT_TRUE(result.ok()) << result.reason;
    EXPECT_EQ(result.value.keysWithPrefix("analysisd.indexer_client_"),
              (std::vector<std::string> {"analysisd.indexer_client_bogus", "analysisd.indexer_client_cpu_threads"}));
    EXPECT_EQ(result.value.keysWithPrefix("wazuh_modules.indexer_client_"),
              (std::vector<std::string> {"wazuh_modules.indexer_client_cpu_threads"}));
    EXPECT_TRUE(result.value.keysWithPrefix("remoted.").empty());
}
