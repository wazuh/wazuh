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
#include "indexer_client/runtimeConfig.hpp"

using indexer_client::Cause;
using indexer_client::KeyValueConfigSource;
using indexer_client::ProcessId;
using indexer_client::RuntimeConfig;

namespace
{
    constexpr const char* INDEXER = R"({"hosts":["https://127.0.0.1:9200"]})";
} // namespace

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

// A line without '=' never fails the parse: it is recorded against its key (the whole line) with its line number,
// and a line with an empty key can never match any key, so it is skipped (the C reader logs and skips both).
TEST(KeyValueConfigSourceTest, MalformedLineRecorded)
{
    const auto noEquals = KeyValueConfigSource::parse("a=1\n# ok\nnot a pair\n", "");
    ASSERT_TRUE(noEquals.ok()) << noEquals.reason;
    EXPECT_EQ(noEquals.value.raw("not a pair"), std::nullopt);
    EXPECT_EQ(noEquals.value.problem("not a pair"), "line 3: 'not a pair' is malformed (expected 'key=value')");
    EXPECT_EQ(noEquals.value.problem("a"), std::nullopt);
    EXPECT_EQ(noEquals.value.keysWithPrefix(""), (std::vector<std::string> {"a", "not a pair"}));

    const auto emptyKey = KeyValueConfigSource::parse("a=1\n= 5\n", "");
    ASSERT_TRUE(emptyKey.ok()) << emptyKey.reason;
    EXPECT_EQ(emptyKey.value.keysWithPrefix(""), (std::vector<std::string> {"a"}));
}

// Another daemon's malformed line never fails this process (the C reader only judges the key it is asked for).
TEST(KeyValueConfigSourceTest, MalformedLineOutsidePrefixIgnored)
{
    const auto source = KeyValueConfigSource::parse("remoted.foo\nwazuh_modules.indexer_client_cpu_threads 4\n"
                                                    "analysisd.indexer_client_cpu_threads=3\n",
                                                    INDEXER);
    ASSERT_TRUE(source.ok()) << source.reason;
    const auto config = RuntimeConfig::from(ProcessId::Analysisd, source.value);
    ASSERT_TRUE(config.ok()) << config.reason;
    EXPECT_EQ(config.value.cpuThreads, 3u);
}

TEST(KeyValueConfigSourceTest, MalformedLineUnderPrefixFails)
{
    const auto source = KeyValueConfigSource::parse(
        "remoted.foo=1\nanalysisd.indexer_client_cpu_threads 4\nanalysisd.indexer_client_cpu_threads=3\n", INDEXER);
    ASSERT_TRUE(source.ok()) << source.reason;
    const auto config = RuntimeConfig::from(ProcessId::Analysisd, source.value);
    EXPECT_EQ(config.cause, Cause::InvalidConfig);
    EXPECT_EQ(config.reason, "line 2: 'analysisd.indexer_client_cpu_threads 4' is malformed (expected 'key=value')");
}

// The C internal-options reader returns on the first matching line: the first occurrence wins and a later duplicate
// is never read (not even validated).
TEST(KeyValueConfigSourceTest, FirstDuplicateWins)
{
    const auto result = KeyValueConfigSource::parse("k=1\nother=x\nk = 2\nk=\n", "");
    ASSERT_TRUE(result.ok()) << result.reason;
    EXPECT_EQ(result.value.raw("k"), "1");
    EXPECT_EQ(result.value.keysWithPrefix("k"), (std::vector<std::string> {"k"}));
    EXPECT_EQ(result.value.problem("k"), std::nullopt) << "the later empty duplicate is never read";
}

// For the C reader a line whose first character is a space is a comment, whatever follows.
TEST(KeyValueConfigSourceTest, LeadingSpaceIsComment)
{
    const auto result = KeyValueConfigSource::parse(" a.b=1\n  not a pair\na.b=2\n\r\n", "");
    ASSERT_TRUE(result.ok()) << result.reason;
    EXPECT_EQ(result.value.raw("a.b"), "2") << "the indented line is a comment, not the first occurrence";
    EXPECT_EQ(result.value.keysWithPrefix(""), (std::vector<std::string> {"a.b"}));
}

// The C reader refuses a key written with no value (an unfinished edit, not an unset option): the key is recorded with
// its line, and no value is ever served for it.
TEST(KeyValueConfigSourceTest, EmptyValueFails)
{
    for (const char* text : {"a=1\nb=\n", "a=1\nb=   \n", "a=1\nb = \t\r\n", "a=1\nb=\nb=2\n"})
    {
        SCOPED_TRACE(text);
        const auto result = KeyValueConfigSource::parse(text, "");
        ASSERT_TRUE(result.ok()) << result.reason;
        EXPECT_EQ(result.value.raw("b"), std::nullopt) << "the first occurrence wins, also when it is the empty one";
        EXPECT_EQ(result.value.problem("b"), "line 2: key 'b' has an empty value");
        EXPECT_EQ(result.value.keysWithPrefix(""), (std::vector<std::string> {"a", "b"}));
    }
}

TEST(KeyValueConfigSourceTest, EmptyValueOutsidePrefixIgnored)
{
    const auto source =
        KeyValueConfigSource::parse("remoted.foo=\nwazuh_modules.indexer_client_cpu_threads=\n", INDEXER);
    ASSERT_TRUE(source.ok()) << source.reason;
    const auto config = RuntimeConfig::from(ProcessId::Analysisd, source.value);
    ASSERT_TRUE(config.ok()) << config.reason;
    EXPECT_EQ(config.value.cpuThreads, RuntimeConfig {}.cpuThreads);
}

TEST(KeyValueConfigSourceTest, EmptyValueUnderPrefixFails)
{
    const auto source = KeyValueConfigSource::parse("# header\nwazuh_modules.indexer_client_cpu_threads = \n", INDEXER);
    ASSERT_TRUE(source.ok()) << source.reason;
    const auto config = RuntimeConfig::from(ProcessId::Modulesd, source.value);
    EXPECT_EQ(config.cause, Cause::InvalidConfig);
    EXPECT_EQ(config.reason, "line 2: key 'wazuh_modules.indexer_client_cpu_threads' has an empty value");
}

// The C reader compares the text before the first '.' with the asked key: a tab-indented line never matches, so it
// is a comment whatever follows (no key, no problem).
TEST(KeyValueConfigSourceTest, TabIndentedIsComment)
{
    const auto result = KeyValueConfigSource::parse(
        "\tanalysisd.indexer_client_cpu_threads=9\n\tnot a pair\n\tb=\nanalysisd.indexer_client_cpu_threads=3\n",
        INDEXER);
    ASSERT_TRUE(result.ok()) << result.reason;
    EXPECT_EQ(result.value.keysWithPrefix(""), (std::vector<std::string> {"analysisd.indexer_client_cpu_threads"}));
    EXPECT_EQ(result.value.raw("analysisd.indexer_client_cpu_threads"), "3")
        << "the tab-indented line is a comment, not the first occurrence";
    const auto config = RuntimeConfig::from(ProcessId::Analysisd, result.value);
    ASSERT_TRUE(config.ok()) << config.reason;
    EXPECT_EQ(config.value.cpuThreads, 3u);
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

// keysWithPrefix merges value keys and recorded problem keys in one sorted list: RuntimeConfig::from() reports the
// first offending key, so the order is part of what an operator sees.
TEST(KeyValueConfigSourceTest, KeysMergedSorted)
{
    const auto source = KeyValueConfigSource::parse("z=1\nb\n", "");
    ASSERT_TRUE(source.ok()) << source.reason;
    EXPECT_EQ(source.value.keysWithPrefix(""), (std::vector<std::string> {"b", "z"}));
}
