/*
 * Wazuh remoted module - Group configuration path unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "control/groupConfigPath.hpp"

#include <gtest/gtest.h>

#include <string>
#include <utility>
#include <vector>

using namespace remoted::control;

namespace
{
    const std::string kShared {"/shared"};
    const std::string kMulti {"/multi"};

    std::string resolve(std::vector<std::string> groups)
    {
        return resolveMergedConfigPath(std::move(groups), kShared, kMulti);
    }
} // namespace

TEST(GroupConfigPathTest, SingleGroupUsesSharedRoot)
{
    EXPECT_EQ(resolve({"default"}), "/shared/default/merged.mg");
}

TEST(GroupConfigPathTest, MultiGroupMatchesWdbLiterals)
{
    // The first 32 hex characters of sha256 over the CSV, as wazuh-db's group_hash computes them.
    EXPECT_EQ(resolve({"alpha", "beta"}), "/multi/76ba5a3bc22ef0b439168b9a5c771ceb/merged.mg");
    EXPECT_EQ(resolve({"web-servers", "databases"}), "/multi/97d668590155b0b50fb09c254d636adc/merged.mg");
    EXPECT_EQ(resolve({"default", "web-servers"}), "/multi/b9d4f26372114529987a9805a4049313/merged.mg");
}

TEST(GroupConfigPathTest, OrderIsPartOfTheIdentity)
{
    const auto ab = resolve({"a", "b"});
    const auto ba = resolve({"b", "a"});

    ASSERT_FALSE(ab.empty());
    ASSERT_FALSE(ba.empty());
    EXPECT_NE(ab, ba);
}

TEST(GroupConfigPathTest, RejectsNamesOutsideTheGrammar)
{
    const std::vector<std::string> names {"a:b",
                                          "g1;rm",
                                          "x=y",
                                          "p(q)",
                                          "n+m",
                                          "a!b",
                                          "c@d",
                                          "caf\xc3\xa9",
                                          std::string(256, 'g'),
                                          ".",
                                          "..",
                                          "../etc",
                                          "a/b",
                                          "a\\b",
                                          std::string("a\0b", 3),
                                          "%2e%2e%2f"};

    for (const auto& name : names)
    {
        EXPECT_EQ(resolve({name}), "") << name;
    }
}

TEST(GroupConfigPathTest, AcceptsTheStrictGrammarBoundaries)
{
    for (const auto& name : {std::string {"AZaz09._-"},
                             std::string {"Az0-9._"},
                             std::string {"g-1"},
                             std::string {"g_2"},
                             std::string {"g.3"},
                             std::string(255, 'g')})
    {
        EXPECT_FALSE(resolve({name}).empty()) << name;
    }
}

TEST(GroupConfigPathTest, AnyBadTokenInAMultigroupRejectsAll)
{
    EXPECT_EQ(resolve({"good", ".."}), "");
    EXPECT_EQ(resolve({"good", "../etc"}), "");
}

TEST(GroupConfigPathTest, EmptyEntryInAListIsRejected)
{
    EXPECT_EQ(resolve({"g1", "", "g2"}), "");
}

TEST(GroupConfigPathTest, EmptyListIsDefault)
{
    EXPECT_EQ(resolve({}), "/shared/default/merged.mg");
}

TEST(GroupConfigPathTest, AcceptsTheFrameworkGroupGrammar)
{
    EXPECT_TRUE(isValidGroupName("default"));
    EXPECT_TRUE(isValidGroupName("web-servers"));
    EXPECT_TRUE(isValidGroupName("centos_8.1"));
    EXPECT_FALSE(isValidGroupName("a:b;c=d+e!f@g(h)"));
    EXPECT_TRUE(isValidGroupName(std::string(255, 'g')));
}

TEST(GroupConfigPathTest, RejectsPathAndSeparatorCharacters)
{
    EXPECT_FALSE(isValidGroupName(""));
    EXPECT_FALSE(isValidGroupName("."));
    EXPECT_FALSE(isValidGroupName(".."));
    EXPECT_FALSE(isValidGroupName("../../etc/shadow"));
    EXPECT_FALSE(isValidGroupName("a/b"));
    EXPECT_FALSE(isValidGroupName("a\\b"));
    EXPECT_FALSE(isValidGroupName(std::string("a\0b", 3)));
    EXPECT_FALSE(isValidGroupName("%2e%2e%2f"));
    EXPECT_FALSE(isValidGroupName("caf\xc3\xa9"));
    EXPECT_FALSE(isValidGroupName(std::string(256, 'g')));
}

TEST(GroupConfigPathTest, RejectsACommaAsASingleGroupName)
{
    // A single group name never contains a comma; the CSV form is a selector, checked separately.
    EXPECT_FALSE(isValidGroupName("default,web-servers"));
}
