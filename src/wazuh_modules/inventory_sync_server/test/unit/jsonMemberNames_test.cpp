/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "common/jsonMemberNames.hpp"

#include <gtest/gtest.h>

#include <string>

using invsync::common::dottedNameReachesWazuh;
using invsync::common::hasDottedMemberName;

namespace
{
    bool dotted(const std::string& text)
    {
        return hasDottedMemberName(nlohmann::json::parse(text));
    }

    bool reachesWazuh(const std::string& text)
    {
        return dottedNameReachesWazuh(nlohmann::json::parse(text));
    }
} // namespace

TEST(JsonMemberNamesTest, EverySpellingThatExpandsIntoWazuhIsFound)
{
    for (const auto* text : {R"({"wazuh.agent.id":"002"})",
                             R"({"wazuh":{"agent.id":"002"}})",
                             R"({"wazuh.agent":{"id":"002"}})",
                             R"({"wazuh":{"cluster.name":"other"}})",
                             R"({"wazuh.":"x"})",
                             R"({"wazuh":{"agent":{"host":{"os":{"x.y":1}}}}})",
                             R"({"wazuh":{"agent":{"groups":[{"a.b":1}]}}})",
                             "{\"wazuh\\u002eagent\\u002eid\":\"002\"}",
                             "{\"wazuh\":{\"x\\u0000.y\":1}}"})
    {
        EXPECT_TRUE(reachesWazuh(text)) << "text: " << text;
    }
}

TEST(JsonMemberNamesTest, DottedNamesOutsideWazuhAreLeftAlone)
{
    // A dotted name expands only below the object that holds it: none of these can land on wazuh.*.
    for (const auto* text : {R"({"package":{"name":"vim","x.y":1}})",
                             R"({"package":{"list":[{"a.b":1}]}})",
                             R"({"x.y":1})",
                             R"({"wazuhx.agent.id":"002"})",
                             R"({"package":{"wazuh.agent.id":"002"}})",
                             R"({"wazuh":{"agent":{"id":"001"}},"package":{"name":"vim"}})",
                             R"([{"wazuh.agent.id":"002"}])",
                             "{\"wazuh\\u0000x\":{\"a.b\":1}}",
                             "42"})
    {
        EXPECT_FALSE(reachesWazuh(text)) << "text: " << text;
    }
}

TEST(JsonMemberNamesTest, NestedDocumentWithoutDottedNamesPasses)
{
    EXPECT_FALSE(dotted(R"({"package":{"name":"curl","version":"7.81.0"},"checksum":{"hash":{"sha1":"ab"}}})"));
}

TEST(JsonMemberNamesTest, ScalarsArraysAndEmptyContainersPass)
{
    for (const auto* text : {"42", R"("a.b")", "null", "[]", "{}", R"([1,"x.y",{"a":[]}])"})
    {
        EXPECT_FALSE(dotted(text)) << "text: " << text;
    }
}

TEST(JsonMemberNamesTest, DotsInValuesPass)
{
    // Only names are expanded by the indexer; dotted values (versions, paths, hostnames) are data.
    EXPECT_FALSE(dotted(R"({"file":{"path":"/etc/a.conf"},"host":{"hostname":"web.example.com"}})"));
}

TEST(JsonMemberNamesTest, DottedNameAtTheRootIsFound)
{
    EXPECT_TRUE(dotted(R"({"wazuh.agent.id":"002"})"));
}

TEST(JsonMemberNamesTest, DottedNameAtEveryLevelOfTheIdentityPathIsFound)
{
    EXPECT_TRUE(dotted(R"({"wazuh":{"agent.id":"002"}})"));
    EXPECT_TRUE(dotted(R"({"wazuh.agent":{"id":"002"}})"));
    EXPECT_TRUE(dotted(R"({"wazuh":{"cluster.name":"other"}})"));
}

TEST(JsonMemberNamesTest, DottedNameDeepOrInsideAnArrayIsFound)
{
    EXPECT_TRUE(dotted(R"({"a":{"b":{"c":{"d.e":1}}}})"));
    EXPECT_TRUE(dotted(R"({"a":[1,{"b":[{"c.d":1}]}]})"));
}

TEST(JsonMemberNamesTest, EscapedDotIsFound)
{
    // "." decodes to '.': the parsed name is what the indexer sees.
    EXPECT_TRUE(dotted("{\"wazuh\\u002eagent\\u002eid\":\"002\"}"));
}

TEST(JsonMemberNamesTest, DotAfterAnEmbeddedNulIsFound)
{
    EXPECT_TRUE(dotted("{\"x\\u0000.y\":1}"));
}

TEST(JsonMemberNamesTest, DeepNestingDoesNotRecurse)
{
    // Deeper than the module's nesting cap: the walk itself must not depend on it.
    constexpr std::size_t kDepth = 10000;
    const std::string text = std::string(kDepth, '[') + R"({"a.b":1})" + std::string(kDepth, ']');
    const auto document = nlohmann::json::parse(text);
    EXPECT_TRUE(hasDottedMemberName(document));
}
