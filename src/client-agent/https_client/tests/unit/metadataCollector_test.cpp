/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "metadataCollector.hpp"

#include "external/nlohmann/json.hpp"

#include <gtest/gtest.h>

#include <cstdio>
#include <string>

namespace
{
    /// The bridge's worst case: 128 groups of 255 bytes, written with
    /// snprintf like bridge_on_collect_stateless_host() does.
    void writeMaxGroups(char* out, size_t cap, void* /*userData*/)
    {
        nlohmann::json agent;
        agent["groups"] = nlohmann::json::array();

        for (int i = 0; i < 128; ++i)
        {
            agent["groups"].push_back(std::string(252, 'g') + std::to_string(100 + i));
        }

        agent["host"]["hostname"] = std::string(255, 'h');
        nlohmann::json root;
        root["agent"] = std::move(agent);
        std::snprintf(out, cap, "%s", root.dump().c_str());
    }

    void writeCapacity(char* out, size_t cap, void* userData)
    {
        *static_cast<size_t*>(userData) = cap;
        std::snprintf(out, cap, "%s", "{}");
    }
} // namespace

TEST(MetadataCollectorTest, NullCallbackYieldsEmptyString)
{
    const auto collect = makeMetadataCollector(nullptr, nullptr, AGENT_METADATA_JSON_MAX_BYTES);
    EXPECT_EQ("", collect());
}

TEST(MetadataCollectorTest, CallbackSeesTheRequestedCapacity)
{
    size_t seen {0};
    const auto collect = makeMetadataCollector(writeCapacity, &seen, AGENT_METADATA_JSON_MAX_BYTES);
    EXPECT_EQ("{}", collect());
    EXPECT_EQ(AGENT_METADATA_JSON_MAX_BYTES, seen);
}

TEST(MetadataCollectorTest, MaximumGroupListIsNotTruncated)
{
    const auto collected = makeMetadataCollector(writeMaxGroups, nullptr, AGENT_METADATA_JSON_MAX_BYTES)();

    ASSERT_GT(collected.size(), HOST_METADATA_JSON_MAX_BYTES);
    const auto parsed = nlohmann::json::parse(collected, nullptr, false);
    ASSERT_FALSE(parsed.is_discarded());
    EXPECT_EQ(128U, parsed.at("agent").at("groups").size());
}

TEST(MetadataCollectorTest, OutputLongerThanTheCapacityIsCutButTerminated)
{
    const auto collected = makeMetadataCollector(writeMaxGroups, nullptr, HOST_METADATA_JSON_MAX_BYTES)();

    EXPECT_EQ(HOST_METADATA_JSON_MAX_BYTES - 1, collected.size());
    EXPECT_TRUE(nlohmann::json::parse(collected, nullptr, false).is_discarded());
}
