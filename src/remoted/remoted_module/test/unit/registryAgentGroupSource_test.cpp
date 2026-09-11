/*
 * Wazuh remoted module - Registry-backed agent group source unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * September 7, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "control/groupSelector.hpp"
#include "control/registryAgentGroupSource.hpp"

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

using namespace remoted::control;

namespace
{
    /// Mirrors what /control/startup leaves behind: groups AND the refresh stamp that says they
    /// came from wazuh-db.
    std::shared_ptr<AgentRegistry> registryWith(AgentId id, std::vector<std::string> groups)
    {
        auto registry = std::make_shared<AgentRegistry>();
        registry->update(id,
                         [groups = std::move(groups)](std::shared_ptr<const AgentEntry>)
                         {
                             auto entry = std::make_shared<AgentEntry>();
                             entry->groups = std::move(groups);
                             entry->groupsRefreshedAtSec = 1000;
                             return entry;
                         });
        return registry;
    }

    /// What /control/shutdown leaves behind for an agent it has never seen: timestamps only, no
    /// groups, and no refresh stamp.
    std::shared_ptr<AgentRegistry> registryWithUnrefreshedEntry(AgentId id)
    {
        auto registry = std::make_shared<AgentRegistry>();
        registry->update(id,
                         [](std::shared_ptr<const AgentEntry>)
                         {
                             auto entry = std::make_shared<AgentEntry>();
                             entry->lastActivitySec = 1000;
                             entry->createdAtSec = 1000;
                             return entry;
                         });
        return registry;
    }
} // namespace

TEST(RegistryAgentGroupSourceTest, ReturnsTheAgentsOwnSelector)
{
    const RegistryAgentGroupSource source {registryWith(1, {"web", "db"})};

    const auto selector = source.expectedSelectorFor("1");

    ASSERT_TRUE(selector.has_value());
    EXPECT_EQ(*selector, "web,db");
}

TEST(RegistryAgentGroupSourceTest, ZeroPaddedAgentIdResolvesToTheSameEntry)
{
    // Agents identify themselves with zero-padded ids ("001"); the registry is keyed by the
    // numeric AgentId, so the two must resolve to one entry.
    const RegistryAgentGroupSource source {registryWith(1, {"web"})};

    EXPECT_EQ(source.expectedSelectorFor("001"), source.expectedSelectorFor("1"));
    EXPECT_EQ(source.expectedSelectorFor("001").value_or(""), "web");
}

TEST(RegistryAgentGroupSourceTest, ReturnsDefaultForAnAgentWithNoGroups)
{
    const RegistryAgentGroupSource source {registryWith(7, {})};

    EXPECT_EQ(source.expectedSelectorFor("7").value_or(""), "default");
}

TEST(RegistryAgentGroupSourceTest, ReturnsNulloptForAnUnknownAgent)
{
    // Fail closed: an agent that never completed /control/startup, or whose entry was evicted,
    // has no established membership to authorize against.
    const RegistryAgentGroupSource source {std::make_shared<AgentRegistry>()};

    EXPECT_FALSE(source.expectedSelectorFor("1").has_value());
}

TEST(RegistryAgentGroupSourceTest, ReturnsNulloptForAMalformedAgentId)
{
    const RegistryAgentGroupSource source {registryWith(1, {"web"})};

    for (const auto* id : {"", "abc", "-1", "1x", " 1", "1 ", "0x1", "99999999999"})
    {
        EXPECT_FALSE(source.expectedSelectorFor(id).has_value()) << "accepted malformed id: '" << id << "'";
    }
}

TEST(RegistryAgentGroupSourceTest, ReturnsNulloptWithoutARegistry)
{
    const RegistryAgentGroupSource source {nullptr};

    EXPECT_FALSE(source.expectedSelectorFor("1").has_value());
}

TEST(RegistryAgentGroupSourceTest, MatchesTheTokenControlHandsOut)
{
    // The anti-drift assertion behind sharing the helpers: whatever /control computes for an
    // entry's groups is what this source answers for that agent.
    const std::vector<std::vector<std::string>> cases {{"default"}, {"web", "db"}, {"db", "web"}, {}, {"a", "b", "c"}};

    AgentId id = 1;
    for (const auto& groups : cases)
    {
        const RegistryAgentGroupSource source {registryWith(id, groups)};

        EXPECT_EQ(source.expectedSelectorFor(std::to_string(id)).value_or(""), makeConfigToken(toGroupsCsv(groups)));
        ++id;
    }
}

TEST(RegistryAgentGroupSourceTest, ReturnsNulloptForAnEntryWhoseGroupsNeverCameFromWazuhDb)
{
    // Regression, found by running the real manager (E3): /control/shutdown creates an entry with
    // no groups for an agent it has never seen, and makeConfigToken("") is "default" -- so without
    // this guard an agent could mint itself an entry with a shutdown and be handed the default
    // group's configuration. An entry is not a membership; only a wazuh-db-backed refresh is.
    const RegistryAgentGroupSource source {registryWithUnrefreshedEntry(1)};

    EXPECT_FALSE(source.expectedSelectorFor("1").has_value());
}

TEST(RegistryAgentGroupSourceTest, StillServesDefaultWhenWazuhDbGenuinelyReturnedNoGroups)
{
    // The other side of the same coin: the refresh DID happen and wdb had nothing, which the
    // manager treats as membership of "default" -- that agent must keep working.
    auto registry = std::make_shared<AgentRegistry>();
    registry->update(1,
                     [](std::shared_ptr<const AgentEntry>)
                     {
                         auto entry = std::make_shared<AgentEntry>();
                         entry->groupsRefreshedAtSec = 1000; // refreshed, and wdb returned nothing
                         return entry;
                     });

    const RegistryAgentGroupSource source {registry};

    EXPECT_EQ(source.expectedSelectorFor("1").value_or(""), "default");
}
