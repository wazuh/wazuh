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

#include "control/controlConfig.hpp"
#include "control/groupSelector.hpp"
#include "control/metrics.hpp"
#include "control/registryAgentGroupSource.hpp"
#include "control/registryLookup.hpp"
#include "fakeUdsServer.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <ctime>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <vector>

using namespace remoted::control;
using remoted::endpoints::GroupVerdict;
using remoted::endpoints::GroupVerdictKind;
using namespace std::chrono_literals;

namespace
{
    constexpr uint32_t kFreshnessSec = 60;

    uint64_t nowSec()
    {
        return static_cast<uint64_t>(std::time(nullptr));
    }

    /// Mirrors what /control/startup leaves behind: groups AND the refresh stamp that says they
    /// came from wazuh-db -- `ageSec` ago (0: fresh).
    std::shared_ptr<AgentRegistry> registryWith(AgentId id, std::vector<std::string> groups, uint64_t ageSec = 0)
    {
        auto registry = std::make_shared<AgentRegistry>();
        registry->update(id,
                         [groups = std::move(groups), ageSec](std::shared_ptr<const AgentEntry>)
                         {
                             auto entry = std::make_shared<AgentEntry>();
                             entry->groups = std::move(groups);
                             entry->groupsRefreshedAtSec = nowSec() - ageSec;
                             return entry;
                         });
        return registry;
    }

    /// What /control/shutdown leaves behind for an agent it has never seen (timestamps only), and
    /// what an invalidation leaves (the groups kept, never established).
    std::shared_ptr<AgentRegistry> registryWithUnestablishedEntry(AgentId id, std::vector<std::string> groups = {})
    {
        auto registry = std::make_shared<AgentRegistry>();
        registry->update(id,
                         [groups = std::move(groups)](std::shared_ptr<const AgentEntry>)
                         {
                             auto entry = std::make_shared<AgentEntry>();
                             entry->groups = groups;
                             entry->lastActivitySec = 1000;
                             entry->createdAtSec = 1000;
                             return entry;
                         });
        return registry;
    }

    /// For the answers the source gives inline: the verdict must be there before resolveSelector() returns.
    GroupVerdict resolveInline(const RegistryAgentGroupSource& source, const std::string& agentId)
    {
        std::optional<GroupVerdict> verdict;
        source.resolveSelector(agentId, [&](GroupVerdict v) { verdict = std::move(v); });
        EXPECT_TRUE(verdict.has_value()) << "expected an inline verdict for agent '" << agentId << "'";
        return verdict.value_or(GroupVerdict {});
    }

    /// The fallback path: the real RegistryLookup against a fake wazuh-db answering select-agent-group.
    struct LookupFixture
    {
        std::string path = remoted::test::makeUniqueSocketPath("rags_wdb");
        std::shared_ptr<std::atomic<int>> selects = std::make_shared<std::atomic<int>>(0);
        std::unique_ptr<remoted::test::FakeUdsServer> server;
        ControlMetrics metrics {};
        Config cfg;
        std::shared_ptr<RegistryLookup> lookup;

        /// @param onSelect Runs when a select reaches the fake, before it answers: the query has been
        ///        issued (its ticket taken), so a registry write here lands while it is in flight.
        LookupFixture(const std::shared_ptr<AgentRegistry>& registry,
                      std::string answer,
                      uint32_t deadlineMs = 2000,
                      std::function<void()> onSelect = {})
        {
            server = std::make_unique<remoted::test::FakeUdsServer>(
                path,
                [selects = selects, answer = std::move(answer), onSelect = std::move(onSelect)](
                    const std::string& request)
                {
                    if (request.rfind("global select-agent-group", 0) == 0)
                    {
                        ++*selects;
                        if (onSelect)
                        {
                            onSelect();
                        }
                        return answer;
                    }
                    return std::string("ok");
                });
            cfg.wdbSocketPath = path;
            cfg.wdbRoundtripDeadlineMs = deadlineMs;
            cfg.wdbRequestDeadlineMs = deadlineMs;
            lookup = std::make_shared<RegistryLookup>(registry, cfg, metrics);
        }

        ~LookupFixture()
        {
            lookup->stop();
            lookup.reset();
            server.reset();
        }
    };

    GroupVerdict resolveAndWait(const RegistryAgentGroupSource& source, const std::string& agentId)
    {
        auto promise = std::make_shared<std::promise<GroupVerdict>>();
        auto future = promise->get_future();
        source.resolveSelector(agentId, [promise](GroupVerdict v) { promise->set_value(std::move(v)); });
        if (future.wait_for(5s) != std::future_status::ready)
        {
            ADD_FAILURE() << "no verdict for agent '" << agentId << "'";
            return GroupVerdict {};
        }
        return future.get();
    }
} // namespace

// -----------------------------------------------------------------------------
// Answered from the registry, inline
// -----------------------------------------------------------------------------

TEST(RegistryAgentGroupSourceTest, ReturnsTheAgentsOwnSelector)
{
    const RegistryAgentGroupSource source {registryWith(1, {"web", "db"}), nullptr, kFreshnessSec};

    const auto verdict = resolveInline(source, "1");

    EXPECT_EQ(verdict.kind, GroupVerdictKind::Selector);
    EXPECT_EQ(verdict.selector, "web,db");
}

TEST(RegistryAgentGroupSourceTest, ZeroPaddedAgentIdResolvesToTheSameEntry)
{
    // Agents identify themselves with zero-padded ids ("001"); the registry is keyed by the
    // numeric AgentId, so the two must resolve to one entry.
    const RegistryAgentGroupSource source {registryWith(1, {"web"}), nullptr, kFreshnessSec};

    EXPECT_EQ(resolveInline(source, "001").selector, resolveInline(source, "1").selector);
    EXPECT_EQ(resolveInline(source, "001").selector, "web");
}

TEST(RegistryAgentGroupSourceTest, ReturnsDefaultForAnAgentWithNoGroups)
{
    const RegistryAgentGroupSource source {registryWith(7, {}), nullptr, kFreshnessSec};

    const auto verdict = resolveInline(source, "7");

    EXPECT_EQ(verdict.kind, GroupVerdictKind::Selector);
    EXPECT_EQ(verdict.selector, "default");
}

TEST(RegistryAgentGroupSourceTest, DeniesAnUnknownAgentWhenNoLookupIsWired)
{
    // Fail closed: with nothing to ask, an agent the registry cannot vouch for is not served.
    const RegistryAgentGroupSource source {std::make_shared<AgentRegistry>(), nullptr, kFreshnessSec};

    EXPECT_EQ(resolveInline(source, "1").kind, GroupVerdictKind::Deny);
}

TEST(RegistryAgentGroupSourceTest, DeniesAMalformedAgentId)
{
    const RegistryAgentGroupSource source {registryWith(1, {"web"}), nullptr, kFreshnessSec};

    for (const auto* id : {"", "abc", "-1", "1x", " 1", "1 ", "0x1", "99999999999"})
    {
        EXPECT_EQ(resolveInline(source, id).kind, GroupVerdictKind::Deny) << "accepted malformed id: '" << id << "'";
    }
}

TEST(RegistryAgentGroupSourceTest, DeniesWithoutARegistry)
{
    const RegistryAgentGroupSource source {nullptr, nullptr, kFreshnessSec};

    EXPECT_EQ(resolveInline(source, "1").kind, GroupVerdictKind::Deny);
}

TEST(RegistryAgentGroupSourceTest, MatchesTheTokenControlHandsOut)
{
    // The anti-drift assertion behind sharing the helpers: whatever /control computes for an
    // entry's groups is what this source answers for that agent.
    const std::vector<std::vector<std::string>> cases {{"default"}, {"web", "db"}, {"db", "web"}, {}, {"a", "b", "c"}};

    AgentId id = 1;
    for (const auto& groups : cases)
    {
        const RegistryAgentGroupSource source {registryWith(id, groups), nullptr, kFreshnessSec};

        EXPECT_EQ(resolveInline(source, std::to_string(id)).selector, makeConfigToken(toGroupsCsv(groups)));
        ++id;
    }
}

TEST(RegistryAgentGroupSourceTest, DeniesAnEntryWhoseGroupsNeverCameFromWazuhDbWhenNoLookupIsWired)
{
    // Regression (#38683): /control/shutdown creates an entry with no groups for an agent it has
    // never seen, and makeConfigToken("") is "default" -- an entry is not a membership; only a
    // wazuh-db-backed refresh is.
    const RegistryAgentGroupSource source {registryWithUnestablishedEntry(1), nullptr, kFreshnessSec};

    EXPECT_EQ(resolveInline(source, "1").kind, GroupVerdictKind::Deny);
}

TEST(RegistryAgentGroupSourceTest, StillServesDefaultWhenWazuhDbGenuinelyReturnedNoGroups)
{
    // The other side of the same coin: the refresh DID happen and wdb had nothing, which the
    // manager treats as membership of "default" -- that agent must keep working.
    const RegistryAgentGroupSource source {registryWith(1, {}), nullptr, kFreshnessSec};

    EXPECT_EQ(resolveInline(source, "1").selector, "default");
}

// -----------------------------------------------------------------------------
// The wazuh-db fallback (#39147)
// -----------------------------------------------------------------------------

TEST(RegistryAgentGroupSourceTest, FreshEntryIsAnsweredInlineWithoutALookup)
{
    const auto registry = registryWith(1, {"web"});
    LookupFixture wdb(registry, "ok [{\"group\":\"other\"}]");
    const RegistryAgentGroupSource source {registry, wdb.lookup, kFreshnessSec};

    const auto verdict = resolveInline(source, "1");

    EXPECT_EQ(verdict.selector, "web");
    EXPECT_EQ(wdb.selects->load(), 0);
    EXPECT_EQ(wdb.lookup->stats().queries, 0U);
}

TEST(RegistryAgentGroupSourceTest, MissingEntryIsLookedUpAndCached)
{
    // A node the agent never sent /control to, or a restarted remoted: nothing in the registry.
    const auto registry = std::make_shared<AgentRegistry>();
    LookupFixture wdb(registry, "ok [{\"group\":\"web,db\"}]");
    const RegistryAgentGroupSource source {registry, wdb.lookup, kFreshnessSec};

    const auto verdict = resolveAndWait(source, "001");

    EXPECT_EQ(verdict.kind, GroupVerdictKind::Selector);
    EXPECT_EQ(verdict.selector, "web,db");
    EXPECT_EQ(wdb.selects->load(), 1);
    ASSERT_NE(registry->get(1), nullptr);
    EXPECT_TRUE(groupsFresh(*registry->get(1), nowSec(), kFreshnessSec));
    EXPECT_EQ(resolveInline(source, "1").selector, "web,db"); // now answered from the registry
    EXPECT_EQ(wdb.selects->load(), 1);
}

TEST(RegistryAgentGroupSourceTest, ExpiredEntryIsLookedUpAndCached)
{
    const auto registry = registryWith(1, {"old"}, 2 * kFreshnessSec);
    LookupFixture wdb(registry, "ok [{\"group\":\"new\"}]");
    const RegistryAgentGroupSource source {registry, wdb.lookup, kFreshnessSec};

    const auto verdict = resolveAndWait(source, "1");

    EXPECT_EQ(verdict.selector, "new");
    EXPECT_EQ(wdb.selects->load(), 1);
    EXPECT_EQ(registry->get(1)->groups, std::vector<std::string> {"new"});
}

TEST(RegistryAgentGroupSourceTest, APublicationAfterACachedReadIsLookedUpAgain)
{
    // The registry holds a fresh read; then the cluster daemon publishes the agent (a membership it
    // just wrote -- possibly older than that read). The publication only withdraws the cached
    // membership: the next download asks wazuh-db, never the cache and never the publication.
    const auto registry = registryWith(1, {"g-read"});
    LookupFixture wdb(registry, "ok [{\"group\":\"g-db\"}]");
    const RegistryAgentGroupSource source {registry, wdb.lookup, kFreshnessSec};
    ASSERT_EQ(resolveInline(source, "1").selector, "g-read");
    ASSERT_EQ(wdb.selects->load(), 0);

    ASSERT_EQ(registry->invalidateGroups(1), AgentRegistry::PushOutcome::Invalidated);
    const auto verdict = resolveAndWait(source, "1");

    EXPECT_EQ(verdict.kind, GroupVerdictKind::Selector);
    EXPECT_EQ(verdict.selector, "g-db");
    EXPECT_EQ(wdb.selects->load(), 1);
    EXPECT_TRUE(groupsFresh(*registry->get(1), nowSec(), kFreshnessSec));
}

TEST(RegistryAgentGroupSourceTest, NoRowIsReportedAsNoRow)
{
    // Never "default" for an agent the local wazuh-db does not know, and nothing is cached: the
    // verdict says "retry" (its row may not have reached this node yet), not "deny".
    const auto registry = std::make_shared<AgentRegistry>();
    LookupFixture wdb(registry, "ok []");
    const RegistryAgentGroupSource source {registry, wdb.lookup, kFreshnessSec};

    EXPECT_EQ(resolveAndWait(source, "1").kind, GroupVerdictKind::NoRow);
    EXPECT_EQ(registry->get(1), nullptr);
}

TEST(RegistryAgentGroupSourceTest, NotEstablishedEntryIsLookedUp)
{
    // An entry whose membership was invalidated (a push, or an earlier "no row"): the download
    // must not take its groups as membership -- it asks wazuh-db, which still has no row.
    const auto registry = registryWithUnestablishedEntry(1, {"default"});
    LookupFixture wdb(registry, "ok []");
    const RegistryAgentGroupSource source {registry, wdb.lookup, kFreshnessSec};

    EXPECT_EQ(resolveAndWait(source, "1").kind, GroupVerdictKind::NoRow);
    EXPECT_EQ(wdb.selects->load(), 1);
}

TEST(RegistryAgentGroupSourceTest, SupersededLookupIsSuperseded)
{
    // The membership is invalidated while the lookup is in flight: its read may predate the change,
    // so the verdict is "retry", never a selector.
    const auto registry = registryWithUnestablishedEntry(1, {"default"});
    LookupFixture wdb(registry, "ok [{\"group\":\"default\"}]", 2000, [&registry] { registry->invalidateGroups(1); });
    const RegistryAgentGroupSource source {registry, wdb.lookup, kFreshnessSec};

    const auto verdict = resolveAndWait(source, "1");
    EXPECT_EQ(verdict.kind, GroupVerdictKind::Superseded);
    EXPECT_TRUE(verdict.selector.empty());
    EXPECT_EQ(registry->get(1)->groupsRefreshedAtSec, 0U);
}

TEST(RegistryAgentGroupSourceTest, UnavailableWhenWazuhDbRefuses)
{
    const auto registry = std::make_shared<AgentRegistry>();
    LookupFixture wdb(registry, "ok []", 300);
    wdb.server.reset(); // wazuh-db is gone while remoted runs
    const RegistryAgentGroupSource source {registry, wdb.lookup, kFreshnessSec};

    const auto start = std::chrono::steady_clock::now();
    const auto verdict = resolveAndWait(source, "1");

    EXPECT_EQ(verdict.kind, GroupVerdictKind::Unavailable);
    EXPECT_LT(std::chrono::steady_clock::now() - start, 2s);
}
