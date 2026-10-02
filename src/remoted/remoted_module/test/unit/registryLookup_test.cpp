/*
 * Wazuh remoted module - RegistryLookup tests
 * Copyright (C) 2015, Wazuh Inc.
 * September 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// The /download fallback's lookup component against a fake wazuh-db (the real WazuhDBClient over a
// UDS): outcomes, what is written into the registry under its ordering rule, coalescing, bounds and
// shutdown. Races are ordered with a gate on the fake's select-agent-group handler (the query has
// been issued, and its ticket taken, before the test acts), never with sleeps.

#include "control/agentRegistry.hpp"
#include "control/controlConfig.hpp"
#include "control/metrics.hpp"
#include "control/registryLookup.hpp"
#include "fakeUdsServer.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace remoted::control;
using namespace std::chrono_literals;
using Kind = LookupOutcome::Kind;

namespace
{
    /// The fake wazuh-db's select-agent-group handler: one fixed answer; optionally holds the
    /// `gateAt`-th query (1-based), or every query (`gateAll`), until release().
    class WdbFake
    {
    public:
        WdbFake(std::string answer, int gateAt, bool gateAll)
            : m_answer(std::move(answer))
            , m_gateAt(gateAt)
            , m_gateAll(gateAll)
            , m_releaseFuture(m_release.get_future().share())
            , m_receivedFuture(m_received.get_future())
        {
        }

        std::string respond(const std::string& request)
        {
            if (request.rfind("global select-agent-group", 0) != 0)
            {
                return "ok";
            }
            const int n = ++m_selects;
            if (m_gateAll || n == m_gateAt)
            {
                if (!m_receivedSet.exchange(true))
                {
                    m_received.set_value();
                }
                m_releaseFuture.wait_for(10s); // bounded: a failing test must not hang the fake
            }
            return m_answer;
        }

        bool waitReceived()
        {
            return m_receivedFuture.wait_for(5s) == std::future_status::ready;
        }

        void release()
        {
            if (!m_released.exchange(true))
            {
                m_release.set_value();
            }
        }

        int selects() const
        {
            return m_selects.load();
        }

    private:
        const std::string m_answer;
        const int m_gateAt;
        const bool m_gateAll;
        std::promise<void> m_release;
        std::shared_future<void> m_releaseFuture;
        std::promise<void> m_received;
        std::future<void> m_receivedFuture;
        std::atomic<bool> m_receivedSet {false};
        std::atomic<bool> m_released {false};
        std::atomic<int> m_selects {0};
    };

    /// Collects the outcomes the waiters receive.
    struct Outcomes
    {
        std::mutex mu;
        std::condition_variable cv;
        std::vector<LookupOutcome> got;

        RegistryLookup::Waiter waiter()
        {
            return [this](LookupOutcome outcome)
            {
                std::lock_guard lock(mu);
                got.push_back(std::move(outcome));
                cv.notify_all();
            };
        }
        bool waitFor(std::size_t n, std::chrono::milliseconds timeout = 5000ms)
        {
            std::unique_lock lock(mu);
            return cv.wait_for(lock, timeout, [&] { return got.size() >= n; });
        }
        std::size_t size()
        {
            std::lock_guard lock(mu);
            return got.size();
        }
        std::size_t count(Kind kind)
        {
            std::lock_guard lock(mu);
            return static_cast<std::size_t>(
                std::count_if(got.begin(), got.end(), [kind](const LookupOutcome& o) { return o.kind == kind; }));
        }
        LookupOutcome first()
        {
            std::lock_guard lock(mu);
            return got.at(0);
        }
    };

    struct Options
    {
        std::string answer = "ok [{\"group\":\"g1\"}]";
        int gateAt = 0;
        bool gateAll = false;
        LookupLimits limits {};
        uint32_t deadlineMs = 2000;
    };

    /// The real WazuhDBClient (inside RegistryLookup) against a fake wazuh-db on a unique socket.
    /// Teardown releases the gate first, so neither the client's workers nor the fake block on it.
    struct Fixture
    {
        std::string path = remoted::test::makeUniqueSocketPath("rl_wdb");
        std::shared_ptr<WdbFake> wdb;
        std::unique_ptr<remoted::test::FakeUdsServer> server;
        std::shared_ptr<AgentRegistry> registry = std::make_shared<AgentRegistry>();
        ControlMetrics metrics {}; // the null object: every inc is a no-op
        Config cfg;
        std::unique_ptr<RegistryLookup> lookup;

        explicit Fixture(Options options = {})
            : wdb(std::make_shared<WdbFake>(options.answer, options.gateAt, options.gateAll))
        {
            server = std::make_unique<remoted::test::FakeUdsServer>(
                path, [wdb = wdb](const std::string& request) { return wdb->respond(request); });
            cfg.wdbSocketPath = path;
            cfg.wdbRoundtripDeadlineMs = options.deadlineMs;
            cfg.wdbRequestDeadlineMs = options.deadlineMs;
            lookup = std::make_unique<RegistryLookup>(registry, cfg, metrics, options.limits);
        }

        ~Fixture()
        {
            wdb->release();
            lookup.reset();
            server.reset();
        }

        /// An established entry with activity fields a lookup must leave alone.
        void putEstablished(AgentId id, std::vector<std::string> groups, uint64_t refreshedAt)
        {
            registry->update(id,
                             [&](std::shared_ptr<const AgentEntry>)
                             {
                                 auto e = std::make_shared<AgentEntry>();
                                 e->groups = groups;
                                 e->groupsRefreshedAtSec = refreshedAt;
                                 e->groupsSeq = registry->nextGroupsSeq();
                                 e->lastKeepaliveUpdateSec = 200;
                                 e->lastActivitySec = 300;
                                 e->createdAtSec = 50;
                                 e->hostPersisted = true;
                                 return e;
                             });
        }
    };
} // namespace

TEST(RegistryLookupTest, RowForAnAbsentAgentIsCachedEstablished)
{
    Fixture f({"ok [{\"group\":\"g1,g2\"}]"});
    Outcomes out;

    f.lookup->lookup(1, 1000, out.waiter());
    ASSERT_TRUE(out.waitFor(1));

    const auto o = out.first();
    EXPECT_EQ(o.kind, Kind::Groups);
    EXPECT_EQ(o.groups, (std::vector<std::string> {"g1", "g2"}));
    const auto entry = f.registry->get(1);
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(entry->groups, (std::vector<std::string> {"g1", "g2"}));
    EXPECT_EQ(entry->groupsRefreshedAtSec, 1000U);
    EXPECT_GT(entry->groupsSeq, 0U);
    EXPECT_EQ(entry->createdAtSec, 1000U);
    EXPECT_EQ(entry->lastActivitySec, 0U); // a lookup is not agent activity
    EXPECT_EQ(f.lookup->stats().queries, 1U);
}

TEST(RegistryLookupTest, RowRefreshesAnExpiredEntryAndKeepsActivity)
{
    Fixture f;
    f.putEstablished(1, {"old"}, 10);
    Outcomes out;

    f.lookup->lookup(1, 1000, out.waiter());
    ASSERT_TRUE(out.waitFor(1));

    EXPECT_EQ(out.first().kind, Kind::Groups);
    const auto entry = f.registry->get(1);
    EXPECT_EQ(entry->groups, std::vector<std::string> {"g1"});
    EXPECT_EQ(entry->groupsRefreshedAtSec, 1000U);
    EXPECT_EQ(entry->lastKeepaliveUpdateSec, 200U);
    EXPECT_EQ(entry->lastActivitySec, 300U);
    EXPECT_EQ(entry->createdAtSec, 50U);
    EXPECT_TRUE(entry->hostPersisted);
}

TEST(RegistryLookupTest, NoRowForAnAbsentAgentCreatesNothing)
{
    Fixture f({"ok []"});
    Outcomes out;

    f.lookup->lookup(1, 1000, out.waiter());
    ASSERT_TRUE(out.waitFor(1));

    EXPECT_EQ(out.first().kind, Kind::NoRow);
    EXPECT_EQ(f.registry->get(1), nullptr); // never a membership, never an entry (no negative cache)
    EXPECT_EQ(f.registry->size(), 0U);
}

TEST(RegistryLookupTest, NoRowInvalidatesAnExistingEntryAndKeepsActivity)
{
    Fixture f({"ok []"});
    f.putEstablished(2, {"old"}, 10);
    const auto before = f.registry->get(2);
    Outcomes out;

    f.lookup->lookup(2, 1000, out.waiter());
    ASSERT_TRUE(out.waitFor(1));

    EXPECT_EQ(out.first().kind, Kind::NoRow);
    const auto after = f.registry->get(2);
    ASSERT_NE(after, nullptr);
    EXPECT_EQ(after->groups, before->groups);
    EXPECT_EQ(after->groupsRefreshedAtSec, 0U); // the membership stops counting
    EXPECT_GT(after->groupsSeq, before->groupsSeq);
    EXPECT_EQ(after->lastKeepaliveUpdateSec, 200U);
    EXPECT_EQ(after->lastActivitySec, 300U);
    EXPECT_EQ(after->createdAtSec, 50U);
    EXPECT_TRUE(after->hostPersisted);
}

TEST(RegistryLookupTest, WazuhDbErrorIsUnavailable)
{
    Fixture f({"err something failed"});
    Outcomes out;

    f.lookup->lookup(1, 1000, out.waiter());
    ASSERT_TRUE(out.waitFor(1));

    EXPECT_EQ(out.first().kind, Kind::Unavailable);
    EXPECT_EQ(f.registry->get(1), nullptr);
}

TEST(RegistryLookupTest, RefusedConnectionIsUnavailableWithinTheDeadline)
{
    Options options;
    options.deadlineMs = 300;
    Fixture f(options);
    f.server.reset(); // wazuh-db is gone while the client lives
    Outcomes out;

    const auto start = std::chrono::steady_clock::now();
    f.lookup->lookup(1, 1000, out.waiter());
    ASSERT_TRUE(out.waitFor(1));

    EXPECT_EQ(out.first().kind, Kind::Unavailable);
    EXPECT_LT(std::chrono::steady_clock::now() - start, 2s);
}

TEST(RegistryLookupTest, ConcurrentLookupsForOneAgentShareOneQuery)
{
    Options options;
    options.gateAt = 1;
    Fixture f(options);
    Outcomes out;

    f.lookup->lookup(1, 1000, out.waiter());
    ASSERT_TRUE(f.wdb->waitReceived());
    for (int i = 0; i < 39; ++i)
    {
        f.lookup->lookup(1, 1000, out.waiter());
    }
    // 32 waiters per agent: the 8 beyond are refused at once, inline.
    EXPECT_EQ(out.size(), 8U);
    EXPECT_EQ(out.count(Kind::Unavailable), 8U);

    f.wdb->release();
    ASSERT_TRUE(out.waitFor(40));
    EXPECT_EQ(out.count(Kind::Groups), 32U);
    EXPECT_EQ(f.wdb->selects(), 1);
    const auto stats = f.lookup->stats();
    EXPECT_EQ(stats.queries, 1U);
    EXPECT_EQ(stats.coalesced, 31U);
    EXPECT_EQ(stats.rejected, 8U);
}

TEST(RegistryLookupTest, TotalWaiterBoundRejects)
{
    Options options;
    options.gateAll = true;
    options.limits = LookupLimits {32, 4};
    Fixture f(options);
    Outcomes out;

    for (AgentId id = 1; id <= 5; ++id)
    {
        f.lookup->lookup(id, 1000, out.waiter());
    }
    EXPECT_EQ(out.size(), 1U); // the fifth, refused at once
    EXPECT_EQ(out.count(Kind::Unavailable), 1U);

    f.wdb->release();
    ASSERT_TRUE(out.waitFor(5));
    EXPECT_EQ(out.count(Kind::Groups), 4U);
    EXPECT_EQ(f.lookup->stats().rejected, 1U);
}

// A push never establishes groups (S45), so a newer established write can only be another read
// stored first -- /control's own query for the same agent, which this component does not coalesce.
TEST(RegistryLookupTest, SupersededByANewerReadAnswersIt)
{
    Options options;
    options.answer = "ok [{\"group\":\"g-old\"}]";
    options.gateAt = 1;
    Fixture f(options);
    f.putEstablished(1, {"g-old"}, 10);
    Outcomes out;

    f.lookup->lookup(1, 1000, out.waiter());
    ASSERT_TRUE(f.wdb->waitReceived());
    f.putEstablished(1, {"g-new"}, 2000); // the other read's store
    const auto storedSeq = f.registry->get(1)->groupsSeq;
    f.wdb->release();
    ASSERT_TRUE(out.waitFor(1));

    EXPECT_EQ(out.first().kind, Kind::Groups);
    EXPECT_EQ(out.first().groups, std::vector<std::string> {"g-new"});
    const auto entry = f.registry->get(1);
    EXPECT_EQ(entry->groups, std::vector<std::string> {"g-new"});
    EXPECT_EQ(entry->groupsSeq, storedSeq);
}

TEST(RegistryLookupTest, NoRowSupersededByANewerReadAnswersIt)
{
    Options options;
    options.answer = "ok []";
    options.gateAt = 1;
    Fixture f(options);
    f.putEstablished(1, {"g-old"}, 10);
    Outcomes out;

    f.lookup->lookup(1, 1000, out.waiter());
    ASSERT_TRUE(f.wdb->waitReceived());
    // The row reached the replica -- and another read stored it -- after this query read it.
    f.putEstablished(1, {"g-new"}, 2000);
    const auto storedSeq = f.registry->get(1)->groupsSeq;
    f.wdb->release();
    ASSERT_TRUE(out.waitFor(1));

    EXPECT_EQ(out.first().kind, Kind::Groups);
    EXPECT_EQ(out.first().groups, std::vector<std::string> {"g-new"});
    const auto entry = f.registry->get(1);
    EXPECT_EQ(entry->groupsSeq, storedSeq); // the older answer neither wrote nor invalidated
    EXPECT_EQ(entry->groupsRefreshedAtSec, 2000U);
}

TEST(RegistryLookupTest, RowWithNoGroupsIsCachedAsDefault)
{
    Fixture f({"ok [{\"group\":\"\"}]"});
    Outcomes out;

    f.lookup->lookup(1, 1000, out.waiter());
    ASSERT_TRUE(out.waitFor(1));

    // A row with no groups is membership of "default" -- stored as /control stores it, so the
    // groups, config_hash and config_token /control builds from the entry stay /control's own.
    EXPECT_EQ(out.first().kind, Kind::Groups);
    EXPECT_EQ(out.first().groups, std::vector<std::string> {"default"});
    const auto entry = f.registry->get(1);
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(entry->groups, std::vector<std::string> {"default"});
    EXPECT_EQ(entry->groupsRefreshedAtSec, 1000U);
}

TEST(RegistryLookupTest, SupersededByInvalidationIsSuperseded)
{
    Options options;
    options.gateAt = 1;
    Fixture f(options);
    f.putEstablished(1, {"g-old"}, 10);
    Outcomes out;

    f.lookup->lookup(1, 1000, out.waiter());
    ASSERT_TRUE(f.wdb->waitReceived());
    // The worker applied a change it could not confirm: the local database may no longer hold
    // what this query is reading.
    ASSERT_EQ(f.registry->invalidateGroups(1), AgentRegistry::PushOutcome::Invalidated);
    const auto invalidatedSeq = f.registry->get(1)->groupsSeq;
    // A request that arrives after the invalidation joins the query already in flight.
    f.lookup->lookup(1, 1000, out.waiter());
    f.wdb->release();
    ASSERT_TRUE(out.waitFor(2));

    // The read may predate the change: it answers nobody, and nothing is written.
    EXPECT_EQ(out.count(Kind::Superseded), 2U);
    EXPECT_EQ(f.lookup->stats().queries, 1U);
    auto entry = f.registry->get(1);
    EXPECT_EQ(entry->groupsRefreshedAtSec, 0U); // still invalidated
    EXPECT_EQ(entry->groupsSeq, invalidatedSeq);
    EXPECT_EQ(entry->groups, std::vector<std::string> {"g-old"});

    // The next request reads the database again, and that read is the answer.
    f.lookup->lookup(1, 1100, out.waiter());
    ASSERT_TRUE(out.waitFor(3));
    EXPECT_EQ(out.count(Kind::Groups), 1U);
    entry = f.registry->get(1);
    EXPECT_EQ(entry->groups, std::vector<std::string> {"g1"});
    EXPECT_EQ(entry->groupsRefreshedAtSec, 1100U);
}

TEST(RegistryLookupTest, SkippedPushMakesTheLookupSuperseded)
{
    Options options;
    options.gateAt = 1;
    Fixture f(options);
    Outcomes out;

    f.lookup->lookup(1, 1000, out.waiter());
    ASSERT_TRUE(f.wdb->waitReceived());
    // A push for an agent this node does not hold: it may have been agent 1's, so this read may
    // predate agent 1's change.
    ASSERT_EQ(f.registry->invalidateGroups(9), AgentRegistry::PushOutcome::Skipped);
    f.wdb->release();
    ASSERT_TRUE(out.waitFor(1));

    EXPECT_EQ(out.first().kind, Kind::Superseded);
    EXPECT_TRUE(out.first().groups.empty());
    EXPECT_EQ(f.registry->get(1), nullptr);
}

TEST(RegistryLookupTest, StopAnswersEveryWaiterOnceAndRefusesNewLookups)
{
    Options options;
    options.gateAll = true; // both agents' queries stay in flight until they time out
    options.deadlineMs = 300;
    Fixture f(options);
    Outcomes out;

    for (int i = 0; i < 3; ++i)
    {
        f.lookup->lookup(1, 1000, out.waiter());
        f.lookup->lookup(2, 1000, out.waiter());
    }
    ASSERT_TRUE(f.wdb->waitReceived());

    const auto start = std::chrono::steady_clock::now();
    std::thread stopper([&] { f.lookup->stop(); });
    stopper.join();
    EXPECT_LT(std::chrono::steady_clock::now() - start, 3s);

    EXPECT_EQ(out.size(), 6U);
    EXPECT_EQ(out.count(Kind::Unavailable), 6U);

    f.lookup->lookup(3, 1000, out.waiter()); // refused inline once stopped
    EXPECT_EQ(out.size(), 7U);
    EXPECT_EQ(out.count(Kind::Unavailable), 7U);
    f.lookup->stop(); // idempotent

    f.wdb->release();
    std::this_thread::sleep_for(100ms); // anything answered twice would show up here
    EXPECT_EQ(out.size(), 7U);
}

TEST(RegistryLookupTest, AWaiterMayLookUpAgainFromItsCallback)
{
    Fixture f;
    Outcomes out;
    auto* lookup = f.lookup.get();
    auto second = out.waiter();

    f.lookup->lookup(1,
                     1000,
                     [lookup, second, first = out.waiter()](LookupOutcome outcome) mutable
                     {
                         lookup->lookup(2, 1000, second); // re-entrant, from a client worker thread
                         first(std::move(outcome));
                     });
    ASSERT_TRUE(out.waitFor(2));
    EXPECT_EQ(out.count(Kind::Groups), 2U);
}
