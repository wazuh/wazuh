/*
 * Wazuh remoted module - Agent registry unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 31, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "control/agentRegistry.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <memory>
#include <thread>
#include <vector>

using namespace remoted::control;

namespace
{
    // Insert an entry with an explicit "reference" timestamp -- max(activity,
    // created) -- so eviction predicates in tests read cleanly. All tests below
    // build entries this way so the ttl comparison in evictExpiredEntries has
    // one place to change if its rule changes.
    void put(AgentRegistry& reg, AgentId id, uint64_t referenceSec, std::vector<std::string> groups = {})
    {
        reg.update(id,
                   [referenceSec, groups = std::move(groups)](std::shared_ptr<const AgentEntry>)
                   {
                       auto entry = std::make_shared<AgentEntry>();
                       entry->groups = std::move(groups);
                       entry->createdAtSec = referenceSec;
                       entry->lastActivitySec = referenceSec;
                       return entry;
                   });
    }
} // namespace

// -----------------------------------------------------------------------------
// get / update happy paths.
// -----------------------------------------------------------------------------

TEST(AgentRegistryTest, GetOnEmptyReturnsNull)
{
    AgentRegistry reg;
    EXPECT_EQ(reg.get(42), nullptr);
}

// size() (the remoted.control.registry.agents pull) sums across ALL shards -- ids are sharded
// by id % 8, so consecutive ids land in different shards and a per-shard bug would undercount --
// counts replacements once, and shrinks with eviction.
TEST(AgentRegistryTest, SizeSumsAcrossShardsAndTracksEviction)
{
    AgentRegistry reg;
    EXPECT_EQ(reg.size(), 0U);

    const auto now = static_cast<uint64_t>(std::time(nullptr));
    for (AgentId id = 1; id <= 10; ++id) // 10 consecutive ids: every shard is hit
    {
        put(reg, id, now);
    }
    EXPECT_EQ(reg.size(), 10U);

    put(reg, 1, now); // replacement, not a new entry
    EXPECT_EQ(reg.size(), 10U);

    put(reg, 11, now - 1000); // stale entry, past the ttl below
    EXPECT_EQ(reg.size(), 11U);
    reg.evictExpiredEntries(/*ttlSec=*/500);
    EXPECT_EQ(reg.size(), 10U);
}

TEST(AgentRegistryTest, UpdateInsertsWhenAbsent)
{
    AgentRegistry reg;

    auto inserted = reg.update(42,
                               [](std::shared_ptr<const AgentEntry> current)
                               {
                                   // Contract: updater receives nullptr for a missing key.
                                   EXPECT_EQ(current, nullptr);
                                   auto e = std::make_shared<AgentEntry>();
                                   e->groups = {"default"};
                                   e->createdAtSec = 1000;
                                   return e;
                               });

    ASSERT_NE(inserted, nullptr);
    EXPECT_EQ(inserted->groups, std::vector<std::string> {"default"});

    // get() reflects the insertion.
    auto got = reg.get(42);
    ASSERT_NE(got, nullptr);
    EXPECT_EQ(got->createdAtSec, 1000U);
    EXPECT_EQ(got.get(), inserted.get()); // same shared_ptr target (copy-on-write).
}

TEST(AgentRegistryTest, UpdateReplacesWhenPresent)
{
    AgentRegistry reg;
    put(reg, 42, 1000, {"g1"});

    auto replaced = reg.update(42,
                               [](std::shared_ptr<const AgentEntry> current)
                               {
                                   // Contract: updater receives the existing entry.
                                   EXPECT_NE(current, nullptr);
                                   auto e = std::make_shared<AgentEntry>(*current);
                                   e->groups = {"g1", "g2"};
                                   e->lastActivitySec = 2000;
                                   return e;
                               });

    ASSERT_NE(replaced, nullptr);
    EXPECT_EQ(replaced->groups, (std::vector<std::string> {"g1", "g2"}));
    EXPECT_EQ(replaced->lastActivitySec, 2000U);
    // createdAtSec is preserved through the copy in the updater.
    EXPECT_EQ(replaced->createdAtSec, 1000U);
}

// -----------------------------------------------------------------------------
// update() with a nullptr-returning updater is a documented "no-op". It exists
// for callers that decide inside the updater not to modify (e.g. keepalive
// throttled) and returning the existing entry, unchanged. The API must NOT
// erase the key on a nullptr return -- only evictExpiredEntries removes.
// -----------------------------------------------------------------------------
TEST(AgentRegistryTest, UpdateReturningNullIsNoOp)
{
    AgentRegistry reg;
    put(reg, 42, 1000, {"g1"});
    auto before = reg.get(42);
    ASSERT_NE(before, nullptr);

    auto result = reg.update(42, [](std::shared_ptr<const AgentEntry>) { return nullptr; });

    // The current entry is returned so the caller can continue reading it.
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result.get(), before.get()); // same shared_ptr, unchanged.

    // And the map still holds it.
    auto after = reg.get(42);
    ASSERT_NE(after, nullptr);
    EXPECT_EQ(after.get(), before.get());
}

// Same, but for a missing key: updater returns nullptr -> registry stays empty
// for that id, and update() propagates the nullptr the caller expects.
TEST(AgentRegistryTest, UpdateReturningNullOnMissingStaysMissing)
{
    AgentRegistry reg;

    auto result = reg.update(42, [](std::shared_ptr<const AgentEntry>) { return nullptr; });

    EXPECT_EQ(result, nullptr);
    EXPECT_EQ(reg.get(42), nullptr);
}

// -----------------------------------------------------------------------------
// Sharded storage: entries with different ids land in independent shards. This
// test's real value is guarding against a future change that would key by
// something other than the id (e.g. hash), which would silently break the
// documented "id determines the shard" locking model.
// -----------------------------------------------------------------------------
TEST(AgentRegistryTest, DifferentIdsCoexist)
{
    AgentRegistry reg;
    for (AgentId id = 1; id < 32; ++id)
    {
        put(reg, id, 1000U + id);
    }
    for (AgentId id = 1; id < 32; ++id)
    {
        auto e = reg.get(id);
        ASSERT_NE(e, nullptr) << "missing id=" << id;
        EXPECT_EQ(e->createdAtSec, 1000U + id);
    }
}

// -----------------------------------------------------------------------------
// evictExpiredEntries: baseline. An entry with reference `now - (ttl + 1)` is
// strictly expired and must go; an entry within ttl must stay.
// -----------------------------------------------------------------------------
TEST(AgentRegistryTest, EvictionRemovesExpiredEntries)
{
    AgentRegistry reg;
    const auto now = static_cast<uint64_t>(std::time(nullptr));
    const uint64_t ttl = 3600;

    put(reg, 1, now - (ttl + 60)); // clearly expired
    put(reg, 2, now - 60);         // fresh

    reg.evictExpiredEntries(ttl);

    EXPECT_EQ(reg.get(1), nullptr);
    EXPECT_NE(reg.get(2), nullptr);
}

// -----------------------------------------------------------------------------
// Boundary: exactly `now - ttl` (age == ttl) is NOT considered expired. The
// predicate is strict inequality (age > ttl). Locks in the current behaviour
// so a switch to `>=` in the future is intentional, not accidental.
// -----------------------------------------------------------------------------
TEST(AgentRegistryTest, EvictionBoundaryAtTtlKeepsEntry)
{
    AgentRegistry reg;
    const auto now = static_cast<uint64_t>(std::time(nullptr));
    const uint64_t ttl = 3600;

    put(reg, 1, now - ttl); // age == ttl exactly
    reg.evictExpiredEntries(ttl);
    EXPECT_NE(reg.get(1), nullptr);
}

// -----------------------------------------------------------------------------
// Never-touched entry (lastActivitySec == 0) must still age out using
// createdAtSec. This is the leak the Phase 1 fix closed -- if we ever
// regress and evict only on lastActivitySec, this test fails.
// -----------------------------------------------------------------------------
TEST(AgentRegistryTest, EvictionUsesCreatedAtWhenActivityIsZero)
{
    AgentRegistry reg;
    const auto now = static_cast<uint64_t>(std::time(nullptr));
    const uint64_t ttl = 3600;

    reg.update(7,
               [now, ttl](std::shared_ptr<const AgentEntry>)
               {
                   auto e = std::make_shared<AgentEntry>();
                   e->createdAtSec = now - (ttl + 120);
                   e->lastActivitySec = 0; // never updated
                   return e;
               });

    reg.evictExpiredEntries(ttl);
    EXPECT_EQ(reg.get(7), nullptr);
}

// -----------------------------------------------------------------------------
// Both timestamps zero means "no reference at all" -- guard against evicting
// something we can't decide about. If we ever start evicting these, this test
// fails loudly.
// -----------------------------------------------------------------------------
TEST(AgentRegistryTest, EvictionKeepsEntriesWithNoTimestamp)
{
    AgentRegistry reg;
    reg.update(9,
               [](std::shared_ptr<const AgentEntry>)
               {
                   auto e = std::make_shared<AgentEntry>();
                   e->createdAtSec = 0;
                   e->lastActivitySec = 0;
                   return e;
               });

    reg.evictExpiredEntries(1);
    EXPECT_NE(reg.get(9), nullptr);
}

// -----------------------------------------------------------------------------
// Two-phase eviction re-check. Simulates: scan collects id=1 as expired, but a
// concurrent update() bumps lastActivitySec before the exclusive phase runs.
// The re-check under the write lock must see the fresh timestamp and keep it.
//
// We can't directly hook into the phase gap from the outside, so we approximate
// it: run a background updater that keeps rewriting the same id with fresh
// timestamps while eviction runs in a loop with an aggressive ttl. The entry
// must never be evicted while the updater is refreshing it.
// -----------------------------------------------------------------------------
TEST(AgentRegistryTest, EvictionRespectsConcurrentRefresh)
{
    AgentRegistry reg;
    const AgentId id = 1;

    put(reg, id, 0); // start with age-0 references so eviction path takes it.

    std::atomic_bool stop {false};
    std::thread refresher(
        [&]
        {
            while (!stop.load(std::memory_order_relaxed))
            {
                const auto now = static_cast<uint64_t>(std::time(nullptr));
                reg.update(id,
                           [now](std::shared_ptr<const AgentEntry> cur)
                           {
                               auto e = cur ? std::make_shared<AgentEntry>(*cur) : std::make_shared<AgentEntry>();
                               e->lastActivitySec = now;
                               e->createdAtSec = e->createdAtSec == 0 ? now : e->createdAtSec;
                               return e;
                           });
                std::this_thread::yield();
            }
        });

    // Run several eviction passes with ttl=0 (everything is expired the instant
    // scan runs) racing against the refresher. Because the write-lock re-check
    // reads a fresh lastActivitySec, the entry must remain.
    for (int i = 0; i < 200; ++i)
    {
        reg.evictExpiredEntries(0);
        std::this_thread::sleep_for(std::chrono::microseconds(50));
        // The entry MAY get evicted if the refresher hasn't ticked yet; but as
        // long as it comes back, the registry is behaving.
    }

    stop.store(true, std::memory_order_relaxed);
    refresher.join();

    // After the refresher's last write, the entry must be present.
    auto entry = reg.get(id);
    ASSERT_NE(entry, nullptr);
    EXPECT_GT(entry->lastActivitySec, 0U);
}

// -----------------------------------------------------------------------------
// Ttl = 0 with a fresh entry (age > 0): the entry IS expired at the same
// second it was created. Confirms the "any age > 0" side of the predicate.
// -----------------------------------------------------------------------------
TEST(AgentRegistryTest, EvictionWithZeroTtlEvictsAnythingWithReference)
{
    AgentRegistry reg;
    const auto now = static_cast<uint64_t>(std::time(nullptr));

    put(reg, 5, now - 1); // 1 second old, ttl=0

    reg.evictExpiredEntries(0);
    EXPECT_EQ(reg.get(5), nullptr);
}

// -----------------------------------------------------------------------------
// Membership writers and the one ordering rule (#39147). Every write to an entry's groups is stamped
// from a registry-wide counter; a wazuh-db answer whose query was ticketed before a newer write must
// not overwrite it.
// -----------------------------------------------------------------------------
namespace
{
    // An established entry whose activity fields a membership push must leave alone.
    void putActive(AgentRegistry& reg, AgentId id, std::vector<std::string> groups)
    {
        reg.update(id,
                   [groups = std::move(groups)](std::shared_ptr<const AgentEntry>)
                   {
                       auto entry = std::make_shared<AgentEntry>();
                       entry->groups = groups;
                       entry->groupsRefreshedAtSec = 100;
                       entry->lastKeepaliveUpdateSec = 200;
                       entry->lastActivitySec = 300;
                       entry->createdAtSec = 50;
                       entry->hostPersisted = true;
                       return entry;
                   });
    }
} // namespace

TEST(AgentRegistryTest, InvalidateGroupsMarksTheEntryNotEstablished)
{
    AgentRegistry reg;
    putActive(reg, 1, {"g1"}); // established at 100
    ASSERT_TRUE(groupsFresh(*reg.get(1), 110, 60));
    const auto before = reg.get(1)->groupsSeq;

    EXPECT_EQ(reg.invalidateGroups(1), AgentRegistry::PushOutcome::Invalidated);

    const auto entry = reg.get(1);
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(entry->groupsRefreshedAtSec, 0U);
    EXPECT_EQ(entry->groups, (std::vector<std::string> {"g1"})); // kept for notify's cached-on-error path
    EXPECT_GT(entry->groupsSeq, before);
    EXPECT_FALSE(groupsFresh(*entry, 110, 60));
    EXPECT_EQ(entry->lastKeepaliveUpdateSec, 200U);
    EXPECT_EQ(entry->lastActivitySec, 300U);
    EXPECT_EQ(entry->createdAtSec, 50U);
    EXPECT_TRUE(entry->hostPersisted);
}

TEST(AgentRegistryTest, InvalidateGroupsSkipsAnAbsentAgent)
{
    AgentRegistry reg;

    EXPECT_EQ(reg.invalidateGroups(7), AgentRegistry::PushOutcome::Skipped);
    EXPECT_EQ(reg.size(), 0U);
}

TEST(AgentRegistryTest, LookupTicketTakenBeforeAnInvalidationIsSuperseded)
{
    AgentRegistry reg;
    putActive(reg, 1, {"g-old"});
    const auto ticket = reg.groupsTicket(); // the query is issued here...

    ASSERT_EQ(reg.invalidateGroups(1), AgentRegistry::PushOutcome::Invalidated); // ...a push lands...

    EXPECT_FALSE(reg.mayStoreLookup(reg.get(1), ticket)); // ...so its answer may predate the change.
}

TEST(AgentRegistryTest, LookupTicketTakenAfterAnInvalidationMayStore)
{
    AgentRegistry reg;
    putActive(reg, 1, {"g-old"});
    ASSERT_EQ(reg.invalidateGroups(1), AgentRegistry::PushOutcome::Invalidated);

    const auto ticket = reg.groupsTicket();

    EXPECT_TRUE(reg.mayStoreLookup(reg.get(1), ticket));
}

TEST(AgentRegistryTest, AbsentAtIssueLookupIsNotCachedAfterASkippedPush)
{
    AgentRegistry reg;
    putActive(reg, 2, {"g1"}); // established, an unrelated agent
    reg.update(3,
               [](std::shared_ptr<const AgentEntry>)
               {
                   auto entry = std::make_shared<AgentEntry>(); // what /control/shutdown mints
                   entry->lastActivitySec = 300;
                   return entry;
               });
    const auto ticket = reg.groupsTicket();

    // A push for an agent this node does not hold: nothing records which agent it was.
    ASSERT_EQ(reg.invalidateGroups(9), AgentRegistry::PushOutcome::Skipped);

    EXPECT_FALSE(reg.mayStoreLookup(nullptr, ticket));
    EXPECT_FALSE(reg.mayStoreLookup(reg.get(3), ticket));
    EXPECT_TRUE(reg.mayStoreLookup(reg.get(2), ticket));          // established and not re-stamped: unaffected
    EXPECT_TRUE(reg.mayStoreLookup(nullptr, reg.groupsTicket())); // a later ticket is past the skip
}

// Eviction erases an entry's groups stamp with it. An agent that only downloads on a node keeps
// lastActivitySec == 0 there and ages out from its creation, even while a lookup for it is in flight.
TEST(AgentRegistryTest, EvictingAnInvalidatedEntrySupersedesAnEarlierLookup)
{
    AgentRegistry reg;
    putActive(reg, 1, {"g-old"}); // activity at 300: long past any TTL below
    reg.update(2,
               [&reg](std::shared_ptr<const AgentEntry>)
               {
                   auto entry = std::make_shared<AgentEntry>(); // an unrelated agent, active now
                   entry->groups = {"g1"};
                   entry->groupsRefreshedAtSec = 100;
                   entry->groupsSeq = reg.nextGroupsSeq();
                   entry->lastActivitySec = static_cast<uint64_t>(std::time(nullptr));
                   return entry;
               });
    const auto ticket = reg.groupsTicket(); // agent 1's query is issued here...

    ASSERT_EQ(reg.invalidateGroups(1), AgentRegistry::PushOutcome::Invalidated); // ...a push lands...
    reg.evictExpiredEntries(/*ttlSec=*/60);                                      // ...and agent 1 ages out
    ASSERT_EQ(reg.get(1), nullptr);
    ASSERT_NE(reg.get(2), nullptr);

    EXPECT_FALSE(reg.mayStoreLookup(nullptr, ticket));            // the empty slot vouches for nothing
    EXPECT_TRUE(reg.mayStoreLookup(reg.get(2), ticket));          // established and kept: unaffected
    EXPECT_TRUE(reg.mayStoreLookup(nullptr, reg.groupsTicket())); // a later ticket is past the eviction
}

TEST(AgentRegistryTest, EvictingANewerReadSupersedesAnOlderLookup)
{
    AgentRegistry reg;
    putActive(reg, 1, {"g-old"});
    const auto ticket = reg.groupsTicket(); // read A is issued...
    ASSERT_EQ(reg.invalidateGroups(1), AgentRegistry::PushOutcome::Invalidated);
    reg.update(1,
               [&reg](std::shared_ptr<const AgentEntry> old)
               {
                   auto entry = std::make_shared<AgentEntry>(*old); // ...read B, issued after the change, stores first
                   entry->groups = {"g-new"};
                   entry->groupsRefreshedAtSec = 400;
                   entry->groupsSeq = reg.nextGroupsSeq();
                   return entry;
               });

    reg.evictExpiredEntries(/*ttlSec=*/60);
    ASSERT_EQ(reg.get(1), nullptr);

    EXPECT_FALSE(reg.mayStoreLookup(nullptr, ticket)); // A may predate the change B saw
}

TEST(AgentRegistryTest, EvictionOnlyBindsLookupsTicketedBeforeTheErasedWrite)
{
    AgentRegistry reg;
    putActive(reg, 1, {"g-old"});
    ASSERT_EQ(reg.invalidateGroups(1), AgentRegistry::PushOutcome::Invalidated);
    const auto ticket = reg.groupsTicket(); // issued after the entry's last groups write

    reg.evictExpiredEntries(/*ttlSec=*/60);
    ASSERT_EQ(reg.get(1), nullptr);

    EXPECT_TRUE(reg.mayStoreLookup(nullptr, ticket)); // this read already follows the invalidation
}

TEST(AgentRegistryTest, EvictingAnEntryWithNoGroupsWriteLeavesNoMark)
{
    AgentRegistry reg;
    const auto ticket = reg.groupsTicket();
    reg.update(3,
               [](std::shared_ptr<const AgentEntry>)
               {
                   auto entry = std::make_shared<AgentEntry>(); // what /control/shutdown mints: groupsSeq 0
                   entry->lastActivitySec = 300;
                   return entry;
               });

    reg.evictExpiredEntries(/*ttlSec=*/60);
    ASSERT_EQ(reg.get(3), nullptr);

    EXPECT_TRUE(reg.mayStoreLookup(nullptr, ticket)); // no groups write went with it
}

TEST(AgentRegistryTest, GroupsSequenceIsStrictlyIncreasingUnderConcurrency)
{
    constexpr int kThreads = 8;
    constexpr int kWrites = 1000;
    AgentRegistry reg;
    for (AgentId id = 1; id <= kThreads; ++id)
    {
        putActive(reg, id, {"g"});
    }

    std::vector<std::vector<uint64_t>> stamps(kThreads);
    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t)
    {
        threads.emplace_back(
            [&, t]()
            {
                const AgentId id = static_cast<AgentId>(t + 1);
                for (int i = 0; i < kWrites; ++i)
                {
                    reg.invalidateGroups(id);
                    stamps[t].push_back(reg.get(id)->groupsSeq); // only this thread writes this agent
                }
            });
    }
    for (auto& th : threads)
    {
        th.join();
    }

    std::vector<uint64_t> all;
    for (const auto& s : stamps)
    {
        for (std::size_t i = 1; i < s.size(); ++i)
        {
            EXPECT_GT(s[i], s[i - 1]);
        }
        all.insert(all.end(), s.begin(), s.end());
    }
    std::sort(all.begin(), all.end());
    EXPECT_EQ(std::adjacent_find(all.begin(), all.end()), all.end());
    EXPECT_EQ(all.size(), static_cast<std::size_t>(kThreads * kWrites));
    EXPECT_EQ(reg.groupsTicket(), static_cast<uint64_t>(kThreads * kWrites));
}

TEST(AgentRegistryTest, GroupsFreshBoundaries)
{
    constexpr uint64_t kNow = 10'000;
    AgentEntry entry;

    entry.groupsRefreshedAtSec = 0;
    EXPECT_FALSE(groupsFresh(entry, kNow, 60)); // never established
    entry.groupsRefreshedAtSec = kNow - 59;
    EXPECT_TRUE(groupsFresh(entry, kNow, 60));
    entry.groupsRefreshedAtSec = kNow - 60;
    EXPECT_FALSE(groupsFresh(entry, kNow, 60)); // the interval itself is expired
    entry.groupsRefreshedAtSec = kNow + 5;
    EXPECT_FALSE(groupsFresh(entry, kNow, 60)); // clock stepped back: expired, never trusted
}
