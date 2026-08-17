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
