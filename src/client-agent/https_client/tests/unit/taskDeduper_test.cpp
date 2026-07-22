/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "taskDeduper.hpp"

#include <gtest/gtest.h>

#include <chrono>

namespace
{
    // A fixed "now" for the tests that do not exercise the TTL; a long default
    // TTL keeps every id live.
    const std::chrono::steady_clock::time_point T0 {};
}

TEST(TaskDeduperTest, NewIdsAreAcceptedOnce)
{
    TaskDeduper deduper;
    EXPECT_TRUE(deduper.markIfNew("task-1", T0));
    EXPECT_FALSE(deduper.markIfNew("task-1", T0)); // Duplicate.
    EXPECT_TRUE(deduper.markIfNew("task-2", T0));
}

TEST(TaskDeduperTest, RecentIdsStayDeduped)
{
    TaskDeduper deduper {3};
    EXPECT_TRUE(deduper.markIfNew("a", T0));
    EXPECT_TRUE(deduper.markIfNew("b", T0));
    EXPECT_TRUE(deduper.markIfNew("c", T0));
    // All three still within capacity and TTL: every repeat is a duplicate.
    EXPECT_FALSE(deduper.markIfNew("a", T0));
    EXPECT_FALSE(deduper.markIfNew("b", T0));
    EXPECT_FALSE(deduper.markIfNew("c", T0));
}

TEST(TaskDeduperTest, LruEvictionAllowsReDeliveryAfterAgingOut)
{
    TaskDeduper deduper {2}; // Capacity 2; oldest ages out first.
    EXPECT_TRUE(deduper.markIfNew("a", T0));
    EXPECT_TRUE(deduper.markIfNew("b", T0));
    // "c" evicts the oldest ("a"); remembered set is now {b, c}.
    EXPECT_TRUE(deduper.markIfNew("c", T0));
    EXPECT_FALSE(deduper.markIfNew("c", T0)); // Still a duplicate.
    // "a" aged out, so a re-delivery is accepted again (at-least-once); this
    // in turn evicts "b".
    EXPECT_TRUE(deduper.markIfNew("a", T0));
    EXPECT_TRUE(deduper.markIfNew("b", T0));
}

TEST(TaskDeduperTest, ZeroCapacityIsClampedToOne)
{
    TaskDeduper deduper {0};
    EXPECT_TRUE(deduper.markIfNew("only", T0));
    EXPECT_FALSE(deduper.markIfNew("only", T0));
}

TEST(TaskDeduperTest, ExpiredIdIsAcceptedAgainAfterTtl)
{
    TaskDeduper deduper {4096, std::chrono::seconds {60}};
    EXPECT_TRUE(deduper.markIfNew("t", T0));
    EXPECT_FALSE(deduper.markIfNew("t", T0 + std::chrono::seconds {59})); // Within TTL.
    // At/after the TTL the id has expired: a re-delivery is accepted.
    EXPECT_TRUE(deduper.markIfNew("t", T0 + std::chrono::seconds {60}));
}

TEST(TaskDeduperTest, PruneEvictsOnlyTheExpiredPrefix)
{
    TaskDeduper deduper {4096, std::chrono::seconds {100}};
    deduper.markIfNew("old", T0);
    deduper.markIfNew("mid", T0 + std::chrono::seconds {50});
    // At t=120 "old" (age 120) has expired but "mid" (age 70) has not: "old"
    // is re-acceptable, "mid" is still a duplicate.
    const auto later = T0 + std::chrono::seconds {120};
    EXPECT_FALSE(deduper.markIfNew("mid", later));
    EXPECT_TRUE(deduper.markIfNew("old", later));
}

TEST(TaskDeduperTest, CapacityStillEnforcedWithinTheTtl)
{
    TaskDeduper deduper {2, std::chrono::seconds {3600}};
    EXPECT_TRUE(deduper.markIfNew("a", T0));
    EXPECT_TRUE(deduper.markIfNew("b", T0));
    EXPECT_TRUE(deduper.markIfNew("c", T0)); // Evicts "a" by capacity, not TTL.
    EXPECT_TRUE(deduper.markIfNew("a", T0));  // "a" was evicted: accepted again.
    EXPECT_FALSE(deduper.markIfNew("c", T0)); // "c" still remembered.
}
