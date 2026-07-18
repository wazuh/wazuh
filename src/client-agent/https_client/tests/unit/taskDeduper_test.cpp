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

TEST(TaskDeduperTest, NewIdsAreAcceptedOnce)
{
    TaskDeduper deduper;
    EXPECT_TRUE(deduper.markIfNew("task-1"));
    EXPECT_FALSE(deduper.markIfNew("task-1")); // Duplicate.
    EXPECT_TRUE(deduper.markIfNew("task-2"));
}

TEST(TaskDeduperTest, RecentIdsStayDeduped)
{
    TaskDeduper deduper {3};
    EXPECT_TRUE(deduper.markIfNew("a"));
    EXPECT_TRUE(deduper.markIfNew("b"));
    EXPECT_TRUE(deduper.markIfNew("c"));
    // All three still within capacity: every repeat is a duplicate.
    EXPECT_FALSE(deduper.markIfNew("a"));
    EXPECT_FALSE(deduper.markIfNew("b"));
    EXPECT_FALSE(deduper.markIfNew("c"));
}

TEST(TaskDeduperTest, LruEvictionAllowsReDeliveryAfterAgingOut)
{
    TaskDeduper deduper {2}; // Capacity 2; oldest ages out first.
    EXPECT_TRUE(deduper.markIfNew("a"));
    EXPECT_TRUE(deduper.markIfNew("b"));
    // "c" evicts the oldest ("a"); remembered set is now {b, c}.
    EXPECT_TRUE(deduper.markIfNew("c"));
    EXPECT_FALSE(deduper.markIfNew("c")); // Still a duplicate.
    // "a" aged out, so a re-delivery is accepted again (at-least-once); this
    // in turn evicts "b".
    EXPECT_TRUE(deduper.markIfNew("a"));
    EXPECT_TRUE(deduper.markIfNew("b"));
}

TEST(TaskDeduperTest, ZeroCapacityIsClampedToOne)
{
    TaskDeduper deduper {0};
    EXPECT_TRUE(deduper.markIfNew("only"));
    EXPECT_FALSE(deduper.markIfNew("only"));
}
