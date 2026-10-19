/*
 * Wazuh shared modules utils
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#include "cacheLRU_test.h"
#include "cacheLRU.hpp"

void CacheLRUTest::SetUp() {};

void CacheLRUTest::TearDown() {};

TEST_F(CacheLRUTest, insertAndHit)
{
    auto cacheMemory = LRUCache<int, int>(10);

    EXPECT_NO_THROW(cacheMemory.insertKey(1, 10));
    EXPECT_EQ(cacheMemory.getValue(1).value(), 10);
}

TEST_F(CacheLRUTest, insertAndMiss)
{
    auto cacheMemory = LRUCache<int, int>(10);

    EXPECT_NO_THROW(cacheMemory.insertKey(10, 10));
    auto result = cacheMemory.getValue(1);

    EXPECT_FALSE(result.has_value());
}
