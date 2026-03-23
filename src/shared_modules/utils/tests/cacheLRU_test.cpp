/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * October 17, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
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
