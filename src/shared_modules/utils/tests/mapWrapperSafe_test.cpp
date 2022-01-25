/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * Sep 15, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <thread>
#include <chrono>
#include "mapWrapperSafe_test.h"
#include "mapWrapperSafe.h"


void MapWrapperSafeTest::SetUp() {};

void MapWrapperSafeTest::TearDown() {};

TEST_F(MapWrapperSafeTest, insertTest)
{
    Utils::MapWrapperSafe<int, int> mapSafe;
    mapSafe.insert(1, 2);
    EXPECT_EQ(2, mapSafe[1]);
}

TEST_F(MapWrapperSafeTest, eraseTest)
{
    Utils::MapWrapperSafe<int, int> mapSafe;
    mapSafe.insert(1, 2);
    EXPECT_NO_THROW(mapSafe.erase(1));
    EXPECT_EQ(0, mapSafe[1]);
}

