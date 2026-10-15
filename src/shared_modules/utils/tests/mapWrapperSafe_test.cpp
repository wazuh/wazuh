/*
 * Wazuh shared modules utils
 * Copyright (C) Wazuh Inc.
 * Sep 15, 2020.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#include "mapWrapperSafe_test.h"
#include "mapWrapperSafe.h"
#include <chrono>
#include <thread>

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
