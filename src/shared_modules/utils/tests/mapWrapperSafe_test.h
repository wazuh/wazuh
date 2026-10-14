/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * Sep 15, 2020.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef MAP_WRAPPER_SAFE_TESTS_H
#define MAP_WRAPPER_SAFE_TESTS_H
#include "gtest/gtest.h"
#include "gmock/gmock.h"

class MapWrapperSafeTest : public ::testing::Test
{
    protected:

        MapWrapperSafeTest() = default;
        virtual ~MapWrapperSafeTest() = default;

        void SetUp() override;
        void TearDown() override;
};
#endif //MAP_WRAPPER_SAFE_TESTS_H