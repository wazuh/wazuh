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