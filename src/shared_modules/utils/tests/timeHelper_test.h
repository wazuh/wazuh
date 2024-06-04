/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * December 28, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef TIME_HELPER_TESTS_H
#define TIME_HELPER_TESTS_H

#include <gtest/gtest.h>

class TimeUtilsTest : public ::testing::Test
{
    protected:

        TimeUtilsTest() = default;
        virtual ~TimeUtilsTest() = default;

        void SetUp() override;
        void TearDown() override;
};

#endif // TIME_HELPER_TESTS_H
