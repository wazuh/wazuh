/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * December 28, 2020.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
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
