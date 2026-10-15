/*
 * Wazuh shared modules utils
 * Copyright (C) Wazuh Inc.
 * October 19, 2020.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef CMD_HELPER_TESTS_H
#define CMD_HELPER_TESTS_H
#include <gtest/gtest.h>

class CmdUtilsTest : public ::testing::Test
{
    protected:

        CmdUtilsTest() = default;
        virtual ~CmdUtilsTest() = default;

        void SetUp() override;
        void TearDown() override;
};
#endif //CMD_HELPER_TESTS_H
