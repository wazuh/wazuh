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

#include "cmdHelper_test.h"
#include "cmdHelper.h"

void CmdUtilsTest::SetUp() {};

void CmdUtilsTest::TearDown() {};
#ifdef WIN32
TEST_F(CmdUtilsTest, CmdVersion)
{
    const auto result {Utils::exec("ver")};
    EXPECT_FALSE(result.empty());
}
#else
TEST_F(CmdUtilsTest, CmdUname)
{
    const auto result {Utils::exec("uname")};
    EXPECT_FALSE(result.empty());
}
#endif