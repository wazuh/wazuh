/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * October 19, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "cmdHelper_test.h"
#include "cmdHelper.h"

void CmdUtilsTest::SetUp() {};

void CmdUtilsTest::TearDown() {};
#ifdef WIN32
TEST_F(CmdUtilsTest, CmdVersion)
{
    const auto result{Utils::exec("ver")};
    EXPECT_FALSE(result.empty());
}
#else
TEST_F(CmdUtilsTest, CmdUname)
{
    const auto result{Utils::exec("uname")};
    EXPECT_FALSE(result.empty());
}
#endif