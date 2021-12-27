/*
 * Wazuh Syscheck
 * Copyright (C) 2015-2021, Wazuh Inc.
 * December 27, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "fimDBUtils.hpp"
#include "fimDBUtilsTest.h"
#include <iostream>

void FIMDBUtilsTest::SetUp() {}

void FIMDBUtilsTest::TearDown() {}

TEST_F(FIMDBUtilsTest, testGetPathsFromINode)
{
    const auto paths { FimDBUtils::getPathsFromINode(1, 12) };
    EXPECT_TRUE(paths.empty());

}
