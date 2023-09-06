/*
 * Wazuh router - Interface tests
 * Copyright (C) 2015, Wazuh Inc.
 * Apr 29, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "interface_c_module_test.hpp"
#include "router.h"

TEST(RouterModuleCInterfaceTest, TestInitialize)
{
    EXPECT_EQ(router_initialize(
                  [](const modules_log_level_t level, const char* log, const char* tag)
                  {
                      std::ignore = level;
                      std::ignore = log;
                      std::ignore = tag;
                  }),
              0);
}

TEST(RouterModuleCInterfaceTest, TestInitializeAndDestroy)
{
    EXPECT_EQ(router_start(), 0);
    EXPECT_EQ(router_stop(), 0);
}

TEST(RouterModuleCInterfaceTest, TestDoubleInitialize)
{
    EXPECT_EQ(router_start(), 0);
    EXPECT_NE(router_start(), 0);
    EXPECT_EQ(router_stop(), 0);
}

TEST(RouterModuleCInterfaceTest, TestDoubleDestroy)
{
    EXPECT_EQ(router_start(), 0);
    EXPECT_EQ(router_stop(), 0);
    EXPECT_NE(router_stop(), 0);
}
