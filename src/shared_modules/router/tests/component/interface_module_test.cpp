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

#include "interface_module_test.hpp"
#include "routerModule.hpp"

TEST(RouterModuleInterfaceTest, TestSingleton)
{
    auto& routerModule = RouterModule::instance();
    EXPECT_EQ(&routerModule, &RouterModule::instance());
}

TEST(RouterModuleInterfaceTest, TestInitializeAndDestroy)
{
    auto& routerModule = RouterModule::instance();
    EXPECT_NO_THROW({
        routerModule.start();
        routerModule.stop();
    });
}

TEST(RouterModuleInterfaceTest, TestDoubleInitialize)
{
    auto& routerModule = RouterModule::instance();
    EXPECT_NO_THROW({ routerModule.start(); });

    EXPECT_THROW({ routerModule.start(); }, std::runtime_error);

    EXPECT_NO_THROW({ routerModule.stop(); });
}

TEST(RouterModuleInterfaceTest, TestDoubleDestroy)
{
    auto& routerModule = RouterModule::instance();
    EXPECT_NO_THROW({
        routerModule.start();
        routerModule.stop();
    });

    EXPECT_THROW({ routerModule.stop(); }, std::runtime_error);
}
