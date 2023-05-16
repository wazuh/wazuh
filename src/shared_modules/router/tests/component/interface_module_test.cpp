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
        routerModule.initialize(nullptr);
        routerModule.destroy();
    });
}

TEST(RouterModuleInterfaceTest, TestDoubleInitialize)
{
    auto& routerModule = RouterModule::instance();
    EXPECT_NO_THROW({ routerModule.initialize(nullptr); });

    EXPECT_THROW({ routerModule.initialize(nullptr); }, std::runtime_error);

    EXPECT_NO_THROW({ routerModule.destroy(); });
}

TEST(RouterModuleInterfaceTest, TestDoubleDestroy)
{
    auto& routerModule = RouterModule::instance();
    EXPECT_NO_THROW({
        routerModule.initialize(nullptr);
        routerModule.destroy();
    });

    EXPECT_THROW({ routerModule.destroy(); }, std::runtime_error);
}
