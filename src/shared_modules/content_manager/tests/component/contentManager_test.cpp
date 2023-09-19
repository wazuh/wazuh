/*
 * Wazuh content manager - Component Tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 26, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "contentManager_test.hpp"
#include "contentManager.hpp"

/*
 * @brief Tests singleton of the ContentModule class
 */
TEST_F(ContentModuleTest, TestSingleton)
{
    auto& contentModule = ContentModule::instance();

    EXPECT_EQ(&contentModule, &ContentModule::instance());
}

/*
 * @brief Tests singleton of the ContentModule class and start method
 */
TEST_F(ContentModuleTest, TestSingletonAndStartMethod)
{
    auto& contentModule = ContentModule::instance();

    EXPECT_EQ(&contentModule, &ContentModule::instance());

    EXPECT_NO_THROW(contentModule.start(nullptr));

    EXPECT_NO_THROW(contentModule.stop());
}
