/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 07, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "factoryCleaner_test.hpp"
#include "cleanUpContent.hpp"
#include "factoryCleaner.hpp"
#include "skipStep.hpp"
#include "updaterContext.hpp"
#include <memory>

/*
 * @brief Check the creation of the content cleaner.
 */
TEST_F(FactoryCleanerTest, CreateCleaner)
{
    // Create the config
    nlohmann::json config = {{"deleteDownloadedContent", true}};

    // Create the content cleaner
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> spCleaner {};
    EXPECT_NO_THROW(spCleaner = FactoryCleaner::create(config));

    // Check if the content cleaner is created
    EXPECT_TRUE(std::dynamic_pointer_cast<CleanUpContent>(spCleaner));
}

/*
 * @brief Check the creation of the skip step.
 */
TEST_F(FactoryCleanerTest, CreateSkipStep)
{
    // Create the config
    nlohmann::json config = {{"deleteDownloadedContent", false}};

    // Create the content cleaner
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> spCleaner {};
    EXPECT_NO_THROW(spCleaner = FactoryCleaner::create(config));

    // Check if the skip step is created
    EXPECT_TRUE(std::dynamic_pointer_cast<SkipStep>(spCleaner));
}
