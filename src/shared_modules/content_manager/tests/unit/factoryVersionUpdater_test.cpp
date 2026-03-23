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

#include "factoryVersionUpdater_test.hpp"
#include "factoryVersionUpdater.hpp"
#include "skipStep.hpp"
#include "updateCtiApiOffset.hpp"
#include "updaterContext.hpp"
#include <memory>

/*
 * @brief Check the creation of a generic version updater.
 */
TEST_F(FactoryVersionUpdaterTest, CreateGenericVersionUpdater)
{
    // Create the config
    nlohmann::json config = {{"versionedContent", "cti-api"}};

    // Create the content version updater
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> spVersionUpdater {};
    EXPECT_NO_THROW(spVersionUpdater = FactoryVersionUpdater::create(config));

    // Check if the generic version updater is created
    EXPECT_TRUE(std::dynamic_pointer_cast<UpdateCtiApiOffset>(spVersionUpdater));
}

/*
 * @brief Check the creation of the skip step.
 */
TEST_F(FactoryVersionUpdaterTest, CreateSkipStep)
{
    // Create the config
    nlohmann::json config = {{"versionedContent", "false"}};

    // Create the content version updater
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> spVersionUpdater {};
    EXPECT_NO_THROW(spVersionUpdater = FactoryVersionUpdater::create(config));

    // Check if the skip step is created
    EXPECT_TRUE(std::dynamic_pointer_cast<SkipStep>(spVersionUpdater));
}

/*
 * @brief Check an invalid versionedContent type.
 */
TEST_F(FactoryVersionUpdaterTest, InvalidVersionedContentType)
{
    // Create the config
    nlohmann::json config = {{"versionedContent", "invalid"}};

    // Create the content version updater
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> spVersionUpdater {};
    EXPECT_THROW(spVersionUpdater = FactoryVersionUpdater::create(config), std::invalid_argument);
}
