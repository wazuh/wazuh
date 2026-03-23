/*
 * Wazuh Content Manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * December 26, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "factoryOffsetUpdater_test.hpp"
#include "chainOfResponsability.hpp"
#include "components/factoryOffsetUpdater.hpp"
#include "components/updateCtiApiOffset.hpp"
#include "components/updaterContext.hpp"
#include "json.hpp"
#include "gtest/gtest.h"
#include <memory>

/**
 * @brief Check the creation of a OffsetUpdater orchestration.
 *
 */
TEST_F(FactoryOffsetUpdaterTest, CreateOrchestration)
{
    nlohmann::json config;
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> spOffsetUpdaterChain {};
    ASSERT_NO_THROW(spOffsetUpdaterChain = FactoryOffsetUpdater::create(config));
    EXPECT_TRUE(std::dynamic_pointer_cast<UpdateCtiApiOffset>(spOffsetUpdaterChain));
}
