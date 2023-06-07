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

#include "factoryDecompressor_test.hpp"
#include "XZDecompressor.hpp"
#include "factoryDecompressor.hpp"
#include "skipStep.hpp"
#include "updaterContext.hpp"
#include <memory>

/*
 * @brief Check the creation of a xz decompressor.
 */
TEST_F(FactoryDecompressorTest, CreateXZDecompressor)
{
    // Create the config
    nlohmann::json config = {{"compressionType", "xz"}};

    // Create the decompressor
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> spDecompressor {};
    EXPECT_NO_THROW(spDecompressor = FactoryDecompressor::create(config));

    // Check if the decompressor is a XZDecompressor
    EXPECT_TRUE(std::dynamic_pointer_cast<XZDecompressor>(spDecompressor));
}

/*
 * @brief Check the creation of the skip step.
 */
TEST_F(FactoryDecompressorTest, CreateSkipStep)
{
    // Create the config
    nlohmann::json config = {{"compressionType", "raw"}};

    // Create the decompressor
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> spDecompressor {};
    EXPECT_NO_THROW(spDecompressor = FactoryDecompressor::create(config));

    // Check if the decompressor is a SkipStep
    EXPECT_TRUE(std::dynamic_pointer_cast<SkipStep>(spDecompressor));
}

/*
 * @brief Check an invalid compressionType type.
 */
TEST_F(FactoryDecompressorTest, InvalidCompressionType)
{
    // Create the config
    nlohmann::json config = {{"compressionType", "invalid"}};

    // Create the decompressor
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> spDecompressor {};
    EXPECT_THROW(spDecompressor = FactoryDecompressor::create(config), std::invalid_argument);
}
