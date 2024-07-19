/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 09, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "factoryDownloader_test.hpp"
#include "CtiOffsetDownloader.hpp"
#include "chainOfResponsability.hpp"
#include "factoryDownloader.hpp"
#include "fileDownloader.hpp"
#include "json.hpp"
#include "offlineDownloader.hpp"
#include "updaterContext.hpp"
#include "gtest/gtest.h"
#include <memory>

/**
 * @brief Check the creation of a CtiOffsetDownloader.
 */
TEST_F(FactoryDownloaderTest, CreateCtiOffsetDownloader)
{
    // Create the config
    nlohmann::json config = {{"contentSource", "cti-offset"}};

    // Create the downloader
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> spDownloader {};
    EXPECT_NO_THROW(spDownloader = FactoryDownloader::create(config));

    // Check if the downloader is a CtiOffsetDownloader
    EXPECT_TRUE(std::dynamic_pointer_cast<CtiOffsetDownloader>(spDownloader));
}

/**
 * @brief Check the creation of a CtiSnapshotDownloader.
 *
 */
TEST_F(FactoryDownloaderTest, CreateCtiSnapshotDownloader)
{
    // Create the config
    const auto config = R"({"contentSource":"cti-snapshot"})"_json;

    // Create the downloader.
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> spDownloader {};
    ASSERT_NO_THROW(spDownloader = FactoryDownloader::create(config));
    EXPECT_TRUE(std::dynamic_pointer_cast<CtiSnapshotDownloader>(spDownloader));
}

/**
 * @brief Check the creation of a FileDownloader.
 *
 */
TEST_F(FactoryDownloaderTest, CreateFileDownloader)
{
    // Create the config
    nlohmann::json config = {{"contentSource", "file"}};

    // Create the downloader
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> spDownloader {};
    EXPECT_NO_THROW(spDownloader = FactoryDownloader::create(config));

    // Check if the downloader is a FileDownloader
    EXPECT_TRUE(std::dynamic_pointer_cast<FileDownloader>(spDownloader));
}

/**
 * @brief Check the creation of a OfflineDownloader.
 *
 */
TEST_F(FactoryDownloaderTest, CreateOfflineDownloader)
{
    auto config = R"({"contentSource":"offline"})"_json;

    // Create the downloader.
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> spDownloader {};
    EXPECT_NO_THROW(spDownloader = FactoryDownloader::create(config));

    EXPECT_TRUE(std::dynamic_pointer_cast<OfflineDownloader>(spDownloader));
}

/*
 * @brief Check an invalid contentSource type.
 */
TEST_F(FactoryDownloaderTest, InvalidContentSource)
{
    // Create the config
    nlohmann::json config = {{"contentSource", "invalid"}};

    // Create the downloader
    EXPECT_THROW(FactoryDownloader::create(config), std::invalid_argument);
}
