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
#include "APIDownloader.hpp"
#include "S3Downloader.hpp"
#include "factoryDownloader.hpp"
#include "updaterContext.hpp"
#include <memory>

/*
 * @brief Check the creation of an APIDownloader.
 */
TEST_F(FactoryDownloaderTest, CreateAPIDownloader)
{
    // Create the config
    nlohmann::json config = {{"contentSource", "api"}};

    // Create the downloader
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> spDownloader {};
    EXPECT_NO_THROW(spDownloader = FactoryDownloader::create(config));

    // Check if the downloader is an APIDownloader
    EXPECT_TRUE(std::dynamic_pointer_cast<APIDownloader>(spDownloader));
}

/*
 * @brief Check the creation of a S3Downloader.
 */
TEST_F(FactoryDownloaderTest, CreateS3Downloader)
{
    // Create the config
    nlohmann::json config = {{"contentSource", "s3"}};

    // Create the downloader
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> spDownloader {};
    EXPECT_NO_THROW(spDownloader = FactoryDownloader::create(config));

    // Check if the downloader is a S3Downloader
    EXPECT_TRUE(std::dynamic_pointer_cast<S3Downloader>(spDownloader));
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
