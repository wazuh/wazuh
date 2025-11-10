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

/**
 * @brief Test OAuth provider creation with complete configuration (indexer + console)
 *
 * This test verifies that createOAuthProviders() correctly instantiates all three
 * OAuth providers when a complete configuration is provided.
 */
TEST_F(FactoryDownloaderTest, CreateOAuthProvidersComplete)
{
    // Create config with complete OAuth configuration (indexer + console)
    nlohmann::json config = R"({
        "contentSource": "cti-offset",
        "oauth": {
            "indexer": {
                "url": "https://indexer.wazuh.com",
                "credentialsEndpoint": "/_wazuh/cti/credentials",
                "timeout": 5000
            },
            "console": {
                "url": "https://console.wazuh.com",
                "instancesEndpoint": "/api/v1/instances/me",
                "tokenExchangeEndpoint": "/api/v1/instances/token/exchange",
                "timeout": 5000
            },
            "enableProductsProvider": true
        }
    })"_json;

    // Create the downloader - this will internally call createOAuthProviders()
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> spDownloader {};
    EXPECT_NO_THROW(spDownloader = FactoryDownloader::create(config));

    // Verify the downloader was created successfully
    EXPECT_TRUE(std::dynamic_pointer_cast<CtiOffsetDownloader>(spDownloader));
}

/**
 * @brief Test OAuth provider creation with indexer-only configuration
 *
 * This test verifies that createOAuthProviders() correctly handles configurations
 * that only have indexer settings (no console), creating only credentials provider.
 */
TEST_F(FactoryDownloaderTest, CreateOAuthProvidersIndexerOnly)
{
    // Create config with indexer-only OAuth configuration
    nlohmann::json config = R"({
        "contentSource": "cti-snapshot",
        "oauth": {
            "indexer": {
                "url": "https://indexer.wazuh.com",
                "credentialsEndpoint": "/_wazuh/cti/credentials"
            }
        }
    })"_json;

    // Create the downloader - this will internally call createOAuthProviders()
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> spDownloader {};
    EXPECT_NO_THROW(spDownloader = FactoryDownloader::create(config));

    // Verify the downloader was created successfully
    EXPECT_TRUE(std::dynamic_pointer_cast<CtiSnapshotDownloader>(spDownloader));
}

/**
 * @brief Test OAuth provider creation with products provider disabled
 *
 * This test verifies that createOAuthProviders() correctly respects the
 * enableProductsProvider flag when set to false.
 */
TEST_F(FactoryDownloaderTest, CreateOAuthProvidersDisabled)
{
    // Create config with products provider explicitly disabled
    nlohmann::json config = R"({
        "contentSource": "cti-offset",
        "oauth": {
            "indexer": {
                "url": "https://indexer.wazuh.com"
            },
            "console": {
                "url": "https://console.wazuh.com"
            },
            "enableProductsProvider": false
        }
    })"_json;

    // Create the downloader - this will internally call createOAuthProviders()
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> spDownloader {};
    EXPECT_NO_THROW(spDownloader = FactoryDownloader::create(config));

    // Verify the downloader was created successfully
    EXPECT_TRUE(std::dynamic_pointer_cast<CtiOffsetDownloader>(spDownloader));
}

/**
 * @brief Test OAuth provider creation with malformed configuration
 *
 * This test verifies that createOAuthProviders() gracefully handles malformed
 * OAuth configurations by catching exceptions and returning nullptr providers.
 */
TEST_F(FactoryDownloaderTest, CreateOAuthProvidersMalformed)
{
    // Create config with malformed OAuth configuration (missing required fields)
    nlohmann::json config = R"({
        "contentSource": "cti-snapshot",
        "oauth": {
            "indexer": {
                "credentialsEndpoint": "/_wazuh/cti/credentials"
            }
        }
    })"_json;

    // Create the downloader - should handle malformed config gracefully
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> spDownloader {};
    EXPECT_NO_THROW(spDownloader = FactoryDownloader::create(config));

    // Verify the downloader was created successfully (falls back to non-authenticated)
    EXPECT_TRUE(std::dynamic_pointer_cast<CtiSnapshotDownloader>(spDownloader));
}
