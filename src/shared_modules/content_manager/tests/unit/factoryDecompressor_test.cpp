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
#include "gzipDecompressor.hpp"
#include "json.hpp"
#include "skipStep.hpp"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include "gtest/gtest.h"
#include <memory>

/*
 * @brief Check the creation of a xz decompressor.
 */
TEST_F(FactoryDecompressorTest, CreateXZDecompressor)
{
    // Create the config
    nlohmann::json config = {{"compressionType", "xz"}, {"contentSource", "api"}};

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
    nlohmann::json config = {{"compressionType", "raw"}, {"contentSource", "api"}};

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
    nlohmann::json config = {{"compressionType", "invalid"}, {"contentSource", "api"}};

    // Create the decompressor
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> spDecompressor {};
    EXPECT_THROW(spDecompressor = FactoryDecompressor::create(config), std::invalid_argument);
}

/**
 * @brief Check the creation of a gzip decompressor.
 *
 */
TEST_F(FactoryDecompressorTest, CreateGzipDecompressor)
{
    auto config = R"({"compressionType": "gzip", "contentSource": "api"})"_json;

    // Create the decompressor.
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> spDecompressor;
    ASSERT_NO_THROW(spDecompressor = FactoryDecompressor::create(config));

    // Check decompressor type.
    EXPECT_TRUE(std::dynamic_pointer_cast<GzipDecompressor>(spDecompressor));
}

/**
 * @brief Check the deduction of the compression type of a raw file.
 *
 */
TEST_F(FactoryDecompressorTest, DeduceCompressionTypeRawFile)
{
    auto config = R"(
        {
            "contentSource": "offline",
            "url": "file:///home/user/file.txt",
            "compressionType": "ignored"
        }
    )"_json;

    const auto expectedConfig = R"(
        {
            "contentSource": "offline",
            "url": "file:///home/user/file.txt",
            "compressionType": "raw"
        }
    )"_json;

    // Create the downloader.
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> spDownloader {};

    EXPECT_NO_THROW(spDownloader = FactoryDecompressor::create(config));
    EXPECT_TRUE(std::dynamic_pointer_cast<SkipStep>(spDownloader));
    EXPECT_EQ(config, expectedConfig);
}

/**
 * @brief Check the deduction of the compression type of a compressed file.
 *
 */
TEST_F(FactoryDecompressorTest, DeduceCompressionTypeCompressedFile)
{
    auto config = R"(
        {
            "contentSource": "offline",
            "url": "file:///home/user/file.txt.gz",
            "compressionType": "ignored"
        }
    )"_json;

    const auto expectedConfig = R"(
        {
            "contentSource": "offline",
            "url": "file:///home/user/file.txt.gz",
            "compressionType": "gzip"
        }
    )"_json;

    // Create the downloader.
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> spDownloader {};

    EXPECT_NO_THROW(spDownloader = FactoryDecompressor::create(config));
    EXPECT_TRUE(std::dynamic_pointer_cast<GzipDecompressor>(spDownloader));
    EXPECT_EQ(config, expectedConfig);
}

/**
 * @brief Check the deduction of the compression type of a file wihout extension.
 *
 */
TEST_F(FactoryDecompressorTest, DeduceCompressionTypeCompressedNoExtensionFile)
{
    auto config = R"(
        {
            "contentSource": "offline",
            "url": "file:///home/user/file_without_extension",
            "compressionType": "ignored"
        }
    )"_json;

    const auto expectedConfig = R"(
        {
            "contentSource": "offline",
            "url": "file:///home/user/file_without_extension",
            "compressionType": "raw"
        }
    )"_json;

    // Create the downloader.
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> spDownloader {};

    EXPECT_NO_THROW(spDownloader = FactoryDecompressor::create(config));
    EXPECT_TRUE(std::dynamic_pointer_cast<SkipStep>(spDownloader));
    EXPECT_EQ(config, expectedConfig);
}

/**
 * @brief Check the creation of a zip decompressor.
 *
 */
TEST_F(FactoryDecompressorTest, CreateZipDecompressor)
{
    auto config = R"({"compressionType": "zip", "contentSource": "api"})"_json;

    // Create the decompressor.
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> spDecompressor;
    ASSERT_NO_THROW(spDecompressor = FactoryDecompressor::create(config));

    // Check decompressor type.
    EXPECT_TRUE(std::dynamic_pointer_cast<ZipDecompressor>(spDecompressor));
}

/**
 * @brief Check the deduction of the compression type of a zip compressed file.
 *
 */
TEST_F(FactoryDecompressorTest, DeduceZipCompressionType)
{
    auto config = R"(
        {
            "contentSource": "offline",
            "url": "file:///home/user/file.zip",
            "compressionType": "ignored"
        }
    )"_json;

    const auto expectedConfig = R"(
        {
            "contentSource": "offline",
            "url": "file:///home/user/file.zip",
            "compressionType": "zip"
        }
    )"_json;

    // Create the downloader.
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> spDownloader {};

    EXPECT_NO_THROW(spDownloader = FactoryDecompressor::create(config));
    EXPECT_TRUE(std::dynamic_pointer_cast<ZipDecompressor>(spDownloader));
    EXPECT_EQ(config, expectedConfig);
}
