/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 08, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "S3Downloader_test.hpp"
#include "S3Downloader.hpp"
#include "updaterContext.hpp"

/*
 * @brief Tests the instantiation of the S3Downloader class
 */
TEST_F(S3DownloaderTest, instantiation)
{
    // Check that the S3Downloader class can be instantiated
    EXPECT_NO_THROW(std::make_shared<S3Downloader>());
}
