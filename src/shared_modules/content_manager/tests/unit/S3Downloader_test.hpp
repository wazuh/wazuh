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

#ifndef _S3_DOWNLOADER_TEST_HPP
#define _S3_DOWNLOADER_TEST_HPP

#include "gtest/gtest.h"

/**
 * @brief Runs unit tests for S3Downloader
 */
class S3DownloaderTest : public ::testing::Test
{
protected:
    S3DownloaderTest() = default;
    ~S3DownloaderTest() override = default;
};

#endif //_S3_DOWNLOADER_TEST_HPP
