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

#ifndef _API_DOWNLOADER_TEST_HPP
#define _API_DOWNLOADER_TEST_HPP

#include "gtest/gtest.h"

/**
 * @brief Runs unit tests for APIDownloader
 */
class APIDownloaderTest : public ::testing::Test
{
protected:
    APIDownloaderTest() = default;
    ~APIDownloaderTest() override = default;
};

#endif //_API_DOWNLOADER_TEST_HPP
