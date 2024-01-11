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

#ifndef _FACTORY_DOWNLOADER_TEST_HPP
#define _FACTORY_DOWNLOADER_TEST_HPP

#include "gtest/gtest.h"

/**
 * @brief Runs unit tests for FactoryDownloader
 */
class FactoryDownloaderTest : public ::testing::Test
{
protected:
    FactoryDownloaderTest() = default;
    ~FactoryDownloaderTest() override = default;
};

#endif //_FACTORY_DOWNLOADER_TEST_HPP
