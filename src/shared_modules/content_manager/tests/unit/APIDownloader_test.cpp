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

#include "APIDownloader_test.hpp"
#include "APIDownloader.hpp"
#include "updaterContext.hpp"

/*
 * @brief Tests the instantiation of the APIDownloader class
 */
TEST_F(APIDownloaderTest, instantiation)
{
    // Check that the APIDownloader class can be instantiated
    EXPECT_NO_THROW(std::make_shared<APIDownloader>());
}
