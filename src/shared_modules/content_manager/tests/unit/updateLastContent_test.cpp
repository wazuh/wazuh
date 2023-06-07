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

#include "updateLastContent_test.hpp"
#include "updateLastContent.hpp"
#include "updaterContext.hpp"

/*
 * @brief Tests the instantiation of the UpdateLastContent class
 */
TEST_F(UpdateLastContentTest, instantiation)
{
    // Check that the UpdateLastContent class can be instantiated
    EXPECT_NO_THROW(std::make_shared<UpdateLastContent>());
}
