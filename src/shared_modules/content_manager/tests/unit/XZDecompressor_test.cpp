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

#include "XZDecompressor_test.hpp"
#include "XZDecompressor.hpp"
#include "updaterContext.hpp"

/*
 * @brief Tests the instantiation of the ExecutionContext class
 */
TEST_F(XZDecompressorTest, instantiation)
{
    // Check that the XZDecompressor class can be instantiated
    EXPECT_NO_THROW(std::make_shared<XZDecompressor>());
}
