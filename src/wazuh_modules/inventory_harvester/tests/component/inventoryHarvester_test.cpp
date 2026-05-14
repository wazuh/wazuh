/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * March 9, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

class InventoryHarvesterComponent : public ::testing::Test
{
protected:
    // LCOV_EXCL_START
    InventoryHarvesterComponent() = default;
    ~InventoryHarvesterComponent() override = default;
    // LCOV_EXCL_STOP
};

TEST_F(InventoryHarvesterComponent, empty)
{
    EXPECT_EQ(1, 1);
}
