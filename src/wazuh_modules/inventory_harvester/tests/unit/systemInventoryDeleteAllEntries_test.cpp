/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * February 20, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "mockFimContext.hpp"
#include "mockSystemContext.hpp"
#include "systemInventory/deleteElement.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

class SystemInventoryDeleteAllEntries : public ::testing::Test
{
protected:
    // LCOV_EXCL_START
    SystemInventoryDeleteAllEntries() = default;
    ~SystemInventoryDeleteAllEntries() override = default;
    // LCOV_EXCL_STOP
};

TEST_F(SystemInventoryDeleteAllEntries, test)
{}
