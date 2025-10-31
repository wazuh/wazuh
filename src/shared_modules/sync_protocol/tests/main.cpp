/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <cstdlib>

// Global test environment to ensure var/run directory exists
class GlobalTestEnvironment : public ::testing::Environment
{
public:
    void SetUp() override
    {
        // Create var/run directory before any tests run
        // This ensures the metadata provider shared memory file can be created
        std::system("mkdir -p var/run 2>/dev/null");
    }
};

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::AddGlobalTestEnvironment(new GlobalTestEnvironment);
    return RUN_ALL_TESTS();
}
