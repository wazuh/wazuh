/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * September 24, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "gtest/gtest.h"
#include "packages/packageMac.h"
#include "packages/brewWrapper.h"
#include <limits.h>
#include <stdexcept>
#include <string>
#include <unistd.h>

namespace
{
    std::string currentWorkingDirectory()
    {
        char path[PATH_MAX];

        if (::getcwd(path, sizeof(path)) == nullptr)
        {
            throw std::runtime_error("getcwd failed");
        }

        return path;
    }
} // namespace

// Fixture under input_files/Cellar/testpkg/1.0.0/: bin/tool (100 bytes) + lib/data.bin (250 bytes) = 350 bytes.
TEST(BrewWrapperTest, SizeSumsKegDirectory)
{
    const std::string cellarPath {currentWorkingDirectory() + "/input_files/Cellar"};
    const PackageContext ctx {cellarPath, "testpkg", "1.0.0"};

    std::shared_ptr<BrewWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<BrewWrapper>(ctx));
    EXPECT_EQ(wrapper->size(), 350);
}

TEST(BrewWrapperTest, SizeIsZeroWhenKegIsMissing)
{
    const std::string cellarPath {currentWorkingDirectory() + "/input_files/Cellar"};
    const PackageContext ctx {cellarPath, "does_not_exist", "0.0.0"};

    std::shared_ptr<BrewWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<BrewWrapper>(ctx));
    EXPECT_EQ(wrapper->size(), 0);
}
