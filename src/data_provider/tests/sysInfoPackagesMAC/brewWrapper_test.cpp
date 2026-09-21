/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * September 21, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>

#include "packages/packageMac.h"
#include "packages/brewWrapper.h"

#include <limits.h>
#include <memory>
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
}

// The keg holds bin/examplepkg (100 bytes) and README (50 bytes), 150 bytes total.
// See src/data_provider/tests/sysInfoPackagesMAC/input_files/Cellar/examplepkg/1.2.3.
TEST(BrewWrapperTest, SizeIsSummedFromKegDirectory)
{
    const std::string cellarPath { currentWorkingDirectory() + "/input_files/Cellar" };
    PackageContext ctx { cellarPath, "examplepkg", "1.2.3" };

    std::shared_ptr<BrewWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<BrewWrapper>(ctx));
    EXPECT_EQ(wrapper->name(), "examplepkg");
    EXPECT_EQ(wrapper->size(), 150);
}

TEST(BrewWrapperTest, SizeIsZeroWhenKegDirectoryIsMissing)
{
    const std::string cellarPath { currentWorkingDirectory() + "/input_files/Cellar" };
    PackageContext ctx { cellarPath, "does-not-exist", "9.9.9" };

    std::shared_ptr<BrewWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<BrewWrapper>(ctx));
    EXPECT_EQ(wrapper->size(), 0);
}
