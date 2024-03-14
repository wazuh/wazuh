/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * August 10, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "rcpWrapper_test.h"
#include "packages/packageMac.h"
#include "packages/rcpWrapper.h"
#include <unistd.h>
#include <iostream>
#include <algorithm>

void RCPWrapperTest::SetUp() {};

void RCPWrapperTest::TearDown() {};

using ::testing::_;
using ::testing::Return;

TEST_F(RCPWrapperTest, Wazuh)
{
    std::string inputPath;
    inputPath += getwd(NULL);
    inputPath += "/input_files/RCPWrapperTest_Wazuh";
    std::string package { "com.apple.pkg.MRTConfigData_10_15.16U4211" };

    struct PackageContext ctx
    {
        inputPath, package, ""
    };
    std::shared_ptr<RCPWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<RCPWrapper>(ctx));
    EXPECT_EQ(wrapper->installPrefixPath(), "/");
    auto bomPaths = wrapper->bomPaths();
    EXPECT_EQ(bomPaths.size(), (size_t)1);
    EXPECT_NE(std::find(bomPaths.begin(), bomPaths.end(), "/Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist"), bomPaths.end());
}
