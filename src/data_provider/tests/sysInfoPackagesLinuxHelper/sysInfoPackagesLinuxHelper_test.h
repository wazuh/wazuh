/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * January 28, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _SYSINFO_PACKAGES_LINUX_HELPER_TEST_H
#define _SYSINFO_PACKAGES_LINUX_HELPER_TEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"

class SysInfoPackagesLinuxHelperTest : public ::testing::Test
{
    protected:

        SysInfoPackagesLinuxHelperTest() = default;
        virtual ~SysInfoPackagesLinuxHelperTest() = default;

        void SetUp() override;
        void TearDown() override;
};

#endif //_SYSINFO_PACKAGES_LINUX_HELPER_TEST_H