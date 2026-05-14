/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * January 12, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SYSINFO_SOLARIS_PACKAGES_TEST_H
#define _SYSINFO_SOLARIS_PACKAGES_TEST_H
#include "gtest/gtest.h"
#include "gmock/gmock.h"

class SysInfoSolarisPackagesTest : public ::testing::Test
{

    protected:

        SysInfoSolarisPackagesTest() = default;
        virtual ~SysInfoSolarisPackagesTest() = default;

        void SetUp() override;
        void TearDown() override;
};

#endif //_SYSINFO_SOLARIS_PACKAGES_TEST_H
