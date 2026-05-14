/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * December 14, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SYSINFO_MAC_PACKAGES_TEST_H
#define _SYSINFO_MAC_PACKAGES_TEST_H
#include "gtest/gtest.h"
#include "gmock/gmock.h"

class SysInfoMacPackagesTest : public ::testing::Test
{

    protected:

        SysInfoMacPackagesTest() = default;
        virtual ~SysInfoMacPackagesTest() = default;

        void SetUp() override;
        void TearDown() override;
};

#endif //_SYSINFO_MAC_PACKAGES_TEST_H