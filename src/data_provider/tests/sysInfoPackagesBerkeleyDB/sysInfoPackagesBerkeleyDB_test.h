/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * March 16, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _SYSINFO_PACKAGES_BERKELEY_DB_TEST_H
#define _SYSINFO_PACKAGES_BERKELEY_DB_TEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"

class SysInfoPackagesBerkeleyDBTest : public ::testing::Test
{
    protected:

        SysInfoPackagesBerkeleyDBTest() = default;
        virtual ~SysInfoPackagesBerkeleyDBTest() = default;

        void SetUp() override;
        void TearDown() override;
};

#endif //_SYSINFO_PACKAGES_BERKELEY_DB_TEST_H
