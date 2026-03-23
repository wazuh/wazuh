/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * December 17, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _SYSINFO_PACKAGES_LINUX_PARSER_RPM_TEST_H
#define _SYSINFO_PACKAGES_LINUX_PARSER_RPM_TEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"

class SysInfoPackagesLinuxParserRPMTest : public ::testing::Test
{
    protected:

        SysInfoPackagesLinuxParserRPMTest() = default;
        virtual ~SysInfoPackagesLinuxParserRPMTest() = default;

        void SetUp() override;
        void TearDown() override;
};

#endif //_SYSINFO_PACKAGES_LINUX_PARSER_RPM_TEST_H
