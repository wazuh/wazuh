/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * November 7, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SYSINFO_NETWORK_WINDOWS_TEST_H
#define _SYSINFO_NETWORK_WINDOWS_TEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"

class SysInfoNetworkWindowsTest : public ::testing::Test
{
    protected:

        SysInfoNetworkWindowsTest() = default;
        virtual ~SysInfoNetworkWindowsTest() = default;

        void SetUp() override;
        void TearDown() override;
};

#endif //_SYSINFO_NETWORK_WINDOWS_TEST_H