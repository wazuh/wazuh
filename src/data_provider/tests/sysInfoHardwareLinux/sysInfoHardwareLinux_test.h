/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * October 9, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _SYSINFO_HARDWARE_LINUX_TEST_H
#define _SYSINFO_HARDWARE_LINUX_TEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"

class SysInfoHardwareLinuxTest : public ::testing::Test
{
    protected:

        SysInfoHardwareLinuxTest() = default;
        virtual ~SysInfoHardwareLinuxTest() = default;

        void SetUp() override;
        void TearDown() override;
};

#endif //_SYSINFO_HARDWARE_LINUX_TEST_H
