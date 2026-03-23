/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * May 18, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SYSINFO_HARDWARE_WRAPPER_ARM_MAC_TEST_H
#define _SYSINFO_HARDWARE_WRAPPER_ARM_MAC_TEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"

class SysInfoHardwareWrapperARMMacTest : public ::testing::Test
{
    protected:
        SysInfoHardwareWrapperARMMacTest() = default;
        virtual ~SysInfoHardwareWrapperARMMacTest() = default;

        void SetUp() override;
        void TearDown() override;
};

#endif //_SYSINFO_HARDWARE_WRAPPER_ARM_MAC_TEST_H
