/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * September 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _SYSINFO_PROCESS_MAC_TEST_H
#define _SYSINFO_PROCESS_MAC_TEST_H

#include "gtest/gtest.h"

class SysInfoProcessMacTest : public ::testing::Test
{
    protected:
        SysInfoProcessMacTest() = default;
        virtual ~SysInfoProcessMacTest() = default;
};

#endif //_SYSINFO_PROCESS_MAC_TEST_H
