/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * September 23, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SYSINFO_PROCESSES_MAC_TEST_H
#define _SYSINFO_PROCESSES_MAC_TEST_H
#include "gtest/gtest.h"

class SysInfoProcessesMacTest : public ::testing::Test
{
    protected:
        SysInfoProcessesMacTest() = default;
        virtual ~SysInfoProcessesMacTest() = default;
};

#endif //_SYSINFO_PROCESSES_MAC_TEST_H
