/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * August 27, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SYSINFO_RPM_DB_READERS_TEST_H
#define _SYSINFO_RPM_DB_READERS_TEST_H

#include "gmock/gmock.h"
#include "gtest/gtest.h"

class SysInfoRpmDbReadersTest : public ::testing::Test
{
    protected:

        SysInfoRpmDbReadersTest() = default;
        virtual ~SysInfoRpmDbReadersTest() = default;

        void SetUp() override;
        void TearDown() override;
};

#endif // _SYSINFO_RPM_DB_READERS_TEST_H
