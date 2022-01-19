/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * November 5, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _SYSINFO_OS_TEST_H
#define _SYSINFO_OS_TEST_H
#include "gtest/gtest.h"
#include "gmock/gmock.h"

class SysOsInfoTest : public ::testing::Test
{

    protected:

        SysOsInfoTest() = default;
        virtual ~SysOsInfoTest() = default;

        void SetUp() override;
        void TearDown() override;
};

#endif //_SYSINFO_OS_TEST_H