/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * August 10, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _RCPWRAPPER_TEST_H
#define _RCPWRAPPER_TEST_H
#include "gtest/gtest.h"
#include "gmock/gmock.h"

class RCPWrapperTest : public ::testing::Test
{
    protected:
        RCPWrapperTest() = default;
        virtual ~RCPWrapperTest() = default;

        void SetUp() override;
        void TearDown() override;
};

#endif //_RCPWRAPPER_TEST_H
