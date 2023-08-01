/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * July 20, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PKGWRAPPER_TEST_H
#define _PKGWRAPPER_TEST_H
#include "gtest/gtest.h"
#include "gmock/gmock.h"

class PKGWrapperTest : public ::testing::Test
{
    protected:
        PKGWrapperTest() = default;
        virtual ~PKGWrapperTest() = default;

        void SetUp() override;
        void TearDown() override;
};

#endif //_PKGWRAPPER_TEST_H
