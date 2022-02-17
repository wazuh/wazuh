/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * November 10, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WINDOWS_HELPER_TEST_H
#define WINDOWS_HELPER_TEST_H
#include "gtest/gtest.h"
#include "gmock/gmock.h"

class WindowsHelperTest : public ::testing::Test
{
    protected:

        WindowsHelperTest() = default;
        virtual ~WindowsHelperTest() = default;

        void SetUp() override;
        void TearDown() override;
};

#endif //WINDOWS_HELPER_TEST_H