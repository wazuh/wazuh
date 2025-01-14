/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * February 17, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef ENCODING_WINDOWS_HELPER_TEST_H
#define ENCODING_WINDOWS_HELPER_TEST_H
#include "gtest/gtest.h"
#include "gmock/gmock.h"

class EncodingWindowsHelperTest : public ::testing::Test
{
    protected:

        EncodingWindowsHelperTest() = default;
        virtual ~EncodingWindowsHelperTest() = default;

        void SetUp() override;
        void TearDown() override;
};

#endif //ENCODING_WINDOWS_HELPER_TEST_H