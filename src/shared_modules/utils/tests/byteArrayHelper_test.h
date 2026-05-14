/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * March 16, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef BYTE_ARRAY_TESTS_H
#define BYTE_ARRAY_TESTS_H
#include "gtest/gtest.h"

class ByteArrayHelperTest : public ::testing::Test
{
    protected:

        ByteArrayHelperTest() = default;
        virtual ~ByteArrayHelperTest() = default;

        void SetUp() override;
        void TearDown() override;
};
#endif //BYTE_ARRAY_TESTS_H
