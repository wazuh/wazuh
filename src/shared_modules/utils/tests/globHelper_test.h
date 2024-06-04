/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * Agoust 11, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _GLOB_HELPER_TEST_H
#define _GLOB_HELPER_TEST_H
#include "gtest/gtest.h"

class GlobHelperTest : public ::testing::Test
{
    protected:

        GlobHelperTest() = default;
        virtual ~GlobHelperTest() = default;

        void SetUp() override;
        void TearDown() override;
};
#endif // _GLOB_HELPER_TEST_H
