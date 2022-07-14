/*
 * Wazuh app - Command line helper
 * Copyright (C) 2015, Wazuh Inc.
 * June 17, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef CMDLINE_HELPER_TEST_H
#define CMDLINE_HELPER_TEST_H
#include "gtest/gtest.h"
#include "gmock/gmock.h"

class CmdLineHelperTest : public ::testing::Test
{
    protected:

        CmdLineHelperTest() = default;
        virtual ~CmdLineHelperTest() = default;

        void SetUp() override;
        void TearDown() override;
};

#endif //CMDLINE_HELPER_TEST_H