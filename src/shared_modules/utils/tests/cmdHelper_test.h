/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * October 19, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef CMD_HELPER_TESTS_H
#define CMD_HELPER_TESTS_H
#include <gtest/gtest.h>

class CmdUtilsTest : public ::testing::Test
{
protected:
    CmdUtilsTest() = default;
    virtual ~CmdUtilsTest() = default;

    void SetUp() override;
    void TearDown() override;
};
#endif // CMD_HELPER_TESTS_H
