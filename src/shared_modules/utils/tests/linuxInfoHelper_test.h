/*
 * Wazuh shared modules utils
 * Copyright (C) 2015-2021, Wazuh Inc.
 * December 10, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef LINUXPROCESS_HELPER_TESTS_H
#define LINUXPROCESS_HELPER_TESTS_H
#include "gtest/gtest.h"

class LinuxProcessHelperTest : public ::testing::Test
{
protected:

    LinuxProcessHelperTest() = default;
    virtual ~LinuxProcessHelperTest() = default;

    void SetUp() override;
    void TearDown() override;
};
#endif //LINUXPROCESS_HELPER_TESTS_H