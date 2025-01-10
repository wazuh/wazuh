/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * December 10, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef LINUXINFO_HELPER_TESTS_H
#define LINUXINFO_HELPER_TESTS_H
#include "gtest/gtest.h"

class LinuxInfoHelperTest : public ::testing::Test
{
protected:
    LinuxInfoHelperTest() = default;
    virtual ~LinuxInfoHelperTest() = default;

    void SetUp() override;
    void TearDown() override;
};
#endif // LINUXINFO_HELPER_TESTS_H
