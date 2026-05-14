/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * February 9, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ARCHIVE_HELPER_TEST_HPP
#define _ARCHIVE_HELPER_TEST_HPP

#include "gtest/gtest.h"

class ArchiveHelperTest : public ::testing::Test
{
protected:
    ArchiveHelperTest() = default;
    virtual ~ArchiveHelperTest() = default;

    void SetUp() override;
    void TearDown() override;
};

#endif // _ARCHIVE_HELPER_TEST_HPP
