/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * October 23, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef FILESYSTEM_HELPER_TESTS_H
#define FILESYSTEM_HELPER_TESTS_H
#include "filesystemHelper.h"
#include "gtest/gtest.h"
#include <thread>

class FilesystemUtilsTest : public ::testing::Test
{
protected:
    FilesystemUtilsTest() = default;
    virtual ~FilesystemUtilsTest() = default;

    void SetUp() override;
    void TearDown() override;
};
#endif // FILESYSTEM_HELPER_TESTS_H
