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
#include "gtest/gtest.h"
#include "filesystemHelper.h"
#include "stdFileSystemHelper.hpp"
#include <algorithm>
#include <deque>
#include <filesystem>
#include <fstream>
#ifndef WIN32
#include "scopedTestDirectory.hpp"
#include <cerrno>
#include <unistd.h>
#endif
#ifdef __linux__
#include <linux/magic.h>
#endif
#include <vector>
#include <thread>

class FilesystemUtilsTest : public ::testing::Test
{
    protected:

        FilesystemUtilsTest() = default;
        virtual ~FilesystemUtilsTest() = default;

        void SetUp() override;
        void TearDown() override;
};
#endif //FILESYSTEM_HELPER_TESTS_H
