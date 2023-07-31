/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 23, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _STD_FILESYSTEM_HELPER_TESTS_HPP
#define _STD_FILESYSTEM_HELPER_TESTS_HPP

#include "gtest/gtest.h"
#include "stdFileSystemHelper.hpp"
#include <filesystem>
#include <fstream>
#include <thread>

constexpr auto FS_MS_WAIT_TIME
{
    50ull
};

class StdFileSystemHelperTest : public ::testing::Test
{
    protected:

        StdFileSystemHelperTest() = default;
        virtual ~StdFileSystemHelperTest() = default;

        void SetUp() override;
        void TearDown() override;

        static void SetUpTestSuite()
        {
            std::filesystem::remove_all("/tmp/wazuh_test");

            while (std::filesystem::exists("/tmp/wazuh_test"))
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(FS_MS_WAIT_TIME));
            }

            std::filesystem::create_directory("/tmp/wazuh_test");
            std::filesystem::create_directory("/tmp/wazuh_test/prefix_1_data");
            std::filesystem::create_directory("/tmp/wazuh_test/prefix_2_data");
            std::filesystem::create_directory("/tmp/wazuh_test/dummy");

            while (!std::filesystem::exists("/tmp/wazuh_test/prefix_1_data") ||
                    !std::filesystem::exists("/tmp/wazuh_test/prefix_2_data") ||
                    !std::filesystem::exists("/tmp/wazuh_test/dummy"))
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(FS_MS_WAIT_TIME));
            }

            // Create dummy file
            std::ofstream dummyFile("/tmp/wazuh_test/dummy.txt");
            dummyFile << "dummy";
            dummyFile.close();

            std::filesystem::create_directory("/tmp/wazuh_test/prefix_1_data/prefix1_1");
            std::filesystem::create_directory("/tmp/wazuh_test/prefix_1_data/prefix1_2");
            std::filesystem::create_directory("/tmp/wazuh_test/prefix_2_data/prefix2_1");
            std::filesystem::create_directory("/tmp/wazuh_test/prefix_2_data/prefix2_2");

            while (!std::filesystem::exists("/tmp/wazuh_test/prefix_1_data/prefix1_1"))
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(FS_MS_WAIT_TIME));
            }
        }
};
#endif //_STD_FILESYSTEM_HELPER_TESTS_HPP
