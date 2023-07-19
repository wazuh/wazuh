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
#include <thread>

class FilesystemUtilsTest : public ::testing::Test
{
    protected:

        FilesystemUtilsTest() = default;
        virtual ~FilesystemUtilsTest() = default;

        void SetUp() override;
        void TearDown() override;

        static void SetUpTestSuite()
        {
            std::filesystem::remove_all("/tmp/wazuh_test");
            std::filesystem::create_directory("/tmp/wazuh_test");
            std::filesystem::create_directory("/tmp/wazuh_test/prefix_1_data");
            std::filesystem::create_directory("/tmp/wazuh_test/prefix_2_data");
            std::filesystem::create_directory("/tmp/wazuh_test/dummy");
            // Create dummy file
            std::ofstream dummyFile("/tmp/wazuh_test/dummy.txt");
            dummyFile << "dummy";
            dummyFile.close();
            std::filesystem::create_directory("/tmp/wazuh_test/prefix_1_data/prefix1_1");
            std::filesystem::create_directory("/tmp/wazuh_test/prefix_1_data/prefix1_2");
            std::filesystem::create_directory("/tmp/wazuh_test/prefix_2_data/prefix2_1");
            std::filesystem::create_directory("/tmp/wazuh_test/prefix_2_data/prefix2_2");

            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
};
#endif //FILESYSTEM_HELPER_TESTS_H
