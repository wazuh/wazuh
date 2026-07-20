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

#include "stdFileSystemHelper.hpp"
#include "gtest/gtest.h"
#include <filesystem>
#include <fstream>
#include <thread>
#include <unordered_map>

constexpr auto FS_MS_WAIT_TIME {50ull};

#ifndef _WIN32
constexpr auto EXPAND_PATH_1 {"/tmp/wazuh_test/prefix_1_data/prefix1_1"};
constexpr auto EXPAND_PATH_2 {"/tmp/wazuh_test/prefix_1_data/prefix1_2"};
constexpr auto EXPAND_PATH_3 {"/tmp/wazuh_test/prefix_2_data/prefix2_1"};
constexpr auto EXPAND_PATH_4 {"/tmp/wazuh_test/prefix_2_data/prefix2_2"};
constexpr auto EXPAND_PATH_5 {"/tmp/wazuh_test/dummy"};
constexpr auto EXPAND_PATH_6 {"/tmp/wazuh_test/dummy.txt"};
constexpr auto PATH_TO_EXPAND_1 {"/tmp/wazuh_test/dum*"};
constexpr auto PATH_TO_EXPAND_2 {"/tmp/wazuh_test/prefix_*_data/*"};
constexpr auto PATH_TO_EXPAND_3 {"/tmp/wazuh_test/prefix_*_data/prefix*"};
constexpr auto PATH_TO_EXPAND_4 {"/tmp/wazuh_test/prefix_*_data/*_1"};
constexpr auto PATH_TO_EXPAND_5 {"/tmp/wazuh_test/prefix_?_data/*_1"};
constexpr auto PATH_TO_EXPAND_6 {"/tmp/wazuh_test/prefix_*_data/prefix?*1"};
constexpr auto TMP_PATH {"/tmp"};
constexpr auto ROOT_PATH {"/tmp/wazuh_test"};
constexpr auto ROOT_PATH_1 {"/tmp/wazuh_test/prefix_1_data"};
constexpr auto ROOT_PATH_2 {"/tmp/wazuh_test/prefix_2_data"};
constexpr auto ROOT_PATH_DUMMY {"/tmp/wazuh_test/dummy"};
constexpr auto DUMMY_FILE {"/tmp/wazuh_test/dummy.txt"};
#else
constexpr auto EXPAND_PATH_1 {"C:\\tmp\\wazuh_test\\prefix_1_data\\prefix1_1"};
constexpr auto EXPAND_PATH_2 {"C:\\tmp\\wazuh_test\\prefix_1_data\\prefix1_2"};
constexpr auto EXPAND_PATH_3 {"C:\\tmp\\wazuh_test\\prefix_2_data\\prefix2_1"};
constexpr auto EXPAND_PATH_4 {"C:\\tmp\\wazuh_test\\prefix_2_data\\prefix2_2"};
constexpr auto EXPAND_PATH_5 {"C:\\tmp\\wazuh_test\\dummy"};
constexpr auto EXPAND_PATH_6 {"C:\\tmp\\wazuh_test\\dummy.txt"};
constexpr auto PATH_TO_EXPAND_1 {"C:\\tmp\\wazuh_test\\dum*"};
constexpr auto PATH_TO_EXPAND_2 {"C:\\tmp\\wazuh_test\\prefix_*_data\\*"};
constexpr auto PATH_TO_EXPAND_3 {"C:\\tmp\\wazuh_test\\prefix_*_data\\prefix*"};
constexpr auto PATH_TO_EXPAND_4 {"C:\\tmp\\wazuh_test\\prefix_*_data\\*_1"};
constexpr auto PATH_TO_EXPAND_5 {"C:\\tmp\\wazuh_test\\prefix_?_data\\*_1"};
constexpr auto PATH_TO_EXPAND_6 {"C:\\tmp\\wazuh_test\\prefix_*_data\\prefix?*1"};
constexpr auto TMP_PATH {"C:\\tmp"};
constexpr auto ROOT_PATH {"C:\\tmp\\wazuh_test"};
constexpr auto ROOT_PATH_1 {"C:\\tmp\\wazuh_test\\prefix_1_data"};
constexpr auto ROOT_PATH_2 {"C:\\tmp\\wazuh_test\\prefix_2_data"};
constexpr auto ROOT_PATH_DUMMY {"C:\\tmp\\wazuh_test\\dummy"};
constexpr auto DUMMY_FILE {"C:\\tmp\\wazuh_test\\dummy.txt"};
#endif

constexpr auto ITERATION_LIMIT {10u};

class StdFileSystemHelperTest : public ::testing::Test
{
protected:
    StdFileSystemHelperTest() = default;
    virtual ~StdFileSystemHelperTest() = default;

    void SetUp() override;
    void TearDown() override;

    static void TearDownTestSuite()
    {
        std::filesystem::remove_all(ROOT_PATH);
        auto iteration {0u};

        while (std::filesystem::exists(ROOT_PATH))
        {
            if (iteration++ > ITERATION_LIMIT)
            {
                FAIL() << "Unable to remove " << ROOT_PATH;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(FS_MS_WAIT_TIME));
        }
    }

    static void SetUpTestSuite()
    {
        auto iteration {0u};
        std::filesystem::remove_all(ROOT_PATH);

        while (std::filesystem::exists(ROOT_PATH))
        {
            if (iteration++ > ITERATION_LIMIT)
            {
                FAIL() << "Unable to remove " << ROOT_PATH;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(FS_MS_WAIT_TIME));
        }

        std::filesystem::create_directory(TMP_PATH);

        iteration = 0u;

        while (!std::filesystem::exists(TMP_PATH))
        {
            if (iteration++ > ITERATION_LIMIT)
            {
                FAIL() << "Unable to create " << TMP_PATH;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(FS_MS_WAIT_TIME));
        }

        std::filesystem::create_directory(ROOT_PATH);

        iteration = 0u;

        while (!std::filesystem::exists(ROOT_PATH))
        {
            if (iteration++ > ITERATION_LIMIT)
            {
                FAIL() << "Unable to create " << ROOT_PATH;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(FS_MS_WAIT_TIME));
        }

        std::filesystem::create_directory(ROOT_PATH_1);
        std::filesystem::create_directory(ROOT_PATH_2);
        std::filesystem::create_directory(ROOT_PATH_DUMMY);

        iteration = 0u;

        while (!std::filesystem::exists(ROOT_PATH_1) || !std::filesystem::exists(ROOT_PATH_2) ||
               !std::filesystem::exists(ROOT_PATH_DUMMY))
        {
            if (iteration++ > ITERATION_LIMIT)
            {
                FAIL() << "Unable to create " << ROOT_PATH_1 << " or " << ROOT_PATH_2 << " or " << ROOT_PATH_DUMMY;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(FS_MS_WAIT_TIME));
        }

        // Create dummy file
        std::ofstream dummyFile(DUMMY_FILE);
        dummyFile << "dummy";
        dummyFile.close();

        std::filesystem::create_directory(EXPAND_PATH_1);
        std::filesystem::create_directory(EXPAND_PATH_2);
        std::filesystem::create_directory(EXPAND_PATH_3);
        std::filesystem::create_directory(EXPAND_PATH_4);

        iteration = 0u;

        while (!std::filesystem::exists(EXPAND_PATH_1) || !std::filesystem::exists(EXPAND_PATH_2) ||
               !std::filesystem::exists(EXPAND_PATH_3) || !std::filesystem::exists(EXPAND_PATH_4))
        {
            if (iteration++ > ITERATION_LIMIT)
            {
                FAIL() << "Unable to create " << EXPAND_PATH_1 << " or " << EXPAND_PATH_2 << " or " << EXPAND_PATH_3
                       << " or " << EXPAND_PATH_4;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(FS_MS_WAIT_TIME));
        }
    }
};
#endif //_STD_FILESYSTEM_HELPER_TESTS_HPP
