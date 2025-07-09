/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * July 16, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _NPMTEST_HPP
#define _NPMTEST_HPP

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "packagesNPM.hpp"
#include "json.hpp"
#include <filesystem>
#include <ifilesystem_wrapper.hpp>

class MockFileSystemWrapper : public IFileSystemWrapper
{
public:
    MOCK_METHOD(bool, exists, (const std::filesystem::path&), (const, override));
    MOCK_METHOD(bool, is_regular_file, (const std::filesystem::path&), (const, override));
    MOCK_METHOD(bool, is_directory, (const std::filesystem::path&), (const, override));
    MOCK_METHOD(bool, is_socket, (const std::filesystem::path&), (const, override));
    MOCK_METHOD(bool, is_symlink, (const std::filesystem::path&), (const, override));
    MOCK_METHOD(std::filesystem::path, canonical, (const std::filesystem::path&), (const, override));
    MOCK_METHOD(std::vector<std::filesystem::path>, list_directory, (const std::filesystem::path&), (const, override));
    MOCK_METHOD(bool, remove, (const std::filesystem::path&), (const, override));
    MOCK_METHOD(std::uintmax_t, remove_all, (const std::filesystem::path&), (const, override));
    MOCK_METHOD(std::filesystem::path, temp_directory_path, (), (const, override));
    MOCK_METHOD(bool, create_directories, (const std::filesystem::path&), (const, override));
    MOCK_METHOD(void, rename, (const std::filesystem::path&, const std::filesystem::path&), (const, override));
    MOCK_METHOD(int, open, (const char*, int, int), (const, override));
    MOCK_METHOD(int, flock, (int, int), (const, override));
    MOCK_METHOD(int, close, (int), (const, override));
};

class MockJsonIO
{
public:
    MOCK_METHOD(nlohmann::json, readJson, (const std::filesystem::path&), ());
};

class NPMTest : public ::testing::Test
{
    protected:
        MockFileSystemWrapper* mockFileSystem; // Raw pointer - npm will own it
        std::unique_ptr<NPM<MockJsonIO>> npm;

        void SetUp() override
        {
            mockFileSystem = new MockFileSystemWrapper();
            npm = std::make_unique<NPM<MockJsonIO>>(std::unique_ptr<IFileSystemWrapper>(mockFileSystem));
        }

        void TearDown() override
        {
            npm.reset(); // This will delete mockFileSystem
        }
};



#endif // _NPMTEST_HPP
