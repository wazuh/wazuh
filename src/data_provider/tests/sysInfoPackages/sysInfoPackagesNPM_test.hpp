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
#include "../shared_modules/file_helper/filesystem/mock_filesystem_wrapper.hpp"

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
