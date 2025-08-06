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

#ifndef _PYPITEST_HPP
#define _PYPITEST_HPP

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "packagesPYPI.hpp"
#include "json.hpp"
#include <filesystem>
#include <ifile_io_utils.hpp>
#include <ifilesystem_wrapper.hpp>
#include "../../../shared_modules/file_helper/filesystem/tests/mocks/mock_filesystem_wrapper.hpp"

class MockFileIO : public IFileIOUtils
{
    public:
        MOCK_METHOD(void, readLineByLine, (const std::filesystem::path& filePath, const std::function<bool(const std::string&)>& callback), (const, override));
        MOCK_METHOD(std::string, getFileContent, (const std::string& filePath), (const, override));
        MOCK_METHOD(std::vector<char>, getBinaryContent, (const std::string& filePath), (const, override));
};

class PYPITest : public ::testing::Test
{
    protected:
        MockFileSystemWrapper* mockFileSystem; // Raw pointer - pypi will own it
        MockFileIO* mockFileIO; // Raw pointer - pypi will own it
        std::unique_ptr<PYPI> pypi;

        void SetUp() override
        {
            mockFileSystem = new MockFileSystemWrapper();
            mockFileIO = new MockFileIO();
            pypi = std::make_unique<PYPI>(std::unique_ptr<MockFileIO>(mockFileIO), std::unique_ptr<IFileSystemWrapper>(mockFileSystem));
        }

        void TearDown() override
        {
            pypi.reset(); // This will delete mockFileSystem
        }
};

#endif // _PYPITEST_HPP
