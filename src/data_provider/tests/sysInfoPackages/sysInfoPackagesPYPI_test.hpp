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
#include <ifilesystem_wrapper.hpp>
#include "../shared_modules/file_helper/filesystem/mock_filesystem_wrapper.hpp"

class MockFileIO
{
public:
    MOCK_METHOD(void, readLineByLine, (const std::filesystem::path&, const std::function<bool(const std::string&)>&), ());
};

class PYPITest : public ::testing::Test
{
protected:
    MockFileSystemWrapper* mockFileSystem; // Raw pointer - pypi will own it
    std::unique_ptr<PYPI<MockFileIO>> pypi;

    void SetUp() override
    {
        mockFileSystem = new MockFileSystemWrapper();
        pypi = std::make_unique<PYPI<MockFileIO>>(std::unique_ptr<IFileSystemWrapper>(mockFileSystem));
    }

    void TearDown() override
    {
        pypi.reset(); // This will delete mockFileSystem
    }
};

#endif // _PYPITEST_HPP
