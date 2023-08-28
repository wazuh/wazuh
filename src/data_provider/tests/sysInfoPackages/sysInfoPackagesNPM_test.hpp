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
#include "MockFileSystem.hpp"
#include "MockJsonIO.hpp"
#include "packagesNPM.hpp"

class NPMTest : public ::testing::Test
{
    protected:
        std::unique_ptr<NPM<MockFileSystem<std::vector<std::filesystem::path>>, MockJsonIO>> npm;

        void SetUp() override
        {
            npm = std::make_unique<NPM<MockFileSystem<std::vector<std::filesystem::path>>, MockJsonIO>>();
        }

        void TearDown() override
        {
            npm.reset();
        }
};



#endif // _NPMTEST_HPP
