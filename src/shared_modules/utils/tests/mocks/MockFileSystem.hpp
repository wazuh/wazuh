/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 16, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MOCKFILESYSTEM_HPP
#define _MOCKFILESYSTEM_HPP

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <filesystem>

template <typename T>
class MockFileSystem
{
    public:
        MOCK_METHOD(bool, exists, (const std::filesystem::path&), ());
        MOCK_METHOD(bool, is_regular_file, (const std::filesystem::path&), ());
        MOCK_METHOD(bool, is_directory, (const std::filesystem::path&), ());
        MOCK_METHOD(T, directory_iterator, (const std::filesystem::path&), ());
};

#endif  // _MOCKFILESYSTEM_HPP
