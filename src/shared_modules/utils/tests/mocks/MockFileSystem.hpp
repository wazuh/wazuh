/*
 * Wazuh shared modules utils
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _MOCKFILESYSTEM_HPP
#define _MOCKFILESYSTEM_HPP

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <filesystem>

template<typename T>
class MockFileSystem
{
public:
    MOCK_METHOD(bool, exists, (const std::filesystem::path&), ());
    MOCK_METHOD(bool, is_regular_file, (const std::filesystem::path&), ());
    MOCK_METHOD(bool, is_directory, (const std::filesystem::path&), ());
    MOCK_METHOD(T, directory_iterator, (const std::filesystem::path&), ());
};

#endif // _MOCKFILESYSTEM_HPP
