/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 16, 2023.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */
#ifndef _MOCKJSONIO_HPP
#define _MOCKJSONIO_HPP

#include "json.hpp"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <filesystem>

class MockJsonIO
{
public:
    MOCK_METHOD(nlohmann::json, readJson, (const std::filesystem::path&), ());
};

#endif // _MOCKJSONIO_HPP
