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
#ifndef _MOCKFILEIO_HPP
#define _MOCKFILEIO_HPP

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <filesystem>

class MockFileIO
{
public:
    MOCK_METHOD(void,
                readLineByLine,
                (const std::filesystem::path&, const std::function<bool(const std::string&)>&),
                ());
};

#endif // _MOCKFILEIO_HPP
