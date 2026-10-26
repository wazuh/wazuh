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

#ifndef WINDOWS_HELPER_TEST_H
#define WINDOWS_HELPER_TEST_H
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <string>

class WindowsHelperTest : public ::testing::Test
{
    protected:

        WindowsHelperTest() = default;
        virtual ~WindowsHelperTest() = default;

        void SetUp() override;
        void TearDown() override;

        std::string m_timezone;
};

#endif //WINDOWS_HELPER_TEST_H