/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * February 17, 2020.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef ENCODING_WINDOWS_HELPER_TEST_H
#define ENCODING_WINDOWS_HELPER_TEST_H
#include "gtest/gtest.h"
#include "gmock/gmock.h"

class EncodingWindowsHelperTest : public ::testing::Test
{
    protected:

        EncodingWindowsHelperTest() = default;
        virtual ~EncodingWindowsHelperTest() = default;

        void SetUp() override;
        void TearDown() override;
};

#endif //ENCODING_WINDOWS_HELPER_TEST_H