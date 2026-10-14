/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * March 16, 2021.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef BYTE_ARRAY_TESTS_H
#define BYTE_ARRAY_TESTS_H
#include "gtest/gtest.h"

class ByteArrayHelperTest : public ::testing::Test
{
    protected:

        ByteArrayHelperTest() = default;
        virtual ~ByteArrayHelperTest() = default;

        void SetUp() override;
        void TearDown() override;
};
#endif //BYTE_ARRAY_TESTS_H
