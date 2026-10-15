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

#include "byteArrayHelper_test.h"
#include "byteArrayHelper.h"

void ByteArrayHelperTest::SetUp() {};

void ByteArrayHelperTest::TearDown() {};

constexpr uint8_t bufferBE[] = {0x12, 0x34, 0x56, 0x78};
constexpr uint8_t bufferLE[] = {0x78, 0x56, 0x34, 0x12};
constexpr int32_t result {305419896};

TEST_F(ByteArrayHelperTest, toInt32BE)
{
    EXPECT_EQ(result, Utils::toInt32BE(bufferBE));
}

TEST_F(ByteArrayHelperTest, toInt32LE)
{
    EXPECT_EQ(result, Utils::toInt32LE(bufferLE));
}
