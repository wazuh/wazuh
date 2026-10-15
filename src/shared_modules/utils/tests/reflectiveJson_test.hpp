/*
 * Wazuh shared modules utils
 * Copyright (C) Wazuh Inc.
 * March 18, 2025.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */
#ifndef REFLECTIVE_JSON_HPP
#define REFLECTIVE_JSON_HPP

#include "gtest/gtest.h"

class ReflectiveJsonTest : public ::testing::Test
{
protected:
    ReflectiveJsonTest() = default;
    virtual ~ReflectiveJsonTest() = default;

    void SetUp() override;
    void TearDown() override;
};
#endif // REFLECTIVE_JSON_HPP
