/*
 * Wazuh shared modules utils
 * Copyright (C) Wazuh Inc.
 * December 22, 2023.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef NUMERIC_HELPER_TESTS_H
#define NUMERIC_HELPER_TESTS_H
#include "gtest/gtest.h"

class NumericUtilsTest : public ::testing::Test
{
protected:
    /**
     * @brief Construct a new NumericUtilsTest object
     *
     */
    NumericUtilsTest() = default;

    /**
     * @brief Destroy the NumericUtilsTest object
     *
     */
    virtual ~NumericUtilsTest() = default;

    /**
     * @brief SetUp.
     *
     */
    void SetUp() override;

    /**
     * @brief TearDown.
     *
     */
    void TearDown() override;
};
#endif //NUMERIC_HELPER_TESTS_H