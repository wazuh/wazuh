/*
 * Wazuh shared modules utils
 * Copyright (C) Wazuh Inc.
 * July 11, 2024.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef EVP_HELPER_TESTS_HPP
#define EVP_HELPER_TESTS_HPP
#include "gtest/gtest.h"

class EVPHelperTest : public ::testing::Test
{
protected:
    EVPHelperTest() = default;
    virtual ~EVPHelperTest() = default;
};
#endif // EVP_HELPER_TESTS_HPP
