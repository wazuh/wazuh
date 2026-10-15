/*
 * Wazuh shared modules utils
 * Copyright (C) Wazuh Inc.
 * Nov 1, 2023.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _WAZUH_DB_QUERY_BUILDER_TEST_HPP
#define _WAZUH_DB_QUERY_BUILDER_TEST_HPP

#include "gtest/gtest.h"

class WazuhDBQueryBuilderTest : public ::testing::Test
{
protected:
    WazuhDBQueryBuilderTest() = default;
    virtual ~WazuhDBQueryBuilderTest() = default;

    void SetUp() override {};
    void TearDown() override {};
};

#endif // _WAZUH_DB_QUERY_BUILDER_TEST_HPP
