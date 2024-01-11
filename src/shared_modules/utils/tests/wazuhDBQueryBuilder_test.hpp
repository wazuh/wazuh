/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * Nov 1, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
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
