/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 11, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
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
