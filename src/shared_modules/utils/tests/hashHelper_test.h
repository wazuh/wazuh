/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * Sep 8, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef HASH_HELPER_TESTS_H
#define HASH_HELPER_TESTS_H
#include "gmock/gmock.h"
#include "gtest/gtest.h"

class HashHelperTest : public ::testing::Test
{
protected:
    HashHelperTest() = default;
    virtual ~HashHelperTest() = default;

    void SetUp() override;
    void TearDown() override;
};
#endif // HASH_HELPER_TESTS_H
