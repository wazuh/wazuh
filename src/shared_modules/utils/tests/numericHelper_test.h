/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * December 22, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
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