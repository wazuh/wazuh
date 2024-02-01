/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * February 01, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef RSA_HELPER_TESTS_H
#define RSA_HELPER_TESTS_H
#include "gtest/gtest.h"

class RsaHelperTest : public ::testing::Test
{
protected:
    /**
     * @brief Construct a new RsaHelperTest object
     *
     */
    RsaHelperTest() = default;

    /**
     * @brief Destroy the RsaHelperTest object
     *
     */
    virtual ~RsaHelperTest() = default;

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
#endif //RSA_HELPER_TESTS_H