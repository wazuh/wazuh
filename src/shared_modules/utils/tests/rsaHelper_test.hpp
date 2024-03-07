/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * Febrary 6, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _RSAHELPER_WRAPPER_TEST_H
#define _RSAHELPER_WRAPPER_TEST_H

#include "gtest/gtest.h"

class RSAHelperTest : public ::testing::Test
{
protected:
    RSAHelperTest() = default;
    virtual ~RSAHelperTest() = default;

    void SetUp() override;
    void TearDown() override;
};

#endif //_RSAHELPER_WRAPPER_TEST_H
