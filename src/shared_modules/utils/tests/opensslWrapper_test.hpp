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

#ifndef _OPENSSL_WRAPPER_TEST_H
#define _OPENSSL_WRAPPER_TEST_H

#include "gtest/gtest.h"

class OpenSSLWrapperTest : public ::testing::Test
{
protected:
    OpenSSLWrapperTest() = default;
    virtual ~OpenSSLWrapperTest() = default;

    void SetUp() override;
    void TearDown() override;
};

#endif //_OPENSSL_WRAPPER_TEST_H
