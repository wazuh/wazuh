/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * May 1, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SOCKET_WRAPPER_TEST_H
#define _SOCKET_WRAPPER_TEST_H

#include "gtest/gtest.h"

class SocketWrapperTest : public ::testing::Test
{
protected:
    SocketWrapperTest() = default;
    virtual ~SocketWrapperTest() = default;

    void SetUp() override;
    void TearDown() override;
};
#endif //_SOCKET_WRAPPER_TEST_H
