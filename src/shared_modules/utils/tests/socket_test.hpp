/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * May 24, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SOCKET_TEST_HPP
#define _SOCKET_TEST_HPP

#include "gtest/gtest.h"

template <typename T>
class SocketTest : public ::testing::Test
{
protected:
    SocketTest() = default;
    virtual ~SocketTest() = default;

    void SetUp() {};
    void TearDown() {};
};
#endif // _SOCKET_TEST_HPP
