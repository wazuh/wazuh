/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * Oct 22, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SOCKET_SERVER_TEST_HPP
#define _SOCKET_SERVER_TEST_HPP

#include "gtest/gtest.h"

class SocketServerTest : public ::testing::Test
{
protected:
    SocketServerTest() = default;
    virtual ~SocketServerTest() = default;

    void SetUp() override;
    void TearDown() override;
};
#endif //_SOCKET_SERVER_TEST_HPP
