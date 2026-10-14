/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * Oct 22, 2024.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
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
