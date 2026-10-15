/*
 * Wazuh shared modules utils
 * Copyright (C) Wazuh Inc.
 * May 1, 2023.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
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
