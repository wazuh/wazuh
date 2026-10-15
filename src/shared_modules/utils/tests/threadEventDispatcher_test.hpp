/*
 * Wazuh shared modules utils
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _THREAD_EVENT_DISPATCHER_TEST_HPP
#define _THREAD_EVENT_DISPATCHER_TEST_HPP

#include "rocksDBQueue.hpp"
#include "threadSafeQueue.h"
#include <gtest/gtest.h>
#include <memory>
#include <thread>

class ThreadEventDispatcherTest : public ::testing::Test
{
protected:
    ThreadEventDispatcherTest() = default;
    ~ThreadEventDispatcherTest() override = default;
    void SetUp() override;
    void TearDown() override;
};
#endif //_THREAD_EVENT_DISPATCHER_TEST_HPP
