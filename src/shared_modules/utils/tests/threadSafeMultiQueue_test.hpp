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

#ifndef THREAD_SAFE_MULTI_QUEUE_TESTS_HPP
#define THREAD_SAFE_MULTI_QUEUE_TESTS_HPP

#include "rocksDBQueueCF.hpp"
#include "threadSafeMultiQueue.hpp"
#include "gtest/gtest.h"

class ThreadSafeMultiQueueTest : public ::testing::Test
{
protected:
    ThreadSafeMultiQueueTest() = default;
    virtual ~ThreadSafeMultiQueueTest() = default;

    void SetUp() override;
    void TearDown() override;
};
#endif // THREAD_SAFE_MULTI_QUEUE_TESTS_HPP
