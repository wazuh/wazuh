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

#ifndef THREAD_SAFE_QUEUE_TESTS_H
#define THREAD_SAFE_QUEUE_TESTS_H
#include "gtest/gtest.h"

class ThreadSafeQueueTest : public ::testing::Test
{
    protected:

        ThreadSafeQueueTest() = default;
        virtual ~ThreadSafeQueueTest() = default;

        void SetUp() override;
        void TearDown() override;
};
#endif //THREAD_SAFE_QUEUE_TESTS_H