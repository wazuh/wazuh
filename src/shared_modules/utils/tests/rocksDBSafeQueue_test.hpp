/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 4, 2023.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _ROCKSDB_SAFEQUEUE_TEST_HPP
#define _ROCKSDB_SAFEQUEUE_TEST_HPP

#include "rocksDBQueue.hpp"
#include "threadSafeQueue.h"
#include <gtest/gtest.h>
#include <memory>
#include <thread>

class RocksDBSafeQueueTest : public ::testing::Test
{
protected:
    RocksDBSafeQueueTest() = default;
    ~RocksDBSafeQueueTest() override = default;
    std::unique_ptr<Utils::SafeQueue<std::string, RocksDBQueue<std::string>>> queue;
    //(RocksDBQueue<std::string>("test.db"));
    void SetUp() override;
    void TearDown() override;
};
#endif //_ROCKSDB_SAFEQUEUE_TEST_HPP
