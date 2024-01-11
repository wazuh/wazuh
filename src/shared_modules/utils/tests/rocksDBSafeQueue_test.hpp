/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 4, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
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
