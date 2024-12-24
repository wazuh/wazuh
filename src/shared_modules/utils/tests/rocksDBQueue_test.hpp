/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * Dec 24, 2024.
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

constexpr auto TEST_DB = "test.db";

class RocksDBQueueTest : public ::testing::Test
{
protected:
    RocksDBQueueTest() = default;
    ~RocksDBQueueTest() override = default;
    std::unique_ptr<RocksDBQueue<std::string>> queue;
    void SetUp() override;
    void TearDown() override;
};
#endif //_ROCKSDB_SAFEQUEUE_TEST_HPP
