/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * May 4, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ROCKSDB_SAFEQUEUE_PREFIX_TEST_HPP
#define _ROCKSDB_SAFEQUEUE_PREFIX_TEST_HPP

#include "rocksDBQueueCF.hpp"
#include "threadSafeMultiQueue.hpp"
#include <gtest/gtest.h>
#include <memory>

class RocksDBSafeQueuePrefixTest : public ::testing::Test
{
protected:
    RocksDBSafeQueuePrefixTest() = default;
    ~RocksDBSafeQueuePrefixTest() override = default;
    std::unique_ptr<Utils::TSafeMultiQueue<std::string, std::string, RocksDBQueueCF<std::string>>> queue;
    void SetUp() override;
    void TearDown() override;
};
#endif //_ROCKSDB_SAFEQUEUE_PREFIX_TEST_HPP
