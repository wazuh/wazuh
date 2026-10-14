/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * May 4, 2024.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
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
