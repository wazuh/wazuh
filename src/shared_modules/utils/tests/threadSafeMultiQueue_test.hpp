/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * April 11, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
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
