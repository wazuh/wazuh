/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 14, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
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
#endif // THREAD_SAFE_QUEUE_TESTS_H
