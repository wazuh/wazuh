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

#include <memory>
#include <string>
#include <thread>

#include <gtest/gtest.h>

#include <base/logging.hpp>
#include <base/utils/rocksDBQueue.hpp>
#include <base/utils/threadEventDispatcher.hpp>
#include <base/utils/threadSafeQueue.hpp>

class ThreadSafeQueueTest : public ::testing::Test
{
protected:
    ThreadSafeQueueTest() = default;
    virtual ~ThreadSafeQueueTest() = default;

    void SetUp() override {}

    void TearDown() override {}
};

TEST_F(ThreadSafeQueueTest, Ctor)
{
    base::utils::queue::SafeQueue<int> queue;
    int ret_val {};
    EXPECT_TRUE(queue.empty());
    EXPECT_FALSE(queue.cancelled());
    EXPECT_FALSE(queue.pop(ret_val, false)); // non wait pop;
    auto spValue {queue.pop(false)};
    EXPECT_FALSE(spValue);
}

TEST_F(ThreadSafeQueueTest, NonBlockingPop)
{
    base::utils::queue::SafeQueue<int> queue;
    queue.push(0);
    int ret_val {};
    EXPECT_TRUE(queue.pop(ret_val, false));  // non wait pop;
    EXPECT_EQ(0, ret_val);                   // non wait pop;
    EXPECT_FALSE(queue.pop(ret_val, false)); // non wait pop;
    queue.push(1);
    auto spValue {queue.pop(false)};
    EXPECT_TRUE(spValue);
    EXPECT_EQ(1, *spValue);
    spValue = queue.pop(false);
    EXPECT_FALSE(spValue);
}

TEST_F(ThreadSafeQueueTest, BlockingPopByRef)
{
    base::utils::queue::SafeQueue<int> queue;
    std::thread t1 {[&queue]()
                    {
                        int ret_val {};
                        EXPECT_TRUE(queue.pop(ret_val));
                        EXPECT_EQ(0, ret_val);
                    }};
    queue.push(0);
    t1.join();
}

TEST_F(ThreadSafeQueueTest, BlockingPopBySmartPtr)
{
    base::utils::queue::SafeQueue<int> queue;
    std::thread t1 {[&queue]()
                    {
                        auto ret_val {queue.pop()};
                        EXPECT_TRUE(ret_val);
                        EXPECT_EQ(0, *ret_val);
                    }};
    queue.push(0);
    t1.join();
}

TEST_F(ThreadSafeQueueTest, Cancel)
{
    base::utils::queue::SafeQueue<int> queue;
    queue.push(0);
    queue.push(1);
    queue.push(2);
    int ret_val {};
    EXPECT_TRUE(queue.pop(ret_val, false)); // non wait pop;
    queue.cancel();
    EXPECT_FALSE(queue.pop(ret_val, false)); // non wait pop;
    EXPECT_FALSE(queue.pop(ret_val));        // wait pop;
    EXPECT_TRUE(queue.cancelled());
}

TEST_F(ThreadSafeQueueTest, CancelBlockingPop)
{
    base::utils::queue::SafeQueue<int> queue;
    std::thread t1 {[&queue]()
                    {
                        auto ret_val {queue.pop()};
                        EXPECT_FALSE(ret_val);
                        EXPECT_TRUE(queue.cancelled());
                    }};
    std::thread t2 {[&queue]()
                    {
                        int ret_val {};
                        EXPECT_FALSE(queue.pop(ret_val));
                        EXPECT_TRUE(queue.cancelled());
                    }};
    queue.cancel();
    t1.join();
    t2.join();
}
