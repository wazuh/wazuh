/*
 * Wazuh DBSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 14, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <thread>
#include "threadSafeQueue_test.h"
#include "threadSafeQueue.h"

void ThreadSafeQueueTest::SetUp() {};

void ThreadSafeQueueTest::TearDown() {};

using namespace Utils;
TEST_F(ThreadSafeQueueTest, Ctor)
{
    SafeQueue<int> queue;
    int ret_val{};
    EXPECT_TRUE(queue.empty());
    EXPECT_FALSE(queue.cancelled());
    EXPECT_FALSE(queue.popFront(ret_val, false));//non wait pop;
    auto spValue{queue.popFront(false)};
    EXPECT_FALSE(spValue);
}

TEST_F(ThreadSafeQueueTest, NonBlockingPopFront)
{
    SafeQueue<int> queue;
    queue.pushBack(0);
    int ret_val{};
    EXPECT_TRUE(queue.popFront(ret_val, false));//non wait pop;
    EXPECT_EQ(0, ret_val);//non wait pop;
    EXPECT_FALSE(queue.popFront(ret_val, false));//non wait pop;
    queue.pushBack(1);
    auto spValue{queue.popFront(false)};
    EXPECT_TRUE(spValue);
    EXPECT_EQ(1, *spValue);
    spValue = queue.popFront(false);
    EXPECT_FALSE(spValue);
}

TEST_F(ThreadSafeQueueTest, NonBlockingPopBack)
{
    SafeQueue<int> queue;
    queue.pushFront(0);
    int ret_val{};
    EXPECT_TRUE(queue.popBack(ret_val, false));//non wait pop;
    EXPECT_EQ(0, ret_val);//non wait pop;
    EXPECT_FALSE(queue.popBack(ret_val, false));//non wait pop;
    queue.pushFront(1);
    auto spValue{queue.popBack(false)};
    EXPECT_TRUE(spValue);
    EXPECT_EQ(1, *spValue);
    spValue = queue.popBack(false);
    EXPECT_FALSE(spValue);
}

TEST_F(ThreadSafeQueueTest, BlockingPopBackByRef)
{
    SafeQueue<int> queue;
    std::thread t1
    {
        [&queue]()
        {
            int ret_val{};
            EXPECT_TRUE(queue.popBack(ret_val));
            EXPECT_EQ(0, ret_val);
        }
    };
    queue.pushBack(0);
    t1.join();
}

TEST_F(ThreadSafeQueueTest, BlockingPopFontByRef)
{
    SafeQueue<int> queue;
    std::thread t1
    {
        [&queue]()
        {
            int ret_val{};
            EXPECT_TRUE(queue.popFront(ret_val));
            EXPECT_EQ(0, ret_val);
        }
    };
    queue.pushFront(0);
    t1.join();
}

TEST_F(ThreadSafeQueueTest, BlockingPopBackBySmartPtr)
{
    SafeQueue<int> queue;
    std::thread t1
    {
        [&queue]()
        {
            auto ret_val{queue.popBack()};
            EXPECT_TRUE(ret_val);
            EXPECT_EQ(0, *ret_val);
        }
    };
    queue.pushBack(0);
    t1.join();
}

TEST_F(ThreadSafeQueueTest, BlockingPopFrontBySmartPtr)
{
    SafeQueue<int> queue;
    std::thread t1
    {
        [&queue]()
        {
            auto ret_val{queue.popFront()};
            EXPECT_TRUE(ret_val);
            EXPECT_EQ(0, *ret_val);
        }
    };
    queue.pushFront(0);
    t1.join();
}

TEST_F(ThreadSafeQueueTest, Cancel)
{
    SafeQueue<int> queue;
    queue.pushBack(0);
    queue.pushBack(1);
    queue.pushFront(2);
    int ret_val{};
    EXPECT_TRUE(queue.popFront(ret_val, false));//non wait pop;
    EXPECT_TRUE(queue.popBack(ret_val, false));//non wait pop;
    queue.cancel();
    EXPECT_FALSE(queue.popFront(ret_val, false));//non wait pop;
    EXPECT_FALSE(queue.popFront(ret_val));//wait pop;
    EXPECT_FALSE(queue.popBack(ret_val));//wait pop;
    EXPECT_TRUE(queue.cancelled());
}

TEST_F(ThreadSafeQueueTest, CancelBlockingPopBack)
{
    SafeQueue<int> queue;
    std::thread t1
    {
        [&queue]()
        {
            auto ret_val{queue.popBack()};
            EXPECT_FALSE(ret_val);
            EXPECT_TRUE(queue.cancelled());
        }
    };
    std::thread t2
    {
        [&queue]()
        {
            int ret_val{};
            EXPECT_FALSE(queue.popBack(ret_val));
            EXPECT_TRUE(queue.cancelled());
        }
    };
    queue.cancel();
    t1.join();
    t2.join();
}

TEST_F(ThreadSafeQueueTest, CancelBlockingPopFront)
{
    SafeQueue<int> queue;
    std::thread t1
    {
        [&queue]()
        {
            auto ret_val{queue.popFront()};
            EXPECT_FALSE(ret_val);
            EXPECT_TRUE(queue.cancelled());
        }
    };
    std::thread t2
    {
        [&queue]()
        {
            int ret_val{};
            EXPECT_FALSE(queue.popFront(ret_val));
            EXPECT_TRUE(queue.cancelled());
        }
    };
    queue.cancel();
    t1.join();
    t2.join();
}