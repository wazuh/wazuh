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

#include <filesystem>

#include "rocksDBSafeQueue_test.hpp"
#include "rocksDBWrapper.hpp"

void RocksDBSafeQueueTest::SetUp()
{
    std::error_code ec;
    std::filesystem::remove_all("test.db", ec);
    queue = std::make_unique<Utils::SafeQueue<std::string, RocksDBQueue<std::string>>>(
        RocksDBQueue<std::string>("test.db"));
};

void RocksDBSafeQueueTest::TearDown() {};

TEST_F(RocksDBSafeQueueTest, PopInCancelledQueue)
{
    queue->cancel();
    EXPECT_TRUE(queue->cancelled());
    EXPECT_TRUE(queue->empty());
    std::string ret_val {};
    EXPECT_FALSE(queue->pop(ret_val, false));
    auto spValue {queue->pop(false)};
    EXPECT_FALSE(spValue);
}

TEST_F(RocksDBSafeQueueTest, PopEmptyQueue)
{
    std::string ret_val {};
    EXPECT_TRUE(queue->empty());
    EXPECT_FALSE(queue->cancelled());
    EXPECT_FALSE(queue->pop(ret_val, false));
    auto spValue {queue->pop(false)};
    EXPECT_FALSE(spValue);
}

TEST_F(RocksDBSafeQueueTest, PopWithData)
{
    queue->push("test");
    std::string ret_val {};
    EXPECT_TRUE(queue->pop(ret_val, false));
    EXPECT_EQ("test", ret_val);

    EXPECT_FALSE(queue->pop(ret_val, false));

    queue->push("test2");
    auto spValue {queue->pop(false)};
    EXPECT_TRUE(spValue);
    EXPECT_EQ("test2", *spValue);

    spValue = queue->pop(false);
    EXPECT_FALSE(spValue);

    queue->cancel();
    EXPECT_TRUE(queue->cancelled());
    EXPECT_TRUE(queue->empty());
    queue->push("test3");
    EXPECT_FALSE(queue->pop(ret_val, false));
    EXPECT_TRUE(queue->empty());
}

TEST_F(RocksDBSafeQueueTest, PopWithMultipleData)
{
    const int ITERATION_COUNT = 10000;
    std::string data = "test";

    for (int i = 0; i < ITERATION_COUNT; i++)
    {
        queue->push(data + std::to_string(i));
    }

    std::string ret_val {};

    for (int i = 0; i < ITERATION_COUNT; i++)
    {
        EXPECT_TRUE(queue->pop(ret_val, false));
        EXPECT_EQ(data + std::to_string(i), ret_val);
    }

    EXPECT_TRUE(queue->empty());
}

TEST_F(RocksDBSafeQueueTest, BlockingPopByRef)
{
    std::thread t1 {[this]()
                    {
                        std::string ret_val {};
                        EXPECT_TRUE(queue->pop(ret_val));
                        EXPECT_EQ("0", ret_val);
                    }};
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    queue->push("0");
    t1.join();
}

TEST_F(RocksDBSafeQueueTest, BlockingPopBySmartPtr)
{
    std::thread t1 {[this]()
                    {
                        auto ret_val {queue->pop()};
                        EXPECT_TRUE(ret_val);
                        EXPECT_EQ("0", *ret_val);
                    }};
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    queue->push("0");
    t1.join();
}

TEST_F(RocksDBSafeQueueTest, CancelBlockingPop)
{
    std::thread t1 {[this]()
                    {
                        auto ret_val {queue->pop()};
                        EXPECT_FALSE(ret_val);
                        EXPECT_TRUE(queue->cancelled());
                    }};
    std::thread t2 {[this]()
                    {
                        int ret_val {};
                        EXPECT_FALSE(queue->pop(ret_val));
                        EXPECT_TRUE(queue->cancelled());
                    }};
    queue->cancel();
    t1.join();
    t2.join();
}

TEST_F(RocksDBSafeQueueTest, CreateFolderRecursively)
{
    const std::string DATABASE_NAME {"folder1/folder2/test.db"};

    EXPECT_NO_THROW({
        (std::make_unique<Utils::SafeQueue<std::string, RocksDBQueue<std::string>>>(
            RocksDBQueue<std::string>(DATABASE_NAME)));
    });

    std::error_code ec;
    std::filesystem::remove_all(DATABASE_NAME, ec);
}
