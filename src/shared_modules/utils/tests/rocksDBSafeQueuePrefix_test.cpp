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

#include "rocksDBSafeQueuePrefix_test.hpp"
#include <filesystem>
#include <thread>

void RocksDBSafeQueuePrefixTest::SetUp()
{
    std::error_code ec;
    std::filesystem::remove_all("test.db", ec);
    queue = std::make_unique<Utils::TSafeMultiQueue<std::string, std::string, RocksDBQueueCF<std::string>>>(
        RocksDBQueueCF<std::string>("test.db"));
};

void RocksDBSafeQueuePrefixTest::TearDown() {};

TEST_F(RocksDBSafeQueuePrefixTest, PopInCancelledQueue)
{
    queue->cancel();
    EXPECT_TRUE(queue->cancelled());
    EXPECT_TRUE(queue->empty());
    auto queueSize {queue->size("000")};
    EXPECT_NO_THROW(queue->pop("000"));
    EXPECT_EQ(queueSize, queue->size("000"));
}

TEST_F(RocksDBSafeQueuePrefixTest, PopEmptyQueue)
{
    EXPECT_TRUE(queue->empty());
    EXPECT_FALSE(queue->cancelled());
    const auto front {queue->front()};
    EXPECT_STREQ("", front.first.c_str());
    EXPECT_STREQ("", front.second.c_str());
}

TEST_F(RocksDBSafeQueuePrefixTest, PopWithData)
{
    queue->push("000", "test");
    EXPECT_EQ(1, queue->size("000"));
    auto front {queue->front()};
    EXPECT_NO_THROW(queue->pop(front.second));
    EXPECT_EQ(0, queue->size("000"));
    EXPECT_STREQ("000", front.second.c_str());
    EXPECT_STREQ("test", front.first.c_str());

    EXPECT_ANY_THROW(queue->pop("000"));

    queue->push("000", "test2");
    EXPECT_EQ(1, queue->size("000"));
    front = queue->front();
    EXPECT_NO_THROW(queue->pop(front.second));
    EXPECT_EQ(0, queue->size("000"));
    EXPECT_STREQ("000", front.second.c_str());
    EXPECT_STREQ("test2", front.first.c_str());

    queue->cancel();
    EXPECT_TRUE(queue->cancelled());
    EXPECT_TRUE(queue->empty());
    queue->push("000", "test3");
    EXPECT_TRUE(queue->empty());
}

TEST_F(RocksDBSafeQueuePrefixTest, PopWithMultipleData)
{
    const int ITERATION_COUNT = 10000;
    std::string data = "test";

    for (int i = 0; i < ITERATION_COUNT; i++)
    {
        queue->push("000", data + std::to_string(i));
    }

    EXPECT_EQ(ITERATION_COUNT, queue->size("000"));

    for (int i = 0; i < ITERATION_COUNT; i++)
    {
        auto front {queue->front()};
        EXPECT_NO_THROW(queue->pop(front.second));
        EXPECT_EQ(data + std::to_string(i), front.first);
    }

    EXPECT_TRUE(queue->empty());
}

TEST_F(RocksDBSafeQueuePrefixTest, PopWithMultipleIDData)
{
    const int ITERATION_COUNT = 10000;
    std::string data = "test";

    for (int i = 0; i < ITERATION_COUNT; i++)
    {
        queue->push(std::to_string(i), data);
    }

    for (int i = 0; i < ITERATION_COUNT; i++)
    {
        auto front {queue->front()};
        EXPECT_EQ(1, queue->size(front.second));
        EXPECT_NO_THROW(queue->pop(front.second));
        EXPECT_EQ(0, queue->size(front.second));
        EXPECT_EQ(data, front.first);
    }

    EXPECT_TRUE(queue->empty());
}

TEST_F(RocksDBSafeQueuePrefixTest, BlockingPopByRef)
{
    std::thread t1 {[this]()
                    {
                        auto front {queue->front()};
                        EXPECT_NO_THROW(queue->pop(front.second));
                        EXPECT_EQ("0", front.first);
                    }};
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    queue->push("000", "0");
    t1.join();
}

TEST_F(RocksDBSafeQueuePrefixTest, CancelBlockingPop)
{
    std::thread t {[this]()
                   {
                       auto front {queue->front()};
                       EXPECT_STREQ("", front.first.c_str());
                       EXPECT_STREQ("", front.second.c_str());
                       EXPECT_TRUE(queue->cancelled());
                   }};
    queue->cancel();
    t.join();
}

TEST_F(RocksDBSafeQueuePrefixTest, CreateFolderRecursively)
{
    const std::string DATABASE_NAME {"folder1/folder2/test.db"};

    EXPECT_NO_THROW({
        (std::make_unique<Utils::TSafeMultiQueue<std::string, std::string, RocksDBQueueCF<std::string>>>(
            RocksDBQueueCF<std::string>(DATABASE_NAME)));
    });

    std::error_code ec;
    std::filesystem::remove_all(DATABASE_NAME, ec);
}

TEST_F(RocksDBSafeQueuePrefixTest, ClearQueue)
{
    queue->push("000", "test");
    queue->push("000", "test2");
    queue->push("000", "test3");
    queue->push("001", "test4");
    queue->push("001", "test5");

    EXPECT_EQ(3, queue->size("000"));
    EXPECT_EQ(2, queue->size("001"));

    queue->clear("000");
    EXPECT_EQ(0, queue->size("000"));
    EXPECT_EQ(2, queue->size("001"));

    queue->clear("001");
    EXPECT_EQ(0, queue->size("001"));
}

TEST_F(RocksDBSafeQueuePrefixTest, ClearAllQueue)
{
    queue->push("000", "test");
    queue->push("000", "test2");
    queue->push("000", "test3");
    queue->push("001", "test4");
    queue->push("001", "test5");

    queue->clear("");
    EXPECT_EQ(0, queue->size("000"));
    EXPECT_EQ(0, queue->size("001"));
    EXPECT_TRUE(queue->empty());
}
