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
#include <memory>
#include <queue>
#include <string>
#include <thread>

#include <gtest/gtest.h>

#include <base/utils/rocksDBQueueCF.hpp>
#include <base/utils/rocksDBWrapper.hpp>
#include <base/utils/threadSafeMultiQueue.hpp>

class RocksDBSafeQueuePrefixTest : public ::testing::Test
{
protected:
    RocksDBSafeQueuePrefixTest() = default;
    ~RocksDBSafeQueuePrefixTest() override = default;

    void SetUp() override
    {
        std::error_code ec;
        std::filesystem::remove_all("test.db", ec);
        queue = std::make_unique<
            base::utils::queue::TSafeMultiQueue<std::string, std::string, RocksDBQueueCF<std::string>>>(
            RocksDBQueueCF<std::string>("test.db"));
    }

    void TearDown() override {}

    std::unique_ptr<base::utils::queue::TSafeMultiQueue<std::string, std::string, RocksDBQueueCF<std::string>>> queue;
};

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
        (std::make_unique<base::utils::queue::TSafeMultiQueue<std::string, std::string, RocksDBQueueCF<std::string>>>(
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

TEST_F(RocksDBSafeQueuePrefixTest, PopWithDeletedIndex)
{
    const int ITERATION_COUNT = 10;
    constexpr int ELEMENTS_TO_POP = 8;
    const std::array elements {"1", "2", "4", "5", "6", "7", "9", "10"};

    for (int i = 0; i < ITERATION_COUNT; i++)
    {
        std::cout << "Pushing " << i + 1 << std::endl;
        queue->push("001", std::to_string(i + 1));
    }

    for (int i = 0; i < ITERATION_COUNT; i++)
    {
        queue->push("002", std::to_string(i + 1));
    }

    queue = nullptr;
    {
        auto db = std::make_unique<utils::rocksdb::RocksDBWrapper>("test.db");
        db->delete_("001_" + std::to_string(3));
        db->delete_("001_" + std::to_string(8));
    }
    queue =
        std::make_unique<base::utils::queue::TSafeMultiQueue<std::string, std::string, RocksDBQueueCF<std::string>>>(
            RocksDBQueueCF<std::string>("test.db"));

    std::queue<std::string> queueElements;
    while (queue->size("001") != 0)
    {
        queueElements.push(queue->front().first);
        EXPECT_NO_THROW(queue->pop("001"));
        std::cout << queueElements.back() << " " << queueElements.front() << std::endl;
    }

    if (queueElements.size() != ELEMENTS_TO_POP)
    {
        FAIL() << "Expected " << ELEMENTS_TO_POP << " elements, but got " << queueElements.size();
    }

    for (const auto& element : elements)
    {
        EXPECT_EQ(element, queueElements.front());
        queueElements.pop();
    }

    EXPECT_EQ(queue->size("001"), 0);
    EXPECT_EQ(queue->size("002"), 10);
}
