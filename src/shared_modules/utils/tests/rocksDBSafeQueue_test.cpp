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

#include "rocksDBSafeQueue_test.hpp"
#include "rocksDBWrapper.hpp"
#include <filesystem>

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

TEST_F(RocksDBSafeQueueTest, CorruptionTest)
{
    const std::string DATABASE_NAME {"corrupted.db"};
    std::unique_ptr<Utils::SafeQueue<std::string, RocksDBQueue<std::string>>> testQueue;

    testQueue = std::make_unique<Utils::SafeQueue<std::string, RocksDBQueue<std::string>>>(
        RocksDBQueue<std::string>(DATABASE_NAME));

    for (int i = 0; i < 10; i++)
    {
        testQueue->push("test" + std::to_string(i));
    }

    testQueue->cancel();
    EXPECT_TRUE(testQueue->cancelled());

    testQueue.reset();

    bool corrupted {false};
    std::string prefix {DATABASE_NAME + "/MANIFEST"};
    for (const auto& entry : std::filesystem::directory_iterator(DATABASE_NAME))
    {
        if (entry.path().string().substr(0, prefix.size()).compare(prefix) == 0)
        {
            std::filesystem::remove(entry.path());
            corrupted = true;
            break;
        }
    }
    EXPECT_TRUE(corrupted);

    try
    {
        testQueue = std::make_unique<Utils::SafeQueue<std::string, RocksDBQueue<std::string>>>(
            RocksDBQueue<std::string>(DATABASE_NAME));
    }
    catch (const std::exception& e)
    {
        FAIL() << "No exception should be thrown, the DB should be repaired: " << e.what();
    }

    testQueue->cancel();
    EXPECT_TRUE(testQueue->cancelled());
    testQueue.reset();

    std::error_code ec;
    std::filesystem::remove_all(DATABASE_NAME, ec);
}
TEST_F(RocksDBSafeQueueTest, PopBulkWithDeletedIndexAndEmpty)
{
    const int ITERATION_COUNT = 1;
    constexpr int ELEMENTS_TO_POP = 0;

    for (int i = 0; i < ITERATION_COUNT; i++)
    {
        queue->push(std::to_string(i + 1));
    }

    queue = nullptr;
    {
        auto db = std::make_unique<Utils::RocksDBWrapper>("test.db");
        db->delete_(std::to_string(1));
    }

    queue = std::make_unique<Utils::SafeQueue<std::string, RocksDBQueue<std::string>>>(
        RocksDBQueue<std::string>("test.db"));

    if (auto queueElements = queue->getBulk(ITERATION_COUNT, std::chrono::seconds(1));
        queueElements.size() != ELEMENTS_TO_POP)
    {
        FAIL() << "Expected " << ELEMENTS_TO_POP << " elements, but got " << queueElements.size();
    }

    EXPECT_NO_THROW(queue->popBulk(5));
    EXPECT_TRUE(queue->empty());
    EXPECT_NO_THROW(queue->popBulk(5));
}

TEST_F(RocksDBSafeQueueTest, PopBulkWithDeletedIndexAndPendingElements)
{
    const int ITERATION_COUNT = 10;
    constexpr int BULK_SIZE = 5;
    constexpr int ELEMENTS_TO_POP_1 = 5;
    constexpr int ELEMENTS_TO_POP_2 = 4;
    const std::array elementsFirstCall {"1", "2", "4", "5", "6"};
    const std::array elementsSecondCall {"7", "8", "9", "10"};

    for (int i = 0; i < ITERATION_COUNT; i++)
    {
        queue->push(std::to_string(i + 1));
    }

    queue = nullptr;
    {
        auto db = std::make_unique<Utils::RocksDBWrapper>("test.db");
        db->delete_(std::to_string(3));
    }
    queue = std::make_unique<Utils::SafeQueue<std::string, RocksDBQueue<std::string>>>(
        RocksDBQueue<std::string>("test.db"));

    auto queueElements = queue->getBulk(BULK_SIZE, std::chrono::seconds(1));

    if (queueElements.size() != ELEMENTS_TO_POP_1)
    {
        FAIL() << "Expected " << ELEMENTS_TO_POP_1 << " elements, but got " << queueElements.size();
    }

    for (const auto& element : elementsFirstCall)
    {
        EXPECT_EQ(element, queueElements.front());
        queueElements.pop();
    }

    EXPECT_NO_THROW(queue->popBulk(ELEMENTS_TO_POP_1));
    EXPECT_FALSE(queue->empty());

    queueElements = queue->getBulk(BULK_SIZE, std::chrono::seconds(1));

    if (queueElements.size() != ELEMENTS_TO_POP_2)
    {
        FAIL() << "Expected " << ELEMENTS_TO_POP_2 << " elements, but got " << queueElements.size();
    }

    for (const auto& element : elementsSecondCall)
    {
        EXPECT_EQ(element, queueElements.front());
        queueElements.pop();
    }

    EXPECT_NO_THROW(queue->popBulk(ELEMENTS_TO_POP_2));
    EXPECT_TRUE(queue->empty());
}

TEST_F(RocksDBSafeQueueTest, PopWithDeletedIndex)
{
    const int ITERATION_COUNT = 10;
    constexpr int BULK_SIZE = 5;
    constexpr int ELEMENTS_TO_POP_1 = 5;
    constexpr int ELEMENTS_TO_POP_2 = 4;
    const std::array elementsFirstCall {"1", "2", "4", "5", "6"};
    const std::array elementsSecondCall {"7", "8", "9", "10"};

    for (int i = 0; i < ITERATION_COUNT; i++)
    {
        queue->push(std::to_string(i + 1));
    }

    queue = nullptr;
    {
        auto db = std::make_unique<Utils::RocksDBWrapper>("test.db");
        db->delete_(std::to_string(3));
    }
    queue = std::make_unique<Utils::SafeQueue<std::string, RocksDBQueue<std::string>>>(
        RocksDBQueue<std::string>("test.db"));

    auto queueElements = queue->getBulk(BULK_SIZE, std::chrono::seconds(1));

    if (queueElements.size() != ELEMENTS_TO_POP_1)
    {
        FAIL() << "Expected " << ELEMENTS_TO_POP_1 << " elements, but got " << queueElements.size();
    }

    for (const auto& element : elementsFirstCall)
    {
        EXPECT_EQ(element, queueElements.front());
        queueElements.pop();
    }

    for (auto i = 0; i < ELEMENTS_TO_POP_1; i++)
    {
        EXPECT_TRUE(queue->pop(false));
    }
    EXPECT_FALSE(queue->empty());

    queueElements = queue->getBulk(BULK_SIZE, std::chrono::seconds(1));

    if (queueElements.size() != ELEMENTS_TO_POP_2)
    {
        FAIL() << "Expected " << ELEMENTS_TO_POP_2 << " elements, but got " << queueElements.size();
    }

    for (const auto& element : elementsSecondCall)
    {
        EXPECT_EQ(element, queueElements.front());
        queueElements.pop();
    }

    for (auto i = 0; i < ELEMENTS_TO_POP_2; i++)
    {
        EXPECT_TRUE(queue->pop(false));
    }
    EXPECT_TRUE(queue->empty());
}

TEST_F(RocksDBSafeQueueTest, PopBulkWithDeletedIndexAndPendingElementsEmpty)
{
    const int ITERATION_COUNT = 20;
    constexpr int BULK_SIZE = 5;
    constexpr int ELEMENTS_TO_POP = 5;
    constexpr int ELEMENTS_TO_DELETE_FROM = 2;
    constexpr int ELEMENTS_TO_DELETE_TO = 10;
    const std::array elements {"1"};

    // Create a queue with 15 elements {1, 2, 3, ..., 20}
    for (int i = 0; i < ITERATION_COUNT; i++)
    {
        queue->push(std::to_string(i + 1));
    }

    queue = nullptr;
    {
        auto db = std::make_unique<Utils::RocksDBWrapper>("test.db");
        // Delete elements from 2 to 9
        for (int i = ELEMENTS_TO_DELETE_FROM; i < ELEMENTS_TO_DELETE_TO; i++)
        {
            db->delete_(std::to_string(i));
        }
    }
    queue = std::make_unique<Utils::SafeQueue<std::string, RocksDBQueue<std::string>>>(
        RocksDBQueue<std::string>("test.db"));

    auto queueElements = queue->getBulk(BULK_SIZE, std::chrono::seconds(1));

    // Get the first 5 elements {1, 11, 12, 13, 14}
    if (queueElements.size() != ELEMENTS_TO_POP)
    {
        FAIL() << "Expected " << ELEMENTS_TO_POP << " elements, but got " << queueElements.size();
    }
    EXPECT_NO_THROW(queue->popBulk(queueElements.size()));

    for (const auto& element : elements)
    {
        EXPECT_EQ(element, queueElements.front());
        queueElements.pop();
    }

    EXPECT_FALSE(queue->empty());

    while (!queue->empty())
    {
        queueElements = queue->getBulk(BULK_SIZE, std::chrono::seconds(1));

        EXPECT_NO_THROW(queue->popBulk(queueElements.size()));
    }
    EXPECT_TRUE(queue->empty());
}
