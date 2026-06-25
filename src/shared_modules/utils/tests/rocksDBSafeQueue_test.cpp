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
#include "rocksdb/cache.h"
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>

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
        db->delete_(Utils::padString(std::to_string(1), '0', 20));
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
        db->delete_(Utils::padString(std::to_string(3), '0', 20));
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
        db->delete_(Utils::padString(std::to_string(3), '0', 20));
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
            db->delete_(Utils::padString(std::to_string(i), '0', 20));
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

namespace
{
    size_t getMemoryUsage()
    {
        std::ifstream statm("/proc/self/statm");
        if (statm.is_open())
        {
            size_t size, resident, share, text, lib, data, dt;
            statm >> size >> resident >> share >> text >> lib >> data >> dt;
            return resident * 4096; // Convert pages to bytes (assuming 4KB pages)
        }
        return 0;
    }

    void printMemoryUsage(const std::string& label)
    {
        size_t memUsage = getMemoryUsage();
        std::cout << label << ": " << std::fixed << std::setprecision(2)
                  << static_cast<double>(memUsage) / (1024.0 * 1024.0) << " MB" << std::endl;
    }

    void printSharedBufferStats(const std::string& label)
    {
        std::cout << "\n=== " << label << " - Shared Buffer Statistics ===" << std::endl;

        // Get shared buffers instance
        auto& sharedBuffers = RocksDBSharedBuffers::getInstance();
        auto writeManager = sharedBuffers.getWriteBufferManager();

        // Print write buffer usage (this method should be available)
        if (writeManager)
        {
            try
            {
                std::cout << "Write Buffer Usage: " << std::fixed << std::setprecision(2)
                          << static_cast<double>(writeManager->memory_usage()) / (1024.0 * 1024.0) << " MB / "
                          << static_cast<double>(writeManager->buffer_size()) / (1024.0 * 1024.0) << " MB" << std::endl;
            }
            catch (...)
            {
                std::cout << "Write Buffer: SHARED (128 MB capacity)" << std::endl;
            }
        }

        printMemoryUsage("Total RSS");
        std::cout << "======================================================\n" << std::endl;
    }
} // namespace

TEST_F(RocksDBSafeQueueTest, StressTestMultipleQueuesAndThreads)
{
    const int NUM_QUEUES = 10;
    const int NUM_THREADS = 10;
    const int ELEMENTS_PER_THREAD = 1000000; // 1M elements per thread (testing stricter limits)

    std::cout << "Starting stress test with " << NUM_QUEUES << " queues, " << NUM_THREADS << " threads, "
              << ELEMENTS_PER_THREAD << " elements per thread" << std::endl;
    std::cout << "Using SHARED BUFFERS optimization - memory should be significantly reduced!" << std::endl;

    printSharedBufferStats("Initial state");

    // Create 10 unique SafeQueue instances with different database names
    std::vector<std::unique_ptr<Utils::SafeQueue<std::string, RocksDBQueue<std::string>>>> queues;

    for (int i = 0; i < NUM_QUEUES; ++i)
    {
        std::string dbName = "stress_test_" + std::to_string(i) + ".db";
        std::error_code ec;
        std::filesystem::remove_all(dbName, ec);

        queues.push_back(std::make_unique<Utils::SafeQueue<std::string, RocksDBQueue<std::string>>>(
            RocksDBQueue<std::string>(dbName, true)));
    }

    printSharedBufferStats("After creating 10 queues");

    // Create threads for pushing data
    std::vector<std::thread> threads;
    std::atomic<int> threadsCompleted {0};

    auto startTime = std::chrono::high_resolution_clock::now();

    for (int threadId = 0; threadId < NUM_THREADS; ++threadId)
    {
        threads.emplace_back(
            [&, threadId]()
            {
                int queueIndex = threadId % NUM_QUEUES; // Distribute threads across queues
                auto& queue = queues[queueIndex];

                for (int i = 0; i < ELEMENTS_PER_THREAD; ++i)
                {
                    std::string data = "thread_" + std::to_string(threadId) + "_element_" + std::to_string(i);
                    queue->push(data);

                    // Print progress every 500k elements
                    if (i % 500000 == 0 && i > 0)
                    {
                        std::cout << "Thread " << threadId << " pushed " << i << " elements" << std::endl;
                        printSharedBufferStats("Thread " + std::to_string(threadId) + " progress");
                    }
                }

                threadsCompleted++;
                std::cout << "Thread " << threadId << " completed. Total completed: " << threadsCompleted.load() << "/"
                          << NUM_THREADS << std::endl;
            });
    }

    // Monitor memory usage while threads are running
    std::thread memoryMonitor(
        [&threadsCompleted, NUM_THREADS]()
        {
            while (threadsCompleted.load() < NUM_THREADS)
            {
                std::this_thread::sleep_for(std::chrono::seconds(15));
                printSharedBufferStats("Memory monitor");
            }
        });

    // Wait for all threads to complete
    for (auto& thread : threads)
    {
        thread.join();
    }

    memoryMonitor.join();

    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime);

    printSharedBufferStats("After all threads completed");

    std::cout << "Stress test completed in " << duration.count() << " seconds" << std::endl;
    std::cout << "Total elements pushed: " << (NUM_THREADS * ELEMENTS_PER_THREAD) << std::endl;

    // Verify some elements exist in each queue
    for (int i = 0; i < NUM_QUEUES; ++i)
    {
        EXPECT_FALSE(queues[i]->empty()) << "Queue " << i << " should not be empty";
    }

    printSharedBufferStats("Before cleanup");

    // Cleanup: cancel all queues and clear the vector
    for (auto& queue : queues)
    {
        queue->cancel();
    }
    queues.clear();

    // Remove test databases
    for (int i = 0; i < NUM_QUEUES; ++i)
    {
        std::string dbName = "stress_test_" + std::to_string(i) + ".db";
        std::error_code ec;
        std::filesystem::remove_all(dbName, ec);
    }

    printSharedBufferStats("After cleanup - buffers should persist");
}
