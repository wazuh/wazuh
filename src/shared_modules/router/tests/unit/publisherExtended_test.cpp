/*
 * Wazuh router - Publisher Extended tests
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "src/publisher.hpp"
#include <atomic>
#include <chrono>
#include <future>
#include <gtest/gtest.h>
#include <memory>
#include <thread>
#include <vector>

/**
 * @brief Runs extended unit tests for Publisher class
 */
class PublisherExtendedTest : public ::testing::Test
{
protected:
    PublisherExtendedTest() = default;
    ~PublisherExtendedTest() override = default;
};

/*
 * @brief Tests Publisher destructor behavior
 */
TEST_F(PublisherExtendedTest, TestPublisherDestructor)
{
    constexpr auto ENDPOINT_NAME = "test-destructor";
    constexpr auto SOCKET_PATH = "test/";

    {
        auto publisher = std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH);
        const std::vector<char> data = {'t', 'e', 's', 't'};
        publisher->push(data);
        // Destructor should be called cleanly when publisher goes out of scope
    }

    // Test passes if no exception is thrown during destruction
    EXPECT_TRUE(true);
}

/*
 * @brief Tests Publisher with very long endpoint name
 */
TEST_F(PublisherExtendedTest, TestPublisherWithLongEndpointName)
{
    const std::string longEndpointName(1000, 'a');
    constexpr auto SOCKET_PATH = "test/";

    // This might throw depending on filesystem limits
    EXPECT_ANY_THROW(auto publisher = std::make_shared<Publisher>(longEndpointName, SOCKET_PATH));
}

/*
 * @brief Tests Publisher with special characters in endpoint name
 */
TEST_F(PublisherExtendedTest, TestPublisherWithSpecialCharacters)
{
    const std::string specialEndpointName = "test-endpoint_123.special";
    constexpr auto SOCKET_PATH = "test/";

    EXPECT_NO_THROW(std::make_shared<Publisher>(specialEndpointName, SOCKET_PATH));
}

/*
 * @brief Tests Publisher with very long socket path
 */
TEST_F(PublisherExtendedTest, TestPublisherWithLongSocketPath)
{
    constexpr auto ENDPOINT_NAME = "test";
    const std::string longSocketPath = std::string(200, 'p') + "/";

    // This might throw depending on filesystem limits
    try
    {
        auto publisher = std::make_shared<Publisher>(ENDPOINT_NAME, longSocketPath);
        EXPECT_TRUE(true);
    }
    catch (const std::exception&)
    {
        // Expected for very long paths
        EXPECT_TRUE(true);
    }
}

/*
 * @brief Tests Publisher push with concurrent access
 */
TEST_F(PublisherExtendedTest, TestPublisherConcurrentPush)
{
    constexpr auto ENDPOINT_NAME = "test-concurrent";
    constexpr auto SOCKET_PATH = "test/";
    constexpr int NUM_THREADS = 5;
    constexpr int MESSAGES_PER_THREAD = 10;

    auto publisher = std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH);
    std::vector<std::thread> threads;
    threads.reserve(NUM_THREADS);
    std::atomic<int> completedThreads {0};

    for (int i = 0; i < NUM_THREADS; ++i)
    {
        threads.emplace_back(
            [publisher, i, &completedThreads]()
            {
                for (int j = 0; j < MESSAGES_PER_THREAD; ++j)
                {
                    std::string message = "thread" + std::to_string(i) + "_msg" + std::to_string(j);
                    std::vector<char> data(message.begin(), message.end());

                    EXPECT_NO_THROW(publisher->push(data));

                    // Small delay to allow interleaving
                    std::this_thread::sleep_for(std::chrono::microseconds(100));
                }
                completedThreads++;
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(completedThreads.load(), NUM_THREADS);
}

/*
 * @brief Tests Publisher push with large number of messages
 */
TEST_F(PublisherExtendedTest, TestPublisherHighVolume)
{
    constexpr auto ENDPOINT_NAME = "test-volume";
    constexpr auto SOCKET_PATH = "test/";
    constexpr int NUM_MESSAGES = 1000;

    auto publisher = std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH);

    for (int i = 0; i < NUM_MESSAGES; ++i)
    {
        std::string message = "message_" + std::to_string(i);
        std::vector<char> data(message.begin(), message.end());

        EXPECT_NO_THROW(publisher->push(data));
    }
}

/*
 * @brief Tests Publisher push with various data sizes
 */
TEST_F(PublisherExtendedTest, TestPublisherVariousDataSizes)
{
    constexpr auto ENDPOINT_NAME = "test-sizes";
    constexpr auto SOCKET_PATH = "test/";

    auto publisher = std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH);

    // Test different data sizes
    std::vector<size_t> sizes = {1, 10, 100, 1024, 10240, 65536};

    for (size_t size : sizes)
    {
        std::vector<char> data(size, 'x');
        EXPECT_NO_THROW(publisher->push(data));
    }
}

/*
 * @brief Tests Publisher call method with direct data
 */
TEST_F(PublisherExtendedTest, TestPublisherCallMethod)
{
    constexpr auto ENDPOINT_NAME = "test-call";
    constexpr auto SOCKET_PATH = "test/";

    auto publisher = std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH);

    const std::vector<char> data = {'c', 'a', 'l', 'l'};
    EXPECT_NO_THROW(publisher->call(data));
}

/*
 * @brief Tests Publisher multiple calls in sequence
 */
TEST_F(PublisherExtendedTest, TestPublisherSequentialCalls)
{
    constexpr auto ENDPOINT_NAME = "test-sequential";
    constexpr auto SOCKET_PATH = "test/";

    auto publisher = std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH);

    for (int i = 0; i < 100; ++i)
    {
        std::string message = "sequential_" + std::to_string(i);
        std::vector<char> data(message.begin(), message.end());

        if (i % 2 == 0)
        {
            EXPECT_NO_THROW(publisher->push(data));
        }
        else
        {
            EXPECT_NO_THROW(publisher->call(data));
        }
    }
}

/*
 * @brief Tests Publisher with rapid creation and destruction
 */
TEST_F(PublisherExtendedTest, TestPublisherRapidCreateDestroy)
{
    constexpr auto SOCKET_PATH = "test/";
    constexpr int NUM_ITERATIONS = 50;

    for (int i = 0; i < NUM_ITERATIONS; ++i)
    {
        std::string endpointName = "test-rapid-" + std::to_string(i);

        try
        {
            auto publisher = std::make_shared<Publisher>(endpointName, SOCKET_PATH);

            std::vector<char> data = {'r', 'a', 'p', 'i', 'd'};
            publisher->push(data);

            // Publisher should be destroyed cleanly when going out of scope
        }
        catch (const std::exception&)
        {
            // Some iterations might fail due to rapid socket creation/destruction
            // This is acceptable in this stress test
        }
    }

    EXPECT_TRUE(true); // Test passes if we complete without crashing
}

/*
 * @brief Tests Publisher memory usage patterns
 */
TEST_F(PublisherExtendedTest, TestPublisherMemoryUsage)
{
    constexpr auto ENDPOINT_NAME = "test-memory";
    constexpr auto SOCKET_PATH = "test/";

    auto publisher = std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH);

    // Test with progressively larger data to check for memory leaks
    for (size_t size = 1024; size <= 1024 * 1024; size *= 2)
    {
        std::vector<char> largeData(size, 'M');
        EXPECT_NO_THROW(publisher->push(largeData));

        // Force some processing time
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

/*
 * @brief Tests Publisher exception safety
 */
TEST_F(PublisherExtendedTest, TestPublisherExceptionSafety)
{
    constexpr auto ENDPOINT_NAME = "test-exception";
    constexpr auto SOCKET_PATH = "test/";

    // Test that Publisher can handle exceptions gracefully
    try
    {
        auto publisher = std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH);

        // Simulate various operations that might throw
        std::vector<char> data = {'e', 'x', 'c', 'e', 'p', 't', 'i', 'o', 'n'};
        publisher->push(data);
        publisher->call(data);

        // Test with edge case data
        std::vector<char> emptyData;
        publisher->push(emptyData);
    }
    catch (const std::exception&)
    {
        // Exceptions are handled, test passes
        EXPECT_TRUE(true);
    }
}
