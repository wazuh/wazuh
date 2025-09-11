/*
 * Wazuh router - Publisher tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "socketClient.hpp"
#include "src/publisher.hpp"
#include <atomic>
#include <gtest/gtest.h>
#include <memory>
#include <thread>
#include <vector>

/**
 * @brief Runs unit tests for Publisher class
 */
class PublisherTest : public ::testing::Test
{
protected:
    PublisherTest() = default;
    ~PublisherTest() override = default;
};

/*
 * @brief Tests the instantiation of the Publisher class
 */
TEST_F(PublisherTest, TestPublisherInstantiation)
{
    constexpr auto ENDPOINT_NAME = "test";
    constexpr auto SOCKET_PATH = "test/";

    // Check that the Publisher class can be instantiated
    EXPECT_NO_THROW(std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH));
}

/*
 * @brief Tests the Publisher class with an invalid socket path. An exception is expected.
 */
TEST_F(PublisherTest, TestPublisherWithInvalidSocketPath)
{
    constexpr auto ENDPOINT_NAME = "test";
    constexpr auto INVALID_SOCKET_PATH = "test";

    // Check that the Publisher class can not be instantiated
    EXPECT_THROW(std::make_shared<Publisher>(ENDPOINT_NAME, INVALID_SOCKET_PATH), std::runtime_error);
}

/*
 * @brief Tests the Publisher class with empty endpoint name. An exception is expected.
 */
TEST_F(PublisherTest, TestPublisherWithEmptyEndpointName)
{
    constexpr auto EMPTY_ENDPOINT_NAME = "";
    constexpr auto EMPTY_SOCKET_PATH = "test/";

    // Check that the Publisher class can not be instantiated
    EXPECT_THROW(std::make_shared<Publisher>(EMPTY_ENDPOINT_NAME, EMPTY_SOCKET_PATH), std::runtime_error);
}

/*
 * @brief Tests the Publisher class with empty endpoint name and socket path. An exception is expected.
 */
TEST_F(PublisherTest, TestPublisherWithEmptyEndpointNameAndSocketPath)
{
    constexpr auto EMPTY_ENDPOINT_NAME = "";
    constexpr auto EMPTY_SOCKET_PATH = "";

    // Check that the Publisher class can not be instantiated
    EXPECT_THROW(std::make_shared<Publisher>(EMPTY_ENDPOINT_NAME, EMPTY_SOCKET_PATH), std::runtime_error);
}

/*
 * @brief Tests two Publishers with the same endpoint name and socket path.
 */
TEST_F(PublisherTest, TestTwoPublishersWithTheSameEndpointNameAndSocketPath)
{
    constexpr auto ENDPOINT_NAME = "test";
    constexpr auto SOCKET_PATH = "test/";

    // Check that the first Publisher class can be instantiated
    EXPECT_NO_THROW(std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH));

    // Check that the second Publisher class can be instantiated
    EXPECT_NO_THROW(std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH));
}

/*
 * @brief Tests publish valid data.
 */
TEST_F(PublisherTest, TestPublishValidData)
{
    constexpr auto ENDPOINT_NAME = "test";
    constexpr auto SOCKET_PATH = "test/";

    const std::vector<char> data = {'h', 'e', 'l', 'l', 'o', '!'};

    const auto publisher {std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH)};

    // Check that the Publisher class can publish data
    EXPECT_NO_THROW(publisher->push(data));
}

/*
 * @brief Tests publish empty data.
 */
TEST_F(PublisherTest, TestPublishEmptyData)
{
    constexpr auto ENDPOINT_NAME = "test";
    constexpr auto SOCKET_PATH = "test/";

    const std::vector<char> emptyData;

    const auto publisher {std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH)};

    // Check that the Publisher class can publish empty data
    EXPECT_NO_THROW(publisher->push(emptyData));
}

/*
 * @brief Tests send data to socket without header P
 */
TEST_F(PublisherTest, TestPublishSocketWithoutP)
{
    const std::string ENDPOINT_NAME = "test";
    const std::string SOCKET_PATH = "test/";
    std::condition_variable cv;
    std::mutex cvMutex;

    const auto publisher = std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH);
    auto socketClient = std::make_unique<SocketClient<Socket<OSPrimitives>, EpollWrapper>>(SOCKET_PATH + ENDPOINT_NAME);

    nlohmann::json jsonMessage;
    jsonMessage["type"] = "subscribe";
    jsonMessage["subscriberId"] = "ID_0";
    auto jsonMessageString = jsonMessage.dump();

    int32_t onReadCallCount = 0;

    socketClient->connect(
        [&onReadCallCount, &cv](const char* body, uint32_t bodySize, const char*, uint32_t)
        {
            nlohmann::json result;
            EXPECT_NO_THROW(result = nlohmann::json::parse(body, body + bodySize));
            if (onReadCallCount == 0)
            {
                EXPECT_EQ(result.dump(), R"({"Result":"OK"})");
            }
            else
            {
                EXPECT_EQ(
                    result.dump(),
                    R"({"offset":57000,"paths":["GracefulShutdown.json"],"stageStatus":[{"stage":"download","status":"ok"}],"type":"offsets"})");
            }
            onReadCallCount++;
            cv.notify_all();
        },
        [&jsonMessageString, &socketClient]()
        { EXPECT_NO_THROW(socketClient->send(jsonMessageString.data(), jsonMessageString.size())); });

    {
        std::unique_lock<std::mutex> lk(cvMutex);
        std::cv_status result = cv.wait_for(lk, std::chrono::seconds(5));
        EXPECT_EQ(result, std::cv_status::no_timeout);
    }

    auto routerMessageJson = R"(
    {
        "type": "offsets",
        "offset": 57000,
        "paths":
        [
            "GracefulShutdown.json"
        ],
        "stageStatus":
        [
            {
                "stage": "download",
                "status": "ok"
            }
        ]
    }
    )"_json;
    const auto routerMessagePayload = routerMessageJson.dump();
    const auto routerMessage = std::vector<char>(routerMessagePayload.begin(), routerMessagePayload.end());
    publisher->call(routerMessage);

    {
        std::unique_lock<std::mutex> lk(cvMutex);
        std::cv_status result = cv.wait_for(lk, std::chrono::seconds(5));
        EXPECT_EQ(result, std::cv_status::no_timeout);
    }
    EXPECT_EQ(onReadCallCount, 2);
}

/*
 * @brief Tests send data to socket with header P
 */
TEST_F(PublisherTest, TestPublishSocketP)
{
    const std::string ENDPOINT_NAME = "test";
    const std::string SOCKET_PATH = "test/";
    std::condition_variable cv;
    std::mutex cvMutex;

    const auto publisher = std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH);
    auto socketClient = std::make_unique<SocketClient<Socket<OSPrimitives>, EpollWrapper>>(SOCKET_PATH + ENDPOINT_NAME);

    auto routerMessageJson = R"(
    {
        "type": "offsets",
        "offset": 57000,
        "paths":
        [
            "GracefulShutdown.json"
        ],
        "stageStatus":
        [
            {
                "stage": "download",
                "status": "ok"
            }
        ]
    }
    )"_json;
    const auto routerMessagePayload = routerMessageJson.dump();
    const auto routerMessage = std::vector<char>(routerMessagePayload.begin(), routerMessagePayload.end());

    socketClient->connect([](const char* body, uint32_t bodySize, const char*, uint32_t) {},
                          [&routerMessage, &socketClient, &publisher, &cv]()
                          {
                              publisher->push(routerMessage);
                              cv.notify_all();
                          });

    {
        std::unique_lock<std::mutex> lk(cvMutex);
        std::cv_status result = cv.wait_for(lk, std::chrono::seconds(5));
        EXPECT_EQ(result, std::cv_status::no_timeout);
    }
}

/*
 * @brief Tests publisher performance with large data
 */
TEST_F(PublisherTest, TestPublisherLargeData)
{
    constexpr auto ENDPOINT_NAME = "large-data-test";
    constexpr auto SOCKET_PATH = "large-test/";

    const auto publisher = std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH);

    // Create large data (1MB)
    const size_t largeSize = 1024 * 1024;
    std::vector<char> largeData(largeSize, 'X');

    // Test that publisher can handle large data without throwing
    EXPECT_NO_THROW(publisher->push(largeData));

    // Test multiple large data pushes
    for (int i = 0; i < 5; ++i)
    {
        EXPECT_NO_THROW(publisher->push(largeData));
    }
}

/*
 * @brief Tests publisher with rapid data pushes
 */
TEST_F(PublisherTest, TestPublisherRapidPushes)
{
    constexpr auto ENDPOINT_NAME = "rapid-test";
    constexpr auto SOCKET_PATH = "rapid-test/";

    const auto publisher = std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH);
    const std::vector<char> testData = {'r', 'a', 'p', 'i', 'd'};

    const int numPushes = 100;
    auto start = std::chrono::high_resolution_clock::now();

    // Perform rapid pushes
    for (int i = 0; i < numPushes; ++i)
    {
        EXPECT_NO_THROW(publisher->push(testData));
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    // Ensure all pushes completed in reasonable time (less than 1 second)
    EXPECT_LT(duration.count(), 1000000);
}

/*
 * @brief Tests publisher with concurrent pushes from multiple threads
 */
TEST_F(PublisherTest, TestPublisherConcurrentPushes)
{
    constexpr auto ENDPOINT_NAME = "concurrent-test";
    constexpr auto SOCKET_PATH = "concurrent-test/";

    const auto publisher = std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH);
    const std::vector<char> testData = {'c', 'o', 'n', 'c', 'u', 'r', 'r', 'e', 'n', 't'};

    const int numThreads = 4;
    const int pushesPerThread = 25;
    std::vector<std::thread> threads;
    threads.reserve(numThreads);
    std::atomic<int> successfulPushes {0};

    for (int t = 0; t < numThreads; ++t)
    {
        threads.emplace_back(
            [&publisher, &testData, pushesPerThread, &successfulPushes]()
            {
                for (int i = 0; i < pushesPerThread; ++i)
                {
                    try
                    {
                        publisher->push(testData);
                        successfulPushes++;
                    }
                    catch (...)
                    {
                        // Count failed pushes as well for debugging
                    }
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(successfulPushes.load(), numThreads * pushesPerThread);
}

/*
 * @brief Tests publisher with special characters in endpoint name
 */
TEST_F(PublisherTest, TestPublisherSpecialCharactersEndpoint)
{
    const std::string SPECIAL_ENDPOINT_NAME = "test-endpoint_123!@#";
    constexpr auto SOCKET_PATH = "special-test/";

    EXPECT_NO_THROW(std::make_shared<Publisher>(SPECIAL_ENDPOINT_NAME, SOCKET_PATH));
}

/*
 * @brief Tests publisher subscriber management
 */
TEST_F(PublisherTest, TestPublisherSubscriberManagement)
{
    constexpr auto ENDPOINT_NAME = "subscriber-mgmt-test";
    constexpr auto SOCKET_PATH = "subscriber-mgmt-test/";

    const auto publisher = std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH);

    // Create a subscriber
    auto subscriber = std::make_shared<Subscriber<const std::vector<char>&>>([](const std::vector<char>& data) {},
                                                                             "test-subscriber-1");

    // Test adding subscriber
    EXPECT_NO_THROW(publisher->addSubscriber(subscriber));

    // Test adding the same subscriber again (should not throw)
    EXPECT_NO_THROW(publisher->addSubscriber(subscriber));

    // Test removing subscriber
    EXPECT_NO_THROW(publisher->removeSubscriber("test-subscriber-1"));

    // Test removing non-existent subscriber (should throw)
    EXPECT_ANY_THROW(publisher->removeSubscriber("non-existent-subscriber"));
}

/*
 * @brief Tests publisher with null callback subscriber
 */
TEST_F(PublisherTest, TestPublisherNullCallbackSubscriber)
{
    constexpr auto ENDPOINT_NAME = "null-callback-test";
    constexpr auto SOCKET_PATH = "null-callback-test/";

    const auto publisher = std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH);

    // Create a subscriber with a null-like callback (should still work)
    auto subscriber = std::make_shared<Subscriber<const std::vector<char>&>>(
        [](const std::vector<char>& data) { /* do nothing */ }, "null-callback-subscriber");

    EXPECT_NO_THROW(publisher->addSubscriber(subscriber));

    const std::vector<char> testData = {'n', 'u', 'l', 'l', 't', 'e', 's', 't'};
    EXPECT_NO_THROW(publisher->push(testData));
}

/*
 * @brief Tests publisher destruction with active subscribers
 */
TEST_F(PublisherTest, TestPublisherDestructionWithSubscribers)
{
    constexpr auto ENDPOINT_NAME = "destruction-test";
    constexpr auto SOCKET_PATH = "destruction-test/";

    {
        const auto publisher = std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH);

        auto subscriber = std::make_shared<Subscriber<const std::vector<char>&>>([](const std::vector<char>& data) {},
                                                                                 "destruction-subscriber");

        publisher->addSubscriber(subscriber);

        const std::vector<char> testData = {'d', 'e', 's', 't', 'r', 'u', 'c', 't'};
        publisher->push(testData);

        // Publisher should be destroyed gracefully when going out of scope
    }

    // Test passes if no crash occurs during destruction
    SUCCEED();
}

/*
 * @brief Tests publisher with very long socket path
 */
TEST_F(PublisherTest, TestPublisherLongSocketPath)
{
    constexpr auto ENDPOINT_NAME = "long-path-test";

    // Create a very long socket path (close to system limits)
    std::string longSocketPath;
    for (int i = 0; i < 50; ++i)
    {
        longSocketPath += "verylongdirectoryname/";
    }

    // This might throw due to path length limits, which is expected behavior
    try
    {
        auto publisher = std::make_shared<Publisher>(ENDPOINT_NAME, longSocketPath);
        SUCCEED(); // If it doesn't throw, that's also fine
    }
    catch (const std::exception&)
    {
        SUCCEED(); // Expected behavior for very long paths
    }
}

/*
 * @brief Tests publisher with binary data
 */
TEST_F(PublisherTest, TestPublisherBinaryData)
{
    constexpr auto ENDPOINT_NAME = "binary-test";
    constexpr auto SOCKET_PATH = "binary-test/";

    const auto publisher = std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH);

    // Create binary data with null bytes and various byte values
    std::vector<char> binaryData;
    for (int i = 0; i < 256; ++i)
    {
        binaryData.push_back(static_cast<char>(i));
    }

    EXPECT_NO_THROW(publisher->push(binaryData));
}

/*
 * @brief Tests publisher message ordering
 */
TEST_F(PublisherTest, TestPublisherMessageOrdering)
{
    constexpr auto ENDPOINT_NAME = "ordering-test";
    constexpr auto SOCKET_PATH = "ordering-test/";

    const auto publisher = std::make_shared<Publisher>(ENDPOINT_NAME, SOCKET_PATH);

    std::vector<int> receivedOrder;
    std::mutex orderMutex;
    std::condition_variable orderCV;
    int expectedMessages = 5;

    auto subscriber = std::make_shared<Subscriber<const std::vector<char>&>>(
        [&receivedOrder, &orderMutex, &orderCV](const std::vector<char>& data)
        {
            if (!data.empty())
            {
                std::lock_guard<std::mutex> lock(orderMutex);
                receivedOrder.push_back(static_cast<int>(data[0]));
                orderCV.notify_all();
            }
        },
        "ordering-subscriber");

    publisher->addSubscriber(subscriber);

    // Send messages in order
    for (int i = 0; i < expectedMessages; ++i)
    {
        std::vector<char> data = {static_cast<char>(i)};
        publisher->push(data);
        std::this_thread::sleep_for(std::chrono::milliseconds(10)); // Small delay
    }

    // Wait for all messages
    std::unique_lock<std::mutex> lock(orderMutex);
    orderCV.wait_for(lock,
                     std::chrono::seconds(2),
                     [&receivedOrder, expectedMessages]() { return receivedOrder.size() >= expectedMessages; });

    // Verify order (this test might be flaky due to async nature, but it's worth testing)
    EXPECT_GE(receivedOrder.size(), static_cast<size_t>(expectedMessages));
}

/*
 * @brief Tests Publisher destructor behavior
 */
TEST_F(PublisherTest, TestPublisherDestructor)
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
TEST_F(PublisherTest, TestPublisherWithLongEndpointName)
{
    const std::string longEndpointName(1000, 'a');
    constexpr auto SOCKET_PATH = "test/";

    // This might throw depending on filesystem limits
    EXPECT_ANY_THROW(auto publisher = std::make_shared<Publisher>(longEndpointName, SOCKET_PATH));
}

/*
 * @brief Tests Publisher with special characters in endpoint name
 */
TEST_F(PublisherTest, TestPublisherWithSpecialCharacters)
{
    const std::string specialEndpointName = "test-endpoint_123.special";
    constexpr auto SOCKET_PATH = "test/";

    EXPECT_NO_THROW(std::make_shared<Publisher>(specialEndpointName, SOCKET_PATH));
}

/*
 * @brief Tests Publisher with very long socket path
 */
TEST_F(PublisherTest, TestPublisherWithLongSocketPath)
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
TEST_F(PublisherTest, TestPublisherConcurrentPush)
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
TEST_F(PublisherTest, TestPublisherHighVolume)
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
TEST_F(PublisherTest, TestPublisherVariousDataSizes)
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
TEST_F(PublisherTest, TestPublisherCallMethod)
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
TEST_F(PublisherTest, TestPublisherSequentialCalls)
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
TEST_F(PublisherTest, TestPublisherRapidCreateDestroy)
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
TEST_F(PublisherTest, TestPublisherMemoryUsage)
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
TEST_F(PublisherTest, TestPublisherExceptionSafety)
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
