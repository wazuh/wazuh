/*
 * Wazuh router - Subscriber tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "provider.hpp"
#include "src/subscriber.hpp"
#include <atomic>
#include <chrono>
#include <functional>
#include <gtest/gtest.h>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

/**
 * @brief Runs unit tests for Subscriber class
 */
class SubscriberTest : public ::testing::Test
{
protected:
    SubscriberTest() = default;
    ~SubscriberTest() override = default;
};

/*
 * @brief Test the instantiation of the Subscriber class
 */
TEST_F(SubscriberTest, TestSubscriberInstantiation)
{
    constexpr auto OBSERVER_ID {"subscriber-id"};
    const std::function<void(const std::vector<char>&)> callback;

    // Check that the Subscriber class can be instantiated
    EXPECT_NO_THROW(std::make_shared<Subscriber<const std::vector<char>&>>(callback, OBSERVER_ID));
}

/*
 * @brief Tests the Subscriber class with empty observer id.
 */
TEST_F(SubscriberTest, TestSubscriberWithEmptyObserverId)
{
    constexpr auto OBSERVER_ID {""};
    const std::function<void(const std::vector<char>&)> callback;

    // Check that the Subscriber class can be instantiated
    EXPECT_NO_THROW(std::make_shared<Subscriber<const std::vector<char>&>>(callback, OBSERVER_ID));
}

/*
 * @brief Tests the update method call of the Subscriber class.
 */
TEST_F(SubscriberTest, TestSubscriberUpdateMethod)
{
    constexpr auto OBSERVER_ID {"subscriber-id"};
    constexpr auto EXPECTED_CAPTURED_OUTPUT {"hello!\n"};

    const std::vector<char> data = {'h', 'e', 'l', 'l', 'o', '!'};
    const std::function<void(const std::vector<char>&)> callback = [](const std::vector<char>& data)
    {
        std::cout << std::string(data.begin(), data.end()) << "\n";
    };

    const auto subscriber {std::make_shared<Subscriber<const std::vector<char>&>>(callback, OBSERVER_ID)};

    testing::internal::CaptureStdout();

    EXPECT_NO_THROW(subscriber->update(data));

    const auto capturedOutput {testing::internal::GetCapturedStdout()};

    EXPECT_EQ(capturedOutput, EXPECTED_CAPTURED_OUTPUT);
}

TEST_F(SubscriberTest, TestRemoveSubscriberNonExistent)
{
    const std::string id = "nonExistent";
    Provider<std::string> provider;

    EXPECT_ANY_THROW(provider.removeSubscriber(id));
}

/*
 * @brief Tests multiple subscribers with the same ID
 */
TEST_F(SubscriberTest, TestMultipleSubscribersSameId)
{
    const std::string id = "duplicate";
    Provider<std::string> provider;
    std::atomic<int> callCount1 {0};
    std::atomic<int> callCount2 {0};

    auto callback1 = [&callCount1](const std::string& /*data*/)
    {
        callCount1++;
    };
    auto callback2 = [&callCount2](const std::string& /*data*/)
    {
        callCount2++;
    };

    auto subscriber1 = std::make_shared<Subscriber<std::string>>(callback1, id);
    auto subscriber2 = std::make_shared<Subscriber<std::string>>(callback2, id);

    provider.addSubscriber(subscriber1);
    provider.addSubscriber(subscriber2); // Same ID - should replace the first one

    provider.call("test data");

    // Give some time for callbacks to execute
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Only the second callback should be called since it replaced the first
    EXPECT_EQ(callCount1.load(), 0);
    EXPECT_EQ(callCount2.load(), 1);
}

/*
 * @brief Tests subscriber with empty ID
 */
TEST_F(SubscriberTest, TestSubscriberEmptyId)
{
    const std::string emptyId;
    Provider<std::string> provider;
    std::atomic<bool> callbackCalled {false};

    auto callback = [&callbackCalled](const std::string& /*data*/)
    {
        callbackCalled = true;
    };
    auto subscriber = std::make_shared<Subscriber<std::string>>(callback, emptyId);

    EXPECT_NO_THROW(provider.addSubscriber(subscriber));
    EXPECT_NO_THROW(provider.call("test data"));

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_TRUE(callbackCalled.load());
}

/*
 * @brief Tests subscriber with very long ID
 */
TEST_F(SubscriberTest, TestSubscriberLongId)
{
    std::string longId(1000, 'X'); // Very long ID
    Provider<std::string> provider;
    std::atomic<bool> callbackCalled {false};

    auto callback = [&callbackCalled](const std::string& /*data*/)
    {
        callbackCalled = true;
    };
    auto subscriber = std::make_shared<Subscriber<std::string>>(callback, longId);

    EXPECT_NO_THROW(provider.addSubscriber(subscriber));
    EXPECT_NO_THROW(provider.call("test data"));

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_TRUE(callbackCalled.load());

    EXPECT_NO_THROW(provider.removeSubscriber(longId));
}

/*
 * @brief Tests subscriber with special characters in ID
 */
TEST_F(SubscriberTest, TestSubscriberSpecialCharacterId)
{
    const std::string specialId = "test-subscriber!@#$%^&*()_+{}|:<>?[]\\;'\".,/~`";
    Provider<std::string> provider;
    std::atomic<bool> callbackCalled {false};

    auto callback = [&callbackCalled](const std::string& /*data*/)
    {
        callbackCalled = true;
    };
    auto subscriber = std::make_shared<Subscriber<std::string>>(callback, specialId);

    EXPECT_NO_THROW(provider.addSubscriber(subscriber));
    EXPECT_NO_THROW(provider.call("test data"));

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_TRUE(callbackCalled.load());

    EXPECT_NO_THROW(provider.removeSubscriber(specialId));
}

/*
 * @brief Tests concurrent subscriber operations
 */
TEST_F(SubscriberTest, TestConcurrentSubscriberOperations)
{
    Provider<std::string> provider;
    const int numThreads = 4;
    const int subscribersPerThread = 10;
    std::vector<std::thread> threads;
    threads.reserve(numThreads);
    std::atomic<int> totalCallbacks {0};

    // Create subscribers concurrently
    for (int t = 0; t < numThreads; ++t)
    {
        threads.emplace_back(
            [&provider, &totalCallbacks, t]()
            {
                for (int i = 0; i < subscribersPerThread; ++i)
                {
                    std::string id = "thread-" + std::to_string(t) + "-subscriber-" + std::to_string(i);
                    auto callback = [&totalCallbacks](const std::string& /*data*/)
                    {
                        totalCallbacks++;
                    };
                    auto subscriber = std::make_shared<Subscriber<std::string>>(callback, id);
                    provider.addSubscriber(subscriber);
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    // Call all subscribers
    provider.call("concurrent test");

    // Give time for all callbacks to execute
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    EXPECT_EQ(totalCallbacks.load(), numThreads * subscribersPerThread);
}

/*
 * @brief Tests subscriber callback with exception
 */
TEST_F(SubscriberTest, TestSubscriberCallbackException)
{
    const std::string id = "exception-subscriber";
    Provider<std::string> provider;
    std::atomic<bool> exceptionThrown {false};

    auto throwingCallback = [&exceptionThrown](const std::string& /*data*/)
    {
        exceptionThrown = true;
        throw std::runtime_error("Test exception");
    };

    auto subscriber = std::make_shared<Subscriber<std::string>>(throwingCallback, id);
    provider.addSubscriber(subscriber);

    EXPECT_ANY_THROW(provider.call("test data"));

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_TRUE(exceptionThrown.load());
}

/*
 * @brief Tests subscriber with different data types
 */
TEST_F(SubscriberTest, TestSubscriberDifferentDataTypes)
{
    // Test with int data type
    {
        Provider<int> intProvider;
        std::atomic<int> receivedValue {0};

        auto callback = [&receivedValue](const int& data)
        {
            receivedValue = data;
        };
        auto subscriber = std::make_shared<Subscriber<int>>(callback, "int-subscriber");

        intProvider.addSubscriber(subscriber);
        intProvider.call(42);

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        EXPECT_EQ(receivedValue.load(), 42);
    }

    // Test with vector data type
    {
        Provider<std::vector<int>> vectorProvider;
        std::atomic<bool> callbackCalled {false};
        std::vector<int> receivedData;

        auto callback = [&callbackCalled, &receivedData](const std::vector<int>& data)
        {
            callbackCalled = true;
            receivedData = data;
        };
        auto subscriber = std::make_shared<Subscriber<std::vector<int>>>(callback, "vector-subscriber");

        vectorProvider.addSubscriber(subscriber);
        std::vector<int> testData = {1, 2, 3, 4, 5};
        vectorProvider.call(testData);

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        EXPECT_TRUE(callbackCalled.load());
        EXPECT_EQ(receivedData, testData);
    }
}

/*
 * @brief Tests rapid subscriber addition and removal
 */
TEST_F(SubscriberTest, TestRapidSubscriberAddRemove)
{
    Provider<std::string> provider;
    const int numOperations = 100;

    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < numOperations; ++i)
    {
        std::string id = "rapid-subscriber-" + std::to_string(i);
        auto callback = [](const std::string& /*data*/) {
        };
        auto subscriber = std::make_shared<Subscriber<std::string>>(callback, id);

        provider.addSubscriber(subscriber);
        provider.removeSubscriber(id);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    // Should complete in reasonable time (less than 100ms)
    EXPECT_LT(duration.count(), 100000);
}

/*
 * @brief Tests subscriber callback data integrity
 */
TEST_F(SubscriberTest, TestSubscriberDataIntegrity)
{
    Provider<std::string> provider;
    std::string receivedData;
    std::mutex dataMutex;

    auto callback = [&receivedData, &dataMutex](const std::string& data)
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        receivedData = data;
    };

    auto subscriber = std::make_shared<Subscriber<std::string>>(callback, "integrity-subscriber");
    provider.addSubscriber(subscriber);

    const std::string testData = "This is a test message with special characters: !@#$%^&*()";
    provider.call(testData);

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    std::lock_guard<std::mutex> lock(dataMutex);
    EXPECT_EQ(receivedData, testData);
}

/*
 * @brief Tests subscriber callback with large data
 */
TEST_F(SubscriberTest, TestSubscriberLargeData)
{
    Provider<std::string> provider;
    std::atomic<bool> callbackCalled {false};
    std::string receivedData;

    auto callback = [&callbackCalled, &receivedData](const std::string& data)
    {
        callbackCalled = true;
        receivedData = data;
    };

    auto subscriber = std::make_shared<Subscriber<std::string>>(callback, "large-data-subscriber");
    provider.addSubscriber(subscriber);

    // Create large string (100KB)
    std::string largeData(100 * 1024, 'L');
    provider.call(largeData);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    EXPECT_TRUE(callbackCalled.load());
    EXPECT_EQ(receivedData.size(), largeData.size());
}

/*
 * @brief Tests provider with no subscribers
 */
TEST_F(SubscriberTest, TestProviderNoSubscribers)
{
    Provider<std::string> provider;

    // Should not throw when calling with no subscribers
    EXPECT_NO_THROW(provider.call("test data"));
}

/*
 * @brief Tests provider state after subscriber removal
 */
TEST_F(SubscriberTest, TestProviderStateAfterRemoval)
{
    Provider<std::string> provider;
    std::atomic<int> callCount {0};

    auto callback = [&callCount](const std::string& /*data*/)
    {
        callCount++;
    };
    auto subscriber = std::make_shared<Subscriber<std::string>>(callback, "removable-subscriber");

    provider.addSubscriber(subscriber);
    provider.call("first call");

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_EQ(callCount.load(), 1);

    provider.removeSubscriber("removable-subscriber");
    provider.call("second call");

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_EQ(callCount.load(), 1); // Should still be 1, not 2
}

/*
 * @brief Tests multiple calls to the same subscriber
 */
TEST_F(SubscriberTest, TestMultipleCallsSameSubscriber)
{
    Provider<std::string> provider;
    std::atomic<int> callCount {0};
    std::vector<std::string> receivedData;
    std::mutex dataMutex;

    auto callback = [&callCount, &receivedData, &dataMutex](const std::string& data)
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        callCount++;
        receivedData.push_back(data);
    };

    auto subscriber = std::make_shared<Subscriber<std::string>>(callback, "multi-call-subscriber");
    provider.addSubscriber(subscriber);

    const int numCalls = 10;
    for (int i = 0; i < numCalls; ++i)
    {
        provider.call("message-" + std::to_string(i));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    EXPECT_EQ(callCount.load(), numCalls);

    std::lock_guard<std::mutex> lock(dataMutex);
    EXPECT_EQ(receivedData.size(), static_cast<size_t>(numCalls));

    for (int i = 0; i < numCalls; ++i)
    {
        EXPECT_EQ(receivedData[i], "message-" + std::to_string(i));
    }
}
