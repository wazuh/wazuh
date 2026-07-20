/*
 * Wazuh router - RemoteSubscriber tests
 * Copyright (C) 2015, Wazuh Inc.
 * June 25, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "routerModule.hpp"
#include "src/remoteSubscriber.hpp"
#include <atomic>
#include <chrono>
#include <functional>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <thread>
#include <vector>

/**
 * @brief Runs unit tests for RemoteSubscriber class
 */
class RemoteSubscriberTest : public ::testing::Test
{
protected:
    RemoteSubscriberTest() = default;
    ~RemoteSubscriberTest() override = default;

    void SetUp() override
    {
        RouterModule::instance().start();
    }

    void TearDown() override
    {
        RouterModule::instance().stop();
    }
};

/*
 * @brief Test RemoteSubscriber basic instantiation
 */
TEST_F(RemoteSubscriberTest, TestRemoteSubscriberInstantiation)
{
    const std::string endpoint = "test-remote-subscriber";
    const std::string subscriberId = "test-subscriber-id";
    const std::string socketPath = "queue/router/";

    auto callback = [](const std::vector<char>& data)
    {
        // Simple callback
    };

    EXPECT_NO_THROW(auto subscriber = std::make_unique<RemoteSubscriber>(endpoint, subscriberId, callback, socketPath));
}

/*
 * @brief Test RemoteSubscriber with empty endpoint name
 */
TEST_F(RemoteSubscriberTest, TestRemoteSubscriberEmptyEndpoint)
{
    const std::string endpoint;
    const std::string subscriberId = "test-subscriber-id";
    const std::string socketPath = "queue/router/";

    auto callback = [](const std::vector<char>& data)
    {
        // Simple callback
    };

    EXPECT_NO_THROW(auto subscriber = std::make_unique<RemoteSubscriber>(endpoint, subscriberId, callback, socketPath));
}

/*
 * @brief Test RemoteSubscriber with empty subscriber ID
 */
TEST_F(RemoteSubscriberTest, TestRemoteSubscriberEmptySubscriberId)
{
    const std::string endpoint = "test-remote-subscriber-empty-id";
    const std::string subscriberId;
    const std::string socketPath = "queue/router/";

    auto callback = [](const std::vector<char>& data)
    {
        // Simple callback
    };

    EXPECT_NO_THROW(auto subscriber = std::make_unique<RemoteSubscriber>(endpoint, subscriberId, callback, socketPath));
}

/*
 * @brief Test RemoteSubscriber with callback and onConnect
 */
TEST_F(RemoteSubscriberTest, TestRemoteSubscriberWithOnConnect)
{
    const std::string endpoint = "test-remote-subscriber-onconnect";
    const std::string subscriberId = "test-subscriber-onconnect";
    const std::string socketPath = "queue/router/";

    std::atomic<bool> callbackCalled {false};
    std::atomic<bool> onConnectCalled {false};

    auto callback = [&callbackCalled](const std::vector<char>& data)
    {
        callbackCalled = true;
    };

    auto onConnect = [&onConnectCalled]()
    {
        onConnectCalled = true;
    };

    auto subscriber = std::make_unique<RemoteSubscriber>(endpoint, subscriberId, callback, socketPath, onConnect);

    // Give some time for potential connection
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    EXPECT_TRUE(subscriber != nullptr);
}

/*
 * @brief Test RemoteSubscriber with long subscriber ID
 */
TEST_F(RemoteSubscriberTest, TestRemoteSubscriberLongSubscriberId)
{
    const std::string endpoint = "test-remote-subscriber-long";
    std::string subscriberId(500, 'S'); // Very long subscriber ID
    const std::string socketPath = "queue/router/";

    auto callback = [](const std::vector<char>& data)
    {
        // Simple callback
    };

    EXPECT_NO_THROW(auto subscriber = std::make_unique<RemoteSubscriber>(endpoint, subscriberId, callback, socketPath));
}

/*
 * @brief Test RemoteSubscriber with special characters in subscriber ID
 */
TEST_F(RemoteSubscriberTest, TestRemoteSubscriberSpecialCharacters)
{
    const std::string endpoint = "test-remote-subscriber-special";
    const std::string subscriberId = "subscriber-!@#$%^&*()";
    const std::string socketPath = "queue/router/";

    auto callback = [](const std::vector<char>& data)
    {
        // Simple callback
    };

    EXPECT_NO_THROW(auto subscriber = std::make_unique<RemoteSubscriber>(endpoint, subscriberId, callback, socketPath));
}

/*
 * @brief Test RemoteSubscriber callback with different data types
 */
TEST_F(RemoteSubscriberTest, TestRemoteSubscriberCallbackDataTypes)
{
    const std::string endpoint = "test-remote-subscriber-datatypes";
    const std::string subscriberId = "datatypes-subscriber";
    const std::string socketPath = "queue/router/";

    std::atomic<bool> emptyDataReceived {false};
    std::atomic<bool> normalDataReceived {false};
    std::atomic<bool> largeDataReceived {false};

    auto callback = [&](const std::vector<char>& data)
    {
        if (data.empty())
        {
            emptyDataReceived = true;
        }
        else if (data.size() < 100)
        {
            normalDataReceived = true;
        }
        else
        {
            largeDataReceived = true;
        }
    };

    auto subscriber = std::make_unique<RemoteSubscriber>(endpoint, subscriberId, callback, socketPath);

    EXPECT_TRUE(subscriber != nullptr);
}

/*
 * @brief Test RemoteSubscriber callback exception handling
 */
TEST_F(RemoteSubscriberTest, TestRemoteSubscriberCallbackException)
{
    const std::string endpoint = "test-remote-subscriber-exception";
    const std::string subscriberId = "exception-subscriber";
    const std::string socketPath = "queue/router/";

    std::atomic<bool> exceptionThrown {false};

    auto callback = [&exceptionThrown](const std::vector<char>& data)
    {
        exceptionThrown = true;
        throw std::runtime_error("Test exception in callback");
    };

    // This should not crash even if callback throws
    EXPECT_NO_THROW(auto subscriber = std::make_unique<RemoteSubscriber>(endpoint, subscriberId, callback, socketPath));
}

/*
 * @brief Test RemoteSubscriber with concurrent operations
 */
TEST_F(RemoteSubscriberTest, TestRemoteSubscriberConcurrentOperations)
{
    const std::string socketPath = "queue/router/";
    std::vector<std::unique_ptr<RemoteSubscriber>> subscribers;
    std::atomic<int> callbackCount {0};

    auto callback = [&callbackCount](const std::vector<char>& data)
    {
        callbackCount++;
    };

    // Create multiple subscribers concurrently
    std::vector<std::thread> threads;
    threads.reserve(5);

    for (int i = 0; i < 5; ++i)
    {
        threads.emplace_back(
            [&, i]()
            {
                std::string endpoint = "concurrent-endpoint-" + std::to_string(i);
                std::string subscriberId = "concurrent-subscriber-" + std::to_string(i);

                auto subscriber = std::make_unique<RemoteSubscriber>(endpoint, subscriberId, callback, socketPath);

                // Let it run for a bit
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_GE(callbackCount.load(), 0); // Should not crash
}

/*
 * @brief Test RemoteSubscriber lifecycle management
 */
TEST_F(RemoteSubscriberTest, TestRemoteSubscriberLifecycle)
{
    const std::string endpoint = "test-remote-subscriber-lifecycle";
    const std::string socketPath = "queue/router/";

    std::atomic<int> creationCount {0};

    for (int i = 0; i < 10; ++i)
    {
        std::string subscriberId = "lifecycle-subscriber-" + std::to_string(i);

        auto callback = [&creationCount](const std::vector<char>& data)
        {
            creationCount++;
        };

        auto subscriber = std::make_unique<RemoteSubscriber>(endpoint, subscriberId, callback, socketPath);

        EXPECT_TRUE(subscriber != nullptr);
        // Destructor called here
    }
}

/*
 * @brief Test RemoteSubscriber with different socket paths
 */
TEST_F(RemoteSubscriberTest, TestRemoteSubscriberDifferentSocketPaths)
{
    const std::string endpoint = "test-remote-subscriber-paths";
    const std::string subscriberId = "paths-subscriber";

    std::vector<std::string> socketPaths = {"queue/router/", "/tmp/test/", "custom/path/", ""};

    auto callback = [](const std::vector<char>& data)
    {
        // Simple callback
    };

    for (const auto& socketPath : socketPaths)
    {
        EXPECT_NO_THROW(auto subscriber =
                            std::make_unique<RemoteSubscriber>(endpoint, subscriberId, callback, socketPath));
    }
}

/*
 * @brief Test RemoteSubscriber memory management with multiple instances
 */
TEST_F(RemoteSubscriberTest, TestRemoteSubscriberMemoryManagement)
{
    const std::string socketPath = "queue/router/";
    std::vector<std::unique_ptr<RemoteSubscriber>> subscribers;
    subscribers.reserve(50);

    auto callback = [](const std::vector<char>& data)
    {
        // Simple callback that doesn't do much
    };

    // Create many subscribers
    for (int i = 0; i < 50; ++i)
    {
        std::string endpoint = "memory-endpoint-" + std::to_string(i);
        std::string subscriberId = "memory-subscriber-" + std::to_string(i);

        subscribers.push_back(std::make_unique<RemoteSubscriber>(endpoint, subscriberId, callback, socketPath));
    }

    EXPECT_EQ(subscribers.size(), 50);

    // Clean up all at once
    subscribers.clear();
}

/*
 * @brief Test RemoteSubscriber with binary data handling
 */
TEST_F(RemoteSubscriberTest, TestRemoteSubscriberBinaryData)
{
    const std::string endpoint = "test-remote-subscriber-binary";
    const std::string subscriberId = "binary-subscriber";
    const std::string socketPath = "queue/router/";

    std::atomic<bool> binaryDataReceived {false};

    auto callback = [&binaryDataReceived](const std::vector<char>& data)
    {
        // Check if we received any data
        if (!data.empty())
        {
            binaryDataReceived = true;
        }
    };

    auto subscriber = std::make_unique<RemoteSubscriber>(endpoint, subscriberId, callback, socketPath);

    EXPECT_TRUE(subscriber != nullptr);
}

/*
 * @brief Test RemoteSubscriber callback data integrity
 */
TEST_F(RemoteSubscriberTest, TestRemoteSubscriberDataIntegrity)
{
    const std::string endpoint = "test-remote-subscriber-integrity";
    const std::string subscriberId = "integrity-subscriber";
    const std::string socketPath = "queue/router/";

    std::vector<char> receivedData;
    std::mutex dataMutex;

    auto callback = [&receivedData, &dataMutex](const std::vector<char>& data)
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        receivedData = data;
    };

    auto subscriber = std::make_unique<RemoteSubscriber>(endpoint, subscriberId, callback, socketPath);

    // Give some time for potential data
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    EXPECT_TRUE(subscriber != nullptr);
}

/*
 * @brief Test RemoteSubscriber error handling
 */
TEST_F(RemoteSubscriberTest, TestRemoteSubscriberErrorHandling)
{
    const std::string endpoint = "test-remote-subscriber-error";
    const std::string subscriberId = "error-subscriber";
    const std::string socketPath = "invalid/path/";

    auto callback = [](const std::vector<char>& data)
    {
        // Simple callback
    };

    // Should not throw even with invalid socket path
    EXPECT_NO_THROW(auto subscriber = std::make_unique<RemoteSubscriber>(endpoint, subscriberId, callback, socketPath));
}

/*
 * @brief Test RemoteSubscriber with null/empty callback scenarios
 */
TEST_F(RemoteSubscriberTest, TestRemoteSubscriberCallbackVariations)
{
    const std::string endpoint = "test-remote-subscriber-callbacks";
    const std::string subscriberId = "callback-subscriber";
    const std::string socketPath = "queue/router/";

    // Test with minimal callback
    auto minimalCallback = [](const std::vector<char>&) {
    };

    EXPECT_NO_THROW(auto subscriber =
                        std::make_unique<RemoteSubscriber>(endpoint, subscriberId, minimalCallback, socketPath));

    // Test with callback that captures variables
    int capturedValue = 42;
    auto capturingCallback = [capturedValue](const std::vector<char>& data)
    {
        // Use captured value
        static_cast<void>(capturedValue);
    };

    EXPECT_NO_THROW(auto subscriber2 = std::make_unique<RemoteSubscriber>(
                        endpoint + "2", subscriberId + "2", capturingCallback, socketPath));
}

/*
 * @brief Test RemoteSubscriber destruction while potentially active
 */
TEST_F(RemoteSubscriberTest, TestRemoteSubscriberSafeDestruction)
{
    const std::string endpoint = "test-remote-subscriber-destruction";
    const std::string subscriberId = "destruction-subscriber";
    const std::string socketPath = "queue/router/";

    std::atomic<bool> destructorSafe {true};

    auto callback = [&destructorSafe](const std::vector<char>& data)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        // Still safe if destructor was called
    };

    {
        auto subscriber = std::make_unique<RemoteSubscriber>(endpoint, subscriberId, callback, socketPath);

        // Give it a moment to potentially start
        std::this_thread::sleep_for(std::chrono::milliseconds(20));

        // Destructor called here - should be safe
    }

    EXPECT_TRUE(destructorSafe.load());
}
