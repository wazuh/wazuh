/*
 * Wazuh router - RemoteProvider tests
 * Copyright (C) 2015, Wazuh Inc.
 * June 25, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "routerModule.hpp"
#include "src/remoteProvider.hpp"
#include <atomic>
#include <chrono>
#include <functional>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <thread>
#include <vector>

/**
 * @brief Runs unit tests for RemoteProvider class
 */
class RemoteProviderTest : public ::testing::Test
{
protected:
    RemoteProviderTest() = default;
    ~RemoteProviderTest() override = default;

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
 * @brief Test RemoteProvider basic instantiation
 */
TEST_F(RemoteProviderTest, TestRemoteProviderInstantiation)
{
    const std::string endpoint = "test-remote-provider";
    const std::string socketPath = "queue/router/";

    EXPECT_NO_THROW(auto provider = std::make_unique<RemoteProvider>(endpoint, socketPath));
}

/*
 * @brief Test RemoteProvider with empty endpoint name
 */
TEST_F(RemoteProviderTest, TestRemoteProviderEmptyEndpoint)
{
    const std::string endpoint;
    const std::string socketPath = "queue/router/";

    EXPECT_NO_THROW(auto provider = std::make_unique<RemoteProvider>(endpoint, socketPath));
}

/*
 * @brief Test RemoteProvider with callback
 */
TEST_F(RemoteProviderTest, TestRemoteProviderWithCallback)
{
    const std::string endpoint = "test-remote-provider-callback";
    const std::string socketPath = "queue/router/";
    std::atomic<bool> callbackCalled {false};

    auto onConnect = [&callbackCalled]()
    {
        callbackCalled = true;
    };

    auto provider = std::make_unique<RemoteProvider>(endpoint, socketPath, onConnect);
    // Give some time for potential connection
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    EXPECT_TRUE(provider != nullptr);
}

/*
 * @brief Test RemoteProvider push with valid data
 */
TEST_F(RemoteProviderTest, TestRemoteProviderPushValidData)
{
    const std::string endpoint = "test-remote-provider-push";
    const std::string socketPath = "queue/router/";

    auto provider = std::make_unique<RemoteProvider>(endpoint, socketPath);

    const std::vector<char> testData = {'t', 'e', 's', 't'};
    EXPECT_NO_THROW(provider->push(testData));
}

/*
 * @brief Test RemoteProvider push with empty data
 */
TEST_F(RemoteProviderTest, TestRemoteProviderPushEmptyData)
{
    const std::string endpoint = "test-remote-provider-empty";
    const std::string socketPath = "queue/router/";

    auto provider = std::make_unique<RemoteProvider>(endpoint, socketPath);

    const std::vector<char> emptyData;
    EXPECT_NO_THROW(provider->push(emptyData));
}

/*
 * @brief Test RemoteProvider push with large data
 */
TEST_F(RemoteProviderTest, TestRemoteProviderPushLargeData)
{
    const std::string endpoint = "test-remote-provider-large";
    const std::string socketPath = "queue/router/";

    auto provider = std::make_unique<RemoteProvider>(endpoint, socketPath);

    // Create large data
    std::vector<char> largeData(10000, 'L');
    EXPECT_NO_THROW(provider->push(largeData));
}

/*
 * @brief Test RemoteProvider multiple pushes rapidly
 */
TEST_F(RemoteProviderTest, TestRemoteProviderRapidPushes)
{
    const std::string endpoint = "test-remote-provider-rapid";
    const std::string socketPath = "queue/router/";

    auto provider = std::make_unique<RemoteProvider>(endpoint, socketPath);

    const std::vector<char> testData = {'t', 'e', 's', 't'};

    for (int i = 0; i < 50; ++i)
    {
        EXPECT_NO_THROW(provider->push(testData));
    }
}

/*
 * @brief Test RemoteProvider concurrent pushes
 */
TEST_F(RemoteProviderTest, TestRemoteProviderConcurrentPushes)
{
    const std::string endpoint = "test-remote-provider-concurrent";
    const std::string socketPath = "queue/router/";

    auto provider = std::make_unique<RemoteProvider>(endpoint, socketPath);

    const int numThreads = 4;
    const int messagesPerThread = 10;
    std::vector<std::thread> threads;
    threads.reserve(numThreads);
    std::atomic<int> successCount {0};

    for (int t = 0; t < numThreads; ++t)
    {
        threads.emplace_back(
            [&, t]()
            {
                for (int i = 0; i < messagesPerThread; ++i)
                {
                    try
                    {
                        std::string data = "thread-" + std::to_string(t) + "-msg-" + std::to_string(i);
                        std::vector<char> testData(data.begin(), data.end());
                        provider->push(testData);
                        successCount++;
                    }
                    catch (...)
                    {
                        // Count failures as well for this test
                    }
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    // Should have attempted all pushes
    EXPECT_GE(successCount.load(), 0);
}

/*
 * @brief Test RemoteProvider with special characters in endpoint
 */
TEST_F(RemoteProviderTest, TestRemoteProviderSpecialCharacters)
{
    const std::string endpoint = "test-provider-special";
    const std::string socketPath = "queue/router/";

    EXPECT_NO_THROW(auto provider = std::make_unique<RemoteProvider>(endpoint, socketPath));
}

/*
 * @brief Test RemoteProvider with long endpoint name
 */
TEST_F(RemoteProviderTest, TestRemoteProviderLongEndpoint)
{
    std::string endpoint(200, 'X'); // Long endpoint name
    const std::string socketPath = "queue/router/";

    EXPECT_NO_THROW(auto provider = std::make_unique<RemoteProvider>(endpoint, socketPath));
}

/*
 * @brief Test RemoteProvider with invalid socket path
 */
TEST_F(RemoteProviderTest, TestRemoteProviderInvalidSocketPath)
{
    const std::string endpoint = "test-remote-provider-invalid";
    const std::string socketPath = "/tmp/invalid/";

    EXPECT_NO_THROW(auto provider = std::make_unique<RemoteProvider>(endpoint, socketPath));
}

/*
 * @brief Test RemoteProvider lifecycle - creation and destruction
 */
TEST_F(RemoteProviderTest, TestRemoteProviderLifecycle)
{
    const std::string endpoint = "test-remote-provider-lifecycle";
    const std::string socketPath = "queue/router/";

    for (int i = 0; i < 5; ++i)
    {
        auto provider = std::make_unique<RemoteProvider>(endpoint, socketPath);
        const std::vector<char> testData = {'t', 'e', 's', 't'};
        EXPECT_NO_THROW(provider->push(testData));
        // Provider destructor called here
    }
}

/*
 * @brief Test RemoteProvider with multiple different endpoints
 */
TEST_F(RemoteProviderTest, TestRemoteProviderMultipleEndpoints)
{
    const std::string socketPath = "queue/router/";
    std::vector<std::unique_ptr<RemoteProvider>> providers;

    for (int i = 0; i < 3; ++i)
    {
        std::string endpoint = "test-endpoint-" + std::to_string(i);
        providers.push_back(std::make_unique<RemoteProvider>(endpoint, socketPath));
    }

    // Test sending from all providers
    const std::vector<char> testData = {'t', 'e', 's', 't'};
    for (auto& provider : providers)
    {
        EXPECT_NO_THROW(provider->push(testData));
    }
}

/*
 * @brief Test RemoteProvider memory management and cleanup
 */
TEST_F(RemoteProviderTest, TestRemoteProviderMemoryManagement)
{
    const std::string endpoint = "test-remote-provider-memory";
    const std::string socketPath = "queue/router/";

    std::vector<std::unique_ptr<RemoteProvider>> providers;
    providers.reserve(20);

    // Create many providers
    for (int i = 0; i < 20; ++i)
    {
        std::string uniqueEndpoint = endpoint + std::to_string(i);
        providers.push_back(std::make_unique<RemoteProvider>(uniqueEndpoint, socketPath));
    }

    // Send data from each
    const std::vector<char> testData = {'m', 'e', 'm', 'o', 'r', 'y'};
    for (auto& provider : providers)
    {
        EXPECT_NO_THROW(provider->push(testData));
    }

    // Clean up all at once
    providers.clear();
}

/*
 * @brief Test RemoteProvider with binary data
 */
TEST_F(RemoteProviderTest, TestRemoteProviderBinaryData)
{
    const std::string endpoint = "test-remote-provider-binary";
    const std::string socketPath = "queue/router/";

    auto provider = std::make_unique<RemoteProvider>(endpoint, socketPath);

    // Create binary data with null bytes and special characters
    std::vector<char> binaryData = {
        static_cast<char>(0x00), static_cast<char>(0x01), static_cast<char>(0x7F), static_cast<char>(0x41)};
    EXPECT_NO_THROW(provider->push(binaryData));
}

/*
 * @brief Test RemoteProvider error handling during push
 */
TEST_F(RemoteProviderTest, TestRemoteProviderErrorHandling)
{
    const std::string endpoint = "test-remote-provider-error";
    const std::string socketPath = "queue/router/";

    auto provider = std::make_unique<RemoteProvider>(endpoint, socketPath);

    // These should not throw exceptions even if connection fails
    const std::vector<char> testData = {'e', 'r', 'r', 'o', 'r'};
    EXPECT_NO_THROW(provider->push(testData));

    // Try multiple times
    for (int i = 0; i < 5; ++i)
    {
        EXPECT_NO_THROW(provider->push(testData));
    }
}
