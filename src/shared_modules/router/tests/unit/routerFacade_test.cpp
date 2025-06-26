/*
 * Wazuh router - RouterFacade tests
 * Copyright (C) 2015, Wazuh Inc.
 * June 25, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "src/routerFacade.hpp"
#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <thread>
#include <vector>

/**
 * @brief Runs unit tests for RouterFacade class
 */
class RouterFacadeTest : public ::testing::Test
{
protected:
    RouterFacadeTest() = default;
    ~RouterFacadeTest() override = default;

    void SetUp() override
    {
        // Clean state before each test
        try
        {
            RouterFacade::instance().destroy();
        }
        catch (...)
        {
            // Ignore if not initialized
        }
    }

    void TearDown() override
    {
        // Clean state after each test
        try
        {
            RouterFacade::instance().destroy();
        }
        catch (...)
        {
            // Ignore if not initialized
        }
    }
};

/*
 * @brief Tests the initialization of RouterFacade
 */
TEST_F(RouterFacadeTest, TestInitialize)
{
    EXPECT_NO_THROW(RouterFacade::instance().initialize());
}

/*
 * @brief Tests double initialization throws exception
 */
TEST_F(RouterFacadeTest, TestDoubleInitializeThrows)
{
    EXPECT_NO_THROW(RouterFacade::instance().initialize());
    EXPECT_THROW(RouterFacade::instance().initialize(), std::runtime_error);
}

/*
 * @brief Tests destroy without initialization throws exception
 */
TEST_F(RouterFacadeTest, TestDestroyWithoutInitializeThrows)
{
    EXPECT_THROW(RouterFacade::instance().destroy(), std::runtime_error);
}

/*
 * @brief Tests initialize and destroy cycle
 */
TEST_F(RouterFacadeTest, TestInitializeDestroyCycle)
{
    EXPECT_NO_THROW(RouterFacade::instance().initialize());
    EXPECT_NO_THROW(RouterFacade::instance().destroy());

    // Should be able to initialize again after destroy
    EXPECT_NO_THROW(RouterFacade::instance().initialize());
    EXPECT_NO_THROW(RouterFacade::instance().destroy());
}

/*
 * @brief Tests local provider initialization
 */
TEST_F(RouterFacadeTest, TestInitProviderLocal)
{
    RouterFacade::instance().initialize();

    const std::string providerName = "test-provider";
    EXPECT_NO_THROW(RouterFacade::instance().initProviderLocal(providerName));
}

/*
 * @brief Tests local provider removal
 */
TEST_F(RouterFacadeTest, TestRemoveProviderLocal)
{
    RouterFacade::instance().initialize();

    const std::string providerName = "test-provider";
    RouterFacade::instance().initProviderLocal(providerName);

    EXPECT_NO_THROW(RouterFacade::instance().removeProviderLocal(providerName));
}

/*
 * @brief Tests removing non-existent local provider throws exception
 */
TEST_F(RouterFacadeTest, TestRemoveNonExistentProviderLocalThrows)
{
    RouterFacade::instance().initialize();

    const std::string providerName = "non-existent-provider";
    EXPECT_THROW(RouterFacade::instance().removeProviderLocal(providerName), std::runtime_error);
}

/*
 * @brief Tests adding local subscriber
 */
TEST_F(RouterFacadeTest, TestAddSubscriberLocal)
{
    RouterFacade::instance().initialize();

    const std::string providerName = "test-provider";
    const std::string subscriberId = "test-subscriber";
    bool callbackCalled = false;

    auto callback = [&callbackCalled](const std::vector<char>& data)
    {
        callbackCalled = true;
    };

    EXPECT_NO_THROW(RouterFacade::instance().addSubscriber(providerName, subscriberId, callback));
}

/*
 * @brief Tests removing local subscriber
 */
TEST_F(RouterFacadeTest, TestRemoveSubscriberLocal)
{
    RouterFacade::instance().initialize();

    const std::string providerName = "test-provider";
    const std::string subscriberId = "test-subscriber";
    bool callbackCalled = false;

    auto callback = [&callbackCalled](const std::vector<char>& data)
    {
        callbackCalled = true;
    };

    RouterFacade::instance().addSubscriber(providerName, subscriberId, callback);
    EXPECT_NO_THROW(RouterFacade::instance().removeSubscriberLocal(providerName, subscriberId));
}

/*
 * @brief Tests push data to existing local provider
 */
TEST_F(RouterFacadeTest, TestPushToLocalProvider)
{
    RouterFacade::instance().initialize();

    const std::string providerName = "test-provider";
    RouterFacade::instance().initProviderLocal(providerName);

    const std::vector<char> testData = {'t', 'e', 's', 't'};
    EXPECT_NO_THROW(RouterFacade::instance().push(providerName, testData));
}

/*
 * @brief Tests push data to non-existent provider throws exception
 */
TEST_F(RouterFacadeTest, TestPushToNonExistentProviderThrows)
{
    RouterFacade::instance().initialize();

    const std::string providerName = "non-existent-provider";
    const std::vector<char> testData = {'t', 'e', 's', 't'};

    EXPECT_THROW(RouterFacade::instance().push(providerName, testData), std::runtime_error);
}

/*
 * @brief Tests remote provider initialization throws exception when provider already exists
 */
TEST_F(RouterFacadeTest, TestInitProviderRemoteDuplicate)
{
    RouterFacade::instance().initialize();

    const std::string providerName = "test-remote-provider";
    auto onConnect = []() {
    };

    EXPECT_NO_THROW(RouterFacade::instance().initProviderRemote(providerName, onConnect));
    EXPECT_THROW(RouterFacade::instance().initProviderRemote(providerName, onConnect), std::runtime_error);
}

/*
 * @brief Tests remote provider removal
 */
TEST_F(RouterFacadeTest, TestRemoveProviderRemote)
{
    RouterFacade::instance().initialize();

    const std::string providerName = "test-remote-provider";
    auto onConnect = []() {
    };

    RouterFacade::instance().initProviderRemote(providerName, onConnect);
    EXPECT_NO_THROW(RouterFacade::instance().removeProviderRemote(providerName));
}

/*
 * @brief Tests removing non-existent remote provider throws exception
 */
TEST_F(RouterFacadeTest, TestRemoveNonExistentProviderRemoteThrows)
{
    RouterFacade::instance().initialize();

    const std::string providerName = "non-existent-remote-provider";
    EXPECT_THROW(RouterFacade::instance().removeProviderRemote(providerName), std::runtime_error);
}

/*
 * @brief Tests remote subscriber addition throws exception when subscriber already exists
 */
TEST_F(RouterFacadeTest, TestAddSubscriberRemoteDuplicate)
{
    RouterFacade::instance().initialize();

    const std::string providerName = "test-provider";
    const std::string subscriberId = "test-subscriber";
    bool callbackCalled = false;

    auto callback = [&callbackCalled](const std::vector<char>& data)
    {
        callbackCalled = true;
    };
    auto onConnect = []() {
    };

    EXPECT_NO_THROW(RouterFacade::instance().addSubscriberRemote(providerName, subscriberId, callback, onConnect));
    EXPECT_THROW(RouterFacade::instance().addSubscriberRemote(providerName, subscriberId, callback, onConnect),
                 std::runtime_error);
}

/*
 * @brief Tests remote subscriber removal
 */
TEST_F(RouterFacadeTest, TestRemoveSubscriberRemote)
{
    RouterFacade::instance().initialize();

    const std::string providerName = "test-provider";
    const std::string subscriberId = "test-subscriber";
    bool callbackCalled = false;

    auto callback = [&callbackCalled](const std::vector<char>& data)
    {
        callbackCalled = true;
    };

    auto onConnect = []() {
    };

    RouterFacade::instance().addSubscriberRemote(providerName, subscriberId, callback, onConnect);
    EXPECT_NO_THROW(RouterFacade::instance().removeSubscriberRemote(providerName, subscriberId));
}

/*
 * @brief Tests concurrent provider initialization
 */
TEST_F(RouterFacadeTest, TestConcurrentProviderInitialization)
{
    RouterFacade::instance().initialize();

    const int numThreads = 4;
    std::vector<std::thread> threads;
    threads.reserve(numThreads);
    std::atomic<int> successCount {0};

    for (int i = 0; i < numThreads; ++i)
    {
        threads.emplace_back(
            [&, i]()
            {
                try
                {
                    std::string providerName = "concurrent-provider-" + std::to_string(i);
                    RouterFacade::instance().initProviderLocal(providerName);
                    successCount++;
                }
                catch (...)
                {
                    // Ignore exceptions for this test
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(numThreads, successCount.load());
}

/*
 * @brief Tests concurrent subscriber addition
 */
TEST_F(RouterFacadeTest, TestConcurrentSubscriberAddition)
{
    RouterFacade::instance().initialize();

    const std::string providerName = "concurrent-provider";
    const int numThreads = 4;
    std::vector<std::thread> threads;
    threads.reserve(numThreads);
    std::atomic<int> successCount {0};

    for (int i = 0; i < numThreads; ++i)
    {
        threads.emplace_back(
            [&, i]()
            {
                try
                {
                    std::string subscriberId = "subscriber-" + std::to_string(i);
                    auto callback = [](const std::vector<char>& data) {
                    };
                    RouterFacade::instance().addSubscriber(providerName, subscriberId, callback);
                    successCount++;
                }
                catch (...)
                {
                    // Ignore exceptions for this test
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(numThreads, successCount.load());
}

/*
 * @brief Tests push to multiple providers
 */
TEST_F(RouterFacadeTest, TestPushToMultipleProviders)
{
    RouterFacade::instance().initialize();

    const int numProviders = 5;
    std::vector<std::string> providerNames;

    for (int i = 0; i < numProviders; ++i)
    {
        std::string providerName = "multi-provider-" + std::to_string(i);
        providerNames.push_back(providerName);
        RouterFacade::instance().initProviderLocal(providerName);
    }

    const std::vector<char> testData = {'m', 'u', 'l', 't', 'i', 'c', 'a', 's', 't'};

    for (const auto& providerName : providerNames)
    {
        EXPECT_NO_THROW(RouterFacade::instance().push(providerName, testData));
    }
}

/*
 * @brief Tests subscriber callback execution
 */
TEST_F(RouterFacadeTest, TestSubscriberCallbackExecution)
{
    RouterFacade::instance().initialize();

    const std::string providerName = "callback-provider";
    const std::string subscriberId = "callback-subscriber";
    bool callbackCalled = false;
    std::vector<char> receivedData;

    auto callback = [&callbackCalled, &receivedData](const std::vector<char>& data)
    {
        callbackCalled = true;
        receivedData = data;
    };

    RouterFacade::instance().addSubscriber(providerName, subscriberId, callback);

    const std::vector<char> testData = {'c', 'a', 'l', 'l', 'b', 'a', 'c', 'k'};
    RouterFacade::instance().push(providerName, testData);

    // Give some time for asynchronous processing
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(testData, receivedData);
}

/*
 * @brief Tests provider removal after data push
 */
TEST_F(RouterFacadeTest, TestProviderRemovalAfterPush)
{
    RouterFacade::instance().initialize();

    const std::string providerName = "removal-provider";
    RouterFacade::instance().initProviderLocal(providerName);

    const std::vector<char> testData = {'r', 'e', 'm', 'o', 'v', 'a', 'l'};
    RouterFacade::instance().push(providerName, testData);

    EXPECT_NO_THROW(RouterFacade::instance().removeProviderLocal(providerName));
}

/*
 * @brief Tests subscriber removal after provider deletion
 */
TEST_F(RouterFacadeTest, TestSubscriberRemovalAfterProviderDeletion)
{
    RouterFacade::instance().initialize();

    const std::string providerName = "deletion-provider";
    const std::string subscriberId = "deletion-subscriber";

    auto callback = [](const std::vector<char>& data) {
    };
    RouterFacade::instance().addSubscriber(providerName, subscriberId, callback);

    // Remove provider first
    RouterFacade::instance().removeProviderLocal(providerName);

    // Then try to remove subscriber - should not throw
    EXPECT_NO_THROW(RouterFacade::instance().removeSubscriberLocal(providerName, subscriberId));
}

/*
 * @brief Tests empty data push
 */
TEST_F(RouterFacadeTest, TestEmptyDataPush)
{
    RouterFacade::instance().initialize();

    const std::string providerName = "empty-data-provider";
    RouterFacade::instance().initProviderLocal(providerName);

    const std::vector<char> emptyData;
    EXPECT_NO_THROW(RouterFacade::instance().push(providerName, emptyData));
}

/*
 * @brief Tests large data push
 */
TEST_F(RouterFacadeTest, TestLargeDataPush)
{
    RouterFacade::instance().initialize();

    const std::string providerName = "large-data-provider";
    RouterFacade::instance().initProviderLocal(providerName);

    // Create large data (100KB)
    const size_t largeSize = 100 * 1024;
    std::vector<char> largeData(largeSize, 'L');

    EXPECT_NO_THROW(RouterFacade::instance().push(providerName, largeData));
}

/*
 * @brief Tests provider creation with empty name
 */
TEST_F(RouterFacadeTest, TestProviderCreationEmptyName)
{
    RouterFacade::instance().initialize();

    const std::string emptyProviderName = "";
    EXPECT_ANY_THROW(RouterFacade::instance().initProviderLocal(emptyProviderName));
}

/*
 * @brief Tests provider creation with special characters
 */
TEST_F(RouterFacadeTest, TestProviderCreationSpecialCharacters)
{
    RouterFacade::instance().initialize();

    const std::string specialProviderName = "provider-with-special!@#$%^&*()_+{}|:<>?[]\\;'\".,/";
    EXPECT_ANY_THROW(RouterFacade::instance().initProviderLocal(specialProviderName));
}

/*
 * @brief Tests removing non-existent remote provider
 */
TEST_F(RouterFacadeTest, TestRemoveNonExistentRemoteProvider)
{
    RouterFacade::instance().initialize();

    const std::string nonExistentProvider = "non-existent-remote-provider";
    EXPECT_THROW(RouterFacade::instance().removeProviderRemote(nonExistentProvider), std::runtime_error);
}

/*
 * @brief Tests multiple destroy calls
 */
TEST_F(RouterFacadeTest, TestMultipleDestroyCalls)
{
    RouterFacade::instance().initialize();

    EXPECT_NO_THROW(RouterFacade::instance().destroy());
    EXPECT_THROW(RouterFacade::instance().destroy(), std::runtime_error);
}

/*
 * @brief Tests state persistence between operations
 */
TEST_F(RouterFacadeTest, TestStatePersistence)
{
    RouterFacade::instance().initialize();

    const std::string providerName = "persistent-provider";
    const std::string subscriberId = "persistent-subscriber";

    // Create provider and subscriber
    RouterFacade::instance().initProviderLocal(providerName);
    auto callback = [](const std::vector<char>& data) {
    };
    RouterFacade::instance().addSubscriber(providerName, subscriberId, callback);

    // Verify state exists by attempting operations that depend on it
    const std::vector<char> testData = {'p', 'e', 'r', 's', 'i', 's', 't'};
    EXPECT_NO_THROW(RouterFacade::instance().push(providerName, testData));
    EXPECT_NO_THROW(RouterFacade::instance().removeSubscriberLocal(providerName, subscriberId));
    EXPECT_NO_THROW(RouterFacade::instance().removeProviderLocal(providerName));
}
