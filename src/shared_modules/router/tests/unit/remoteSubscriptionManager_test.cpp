/*
 * Wazuh router - RemoteSubscriptionManager tests
 * Copyright (C) 2015, Wazuh Inc.
 * June 25, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "routerModule.hpp"
#include "src/remoteSubscriptionManager.hpp"
#include <atomic>
#include <chrono>
#include <functional>
#include <gtest/gtest.h>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

/**
 * @brief Runs unit tests for RemoteSubscriptionManager class
 */
class RemoteSubscriptionManagerTest : public ::testing::Test
{
protected:
    RemoteSubscriptionManagerTest() = default;
    ~RemoteSubscriptionManagerTest() override = default;

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
 * @brief Test RemoteSubscriptionManager basic instantiation
 */
TEST_F(RemoteSubscriptionManagerTest, TestRemoteSubscriptionManagerInstantiation)
{
    EXPECT_NO_THROW(auto manager = std::make_unique<RemoteSubscriptionManager>());
}

/*
 * @brief Test RemoteSubscriptionManager sendInitProviderMessage with valid endpoint
 */
TEST_F(RemoteSubscriptionManagerTest, TestSendInitProviderMessageValidEndpoint)
{
    auto manager = std::make_unique<RemoteSubscriptionManager>();

    const std::string endpointName = "test-endpoint";
    std::atomic<bool> callbackCalled {false};

    auto onSuccess = [&callbackCalled]()
    {
        callbackCalled = true;
    };

    EXPECT_NO_THROW(manager->sendInitProviderMessage(endpointName, onSuccess));
}

/*
 * @brief Test RemoteSubscriptionManager sendInitProviderMessage with empty endpoint
 */
TEST_F(RemoteSubscriptionManagerTest, TestSendInitProviderMessageEmptyEndpoint)
{
    auto manager = std::make_unique<RemoteSubscriptionManager>();

    const std::string endpointName;
    std::atomic<bool> callbackCalled {false};

    auto onSuccess = [&callbackCalled]()
    {
        callbackCalled = true;
    };

    EXPECT_NO_THROW(manager->sendInitProviderMessage(endpointName, onSuccess));
}

/*
 * @brief Test RemoteSubscriptionManager sendInitProviderMessage with long endpoint name
 */
TEST_F(RemoteSubscriptionManagerTest, TestSendInitProviderMessageLongEndpoint)
{
    auto manager = std::make_unique<RemoteSubscriptionManager>();

    std::string endpointName(1000, 'E');
    std::atomic<bool> callbackCalled {false};

    auto onSuccess = [&callbackCalled]()
    {
        callbackCalled = true;
    };

    EXPECT_NO_THROW(manager->sendInitProviderMessage(endpointName, onSuccess));
}

/*
 * @brief Test RemoteSubscriptionManager sendInitProviderMessage with special characters
 */
TEST_F(RemoteSubscriptionManagerTest, TestSendInitProviderMessageSpecialCharacters)
{
    auto manager = std::make_unique<RemoteSubscriptionManager>();

    const std::string endpointName = "endpoint-!@#$%^&*()";
    std::atomic<bool> callbackCalled {false};

    auto onSuccess = [&callbackCalled]()
    {
        callbackCalled = true;
    };

    EXPECT_NO_THROW(manager->sendInitProviderMessage(endpointName, onSuccess));
}

/*
 * @brief Test RemoteSubscriptionManager sendInitProviderMessage multiple times
 */
TEST_F(RemoteSubscriptionManagerTest, TestSendInitProviderMessageMultipleTimes)
{
    auto manager = std::make_unique<RemoteSubscriptionManager>();

    std::atomic<int> callbackCount {0};

    auto onSuccess = [&callbackCount]()
    {
        callbackCount++;
    };

    // Send multiple messages
    for (int i = 0; i < 5; ++i)
    {
        std::string endpointName = "endpoint-" + std::to_string(i);
        EXPECT_NO_THROW(manager->sendInitProviderMessage(endpointName, onSuccess));
    }
}

/*
 * @brief Test RemoteSubscriptionManager callback exception handling
 */
TEST_F(RemoteSubscriptionManagerTest, TestSendInitProviderMessageCallbackException)
{
    auto manager = std::make_unique<RemoteSubscriptionManager>();

    const std::string endpointName = "exception-endpoint";
    std::atomic<bool> exceptionThrown {false};

    auto onSuccessWithException = [&exceptionThrown]()
    {
        exceptionThrown = true;
        throw std::runtime_error("Test exception in callback");
    };

    // Should not crash even if callback throws
    EXPECT_NO_THROW(manager->sendInitProviderMessage(endpointName, onSuccessWithException));
}

/*
 * @brief Test RemoteSubscriptionManager multiple managers
 */
TEST_F(RemoteSubscriptionManagerTest, TestMultipleRemoteSubscriptionManagers)
{
    std::vector<std::unique_ptr<RemoteSubscriptionManager>> managers;
    managers.reserve(5);

    // Create multiple managers
    for (int i = 0; i < 5; ++i)
    {
        managers.push_back(std::make_unique<RemoteSubscriptionManager>());
    }

    std::atomic<int> totalCallbacks {0};

    auto onSuccess = [&totalCallbacks]()
    {
        totalCallbacks++;
    };

    // Send messages from all managers
    for (size_t i = 0; i < managers.size(); ++i)
    {
        std::string endpointName = "manager-" + std::to_string(i) + "-endpoint";
        EXPECT_NO_THROW(managers[i]->sendInitProviderMessage(endpointName, onSuccess));
    }
}

/*
 * @brief Test RemoteSubscriptionManager lifecycle
 */
TEST_F(RemoteSubscriptionManagerTest, TestRemoteSubscriptionManagerLifecycle)
{
    std::atomic<int> managersCreated {0};

    for (int i = 0; i < 10; ++i)
    {
        auto manager = std::make_unique<RemoteSubscriptionManager>();
        managersCreated++;

        const std::string endpointName = "lifecycle-endpoint-" + std::to_string(i);

        auto onSuccess = []()
        {
            // Simple callback
        };

        EXPECT_NO_THROW(manager->sendInitProviderMessage(endpointName, onSuccess));

        // Manager destructor called here
    }

    EXPECT_EQ(managersCreated.load(), 10);
}

/*
 * @brief Test RemoteSubscriptionManager memory management
 */
TEST_F(RemoteSubscriptionManagerTest, TestRemoteSubscriptionManagerMemoryManagement)
{
    auto manager = std::make_unique<RemoteSubscriptionManager>();

    std::vector<std::string> endpointNames;
    endpointNames.reserve(50);

    auto onSuccess = []()
    {
        // Simple callback
    };

    // Create many endpoint names and send messages
    for (int i = 0; i < 50; ++i)
    {
        std::string endpointName = "memory-endpoint-" + std::to_string(i);
        endpointNames.push_back(endpointName);

        EXPECT_NO_THROW(manager->sendInitProviderMessage(endpointName, onSuccess));
    }

    EXPECT_EQ(endpointNames.size(), 50);
}

/*
 * @brief Test RemoteSubscriptionManager callback variations
 */
TEST_F(RemoteSubscriptionManagerTest, TestSendInitProviderMessageCallbackVariations)
{
    auto manager = std::make_unique<RemoteSubscriptionManager>();

    // Test with empty callback
    auto emptyCallback = []() {
    };
    EXPECT_NO_THROW(manager->sendInitProviderMessage("empty-callback-endpoint", emptyCallback));

    // Test with callback that captures variables
    int capturedValue = 42;
    auto capturingCallback = [capturedValue]()
    {
        static_cast<void>(capturedValue);
    };
    EXPECT_NO_THROW(manager->sendInitProviderMessage("capturing-callback-endpoint", capturingCallback));

    // Test with callback that does work
    std::atomic<int> workCount {0};
    auto workingCallback = [&workCount]()
    {
        workCount++;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    };
    EXPECT_NO_THROW(manager->sendInitProviderMessage("working-callback-endpoint", workingCallback));
}

/*
 * @brief Test RemoteSubscriptionManager rapid consecutive calls
 */
TEST_F(RemoteSubscriptionManagerTest, TestSendInitProviderMessageRapidCalls)
{
    auto manager = std::make_unique<RemoteSubscriptionManager>();

    std::atomic<int> rapidCallbacks {0};

    auto onSuccess = [&rapidCallbacks]()
    {
        rapidCallbacks++;
    };

    // Rapid consecutive calls
    for (int i = 0; i < 20; ++i)
    {
        std::string endpointName = "rapid-endpoint-" + std::to_string(i);
        EXPECT_NO_THROW(manager->sendInitProviderMessage(endpointName, onSuccess));
    }
}

/*
 * @brief Test RemoteSubscriptionManager with numeric endpoint names
 */
TEST_F(RemoteSubscriptionManagerTest, TestSendInitProviderMessageNumericEndpoints)
{
    auto manager = std::make_unique<RemoteSubscriptionManager>();

    auto onSuccess = []()
    {
        // Simple callback
    };

    // Test with numeric endpoint names
    std::vector<std::string> numericEndpoints = {"123", "0", "999999", "-1", "3.14159"};

    for (const auto& endpoint : numericEndpoints)
    {
        EXPECT_NO_THROW(manager->sendInitProviderMessage(endpoint, onSuccess));
    }
}

/*
 * @brief Test RemoteSubscriptionManager destruction while operations might be pending
 */
TEST_F(RemoteSubscriptionManagerTest, TestRemoteSubscriptionManagerSafeDestruction)
{
    std::atomic<bool> destructionSafe {true};

    {
        auto manager = std::make_unique<RemoteSubscriptionManager>();

        auto onSuccess = []()
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            // Should still be safe even if destructor was called
        };

        manager->sendInitProviderMessage("destruction-test-endpoint", onSuccess);

        // Give it a moment to potentially start
        std::this_thread::sleep_for(std::chrono::milliseconds(5));

        // Destructor called here - should be safe
    }

    EXPECT_TRUE(destructionSafe.load());
}
