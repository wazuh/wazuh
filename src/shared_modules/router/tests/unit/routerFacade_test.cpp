/*
 * Wazuh router - RouterFacade tests
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
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
