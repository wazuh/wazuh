/*
 * Wazuh router - Interface tests
 * Copyright (C) 2015, Wazuh Inc.
 * Apr 29, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "interface_c_test.hpp"
#include "remoteSubscriptionManager.hpp"
#include "router.h"
#include "routerSubscriber.hpp"
#include <chrono>
#include <filesystem>
#include <thread>

void RouterCInterfaceTest::SetUp()
{
    if (router_start() != 0)
    {
        FAIL() << "Failed to start router";
    }
};

void RouterCInterfaceTest::TearDown()
{
    if (router_stop() != 0)
    {
        FAIL() << "Failed to stop router";
    }
};

void RouterCInterfaceTestNoSetUp::TearDown() {};

TEST_F(RouterCInterfaceTest, DISABLED_TestDoubleProviderInit)
{
    auto handle {router_provider_create("test", false)};
    EXPECT_NE(handle, nullptr);

    EXPECT_EQ(router_provider_create("test", false), nullptr);
}

TEST_F(RouterCInterfaceTest, TestDoubleSubscriberInit)
{
    const char* topic_name = "test";
    const char* subscriber_id = "test-subscriber";

    auto handle1 = router_subscriber_create(topic_name, subscriber_id, true);
    EXPECT_NE(handle1, nullptr);

    auto handle2 = router_subscriber_create(topic_name, subscriber_id, true);
    EXPECT_NE(handle2, nullptr);

    // Both handles should be valid but different
    EXPECT_NE(handle1, handle2);

    if (handle1 != nullptr)
    {
        router_subscriber_destroy(handle1);
    }
    if (handle2 != nullptr)
    {
        router_subscriber_destroy(handle2);
    }
}

TEST_F(RouterCInterfaceTest, TestProviderSend)
{
    auto handle {router_provider_create("test", false)};
    EXPECT_NE(handle, nullptr);

    EXPECT_EQ(router_provider_send(handle, "test", 4), 0);

    // Clean up provider
    EXPECT_NO_THROW(router_provider_destroy(handle));
}

TEST_F(RouterCInterfaceTest, TestProviderSendNull)
{
    auto handle {router_provider_create("test", false)};
    EXPECT_NE(handle, nullptr);

    EXPECT_EQ(router_provider_send(handle, nullptr, 4), -1);

    EXPECT_NO_THROW(router_provider_destroy(handle));
}

TEST_F(RouterCInterfaceTest, TestProviderSendZero)
{
    auto handle {router_provider_create("test", false)};
    EXPECT_NE(handle, nullptr);

    EXPECT_EQ(router_provider_send(handle, "test", 0), -1);

    EXPECT_NO_THROW(router_provider_destroy(handle));
}

TEST_F(RouterCInterfaceTest, TestProviderSendAndDestroy)
{
    auto handle {router_provider_create("test", false)};

    EXPECT_NE(handle, nullptr);

    EXPECT_EQ(router_provider_send(handle, "test", 4), 0);

    EXPECT_NO_THROW(router_provider_destroy(handle));

    // TODO - Add C interface for subscribers.
}

TEST_F(RouterCInterfaceTest, TestProviderWithEmptyTopicName)
{
    auto handle {router_provider_create("", false)};

    EXPECT_EQ(handle, nullptr);

    // TODO - Add C interface for subscribers.
}

TEST_F(RouterCInterfaceTest, TestTwoProvidersWithTheSameTopicName)
{
    auto handle1 {router_provider_create("test-provider", false)};

    EXPECT_NE(handle1, nullptr);

    auto handle2 {router_provider_create("test-provider", false)};

    EXPECT_EQ(handle2, nullptr);

    EXPECT_NO_THROW(router_provider_destroy(handle1));
}

/**
 * @brief We simulate the crash of the broker and check that client doesn't hang.
 *
 */
TEST_F(RouterCInterfaceTestNoSetUp, TestRemoveProviderWithServerDown)
{
    router_start();

    ROUTER_PROVIDER_HANDLE provider = router_provider_create("test", false);
    if (nullptr == provider)
    {
        FAIL() << "The provider wasn't created";
    }

    // Simulating the broker crash
    std::filesystem::remove(std::filesystem::path(REMOTE_SUBSCRIPTION_ENDPOINT));

    EXPECT_NO_THROW(router_provider_destroy(provider));

    // It shouldn't hang here
    if (router_stop() != 0)
    {
        FAIL() << "Failed to stop router";
    }
}

/**
 * @brief We simulate send data to a provider after the broker crash and check that client doesn't hang.
 *
 */
TEST_F(RouterCInterfaceTestNoSetUp, TestRemoveBrokerBeforeProvider)
{
    router_start();

    ROUTER_PROVIDER_HANDLE handle = router_provider_create("test", false);
    if (nullptr == handle)
    {
        FAIL() << "The provider wasn't created";
    }

    // Simulating the broker crash
    std::filesystem::remove(std::filesystem::path(REMOTE_SUBSCRIPTION_ENDPOINT));

    // It shouldn't hang here
    if (router_stop() != 0)
    {
        FAIL() << "Failed to stop router";
    }

    EXPECT_EQ(router_provider_send(handle, "test", 4), -1);
    EXPECT_EQ(router_provider_send(handle, "test", 4), -1);
}

/**
 * @brief We simulate send data to a provider after the broker crash and check that client doesn't hang.
 *
 */
TEST_F(RouterCInterfaceTestNoSetUp, TestSendMessageAfterBrokerRestart)
{
    router_start();

    ROUTER_PROVIDER_HANDLE handle = router_provider_create("test", false);
    if (nullptr == handle)
    {
        FAIL() << "The provider wasn't created";
    }

    // Simulating the broker crash
    std::filesystem::remove(std::filesystem::path(REMOTE_SUBSCRIPTION_ENDPOINT));

    // It shouldn't hang here
    if (router_stop() != 0)
    {
        FAIL() << "Failed to stop router";
    }

    router_start();

    auto subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest");

    std::atomic<int> count = 0;
    constexpr auto MESSAGE_COUNT = 2;

    auto payloadString = std::string("test");
    auto payload = std::vector<char> {payloadString.begin(), payloadString.end()};
    std::promise<void> promiseSubscriber;
    std::promise<void> promiseSubscriberConnected;

    EXPECT_NO_THROW({
        subscriptor->subscribe(
            [&](const std::vector<char>& message)
            {
                // Validate payload
                EXPECT_EQ(message.size(), 4);
                std::string str(message.begin(), message.end());
                EXPECT_EQ(str, "test");
                //  Count messages
                count++;

                if (count == MESSAGE_COUNT)
                {
                    promiseSubscriber.set_value();
                }
            },
            [&]() { promiseSubscriberConnected.set_value(); });
    });
    promiseSubscriberConnected.get_future().wait();

    EXPECT_EQ(router_provider_send(handle, "test", 4), 0);
    EXPECT_EQ(router_provider_send(handle, "test", 4), 0);

    promiseSubscriber.get_future().wait();

    if (router_stop() != 0)
    {
        FAIL() << "Failed to stop router";
    }
}

// Global variables for integration testing callbacks
static std::atomic<int> g_integration_callback_count {0};
static std::string g_integration_last_message;
static std::mutex g_integration_message_mutex;

void integration_test_callback(const char* message)
{
    if (message != nullptr)
    {
        std::lock_guard<std::mutex> lock(g_integration_message_mutex);
        g_integration_last_message = std::string(message);
        g_integration_callback_count++;
    }
}

/**
 * @brief Integration test: Provider sends data to C interface subscriber
 */
TEST_F(RouterCInterfaceTest, TestProviderToSubscriberCInterface)
{
    const char* topic_name = "integration-topic";
    const char* subscriber_id = "integration-subscriber";
    const char* test_message = "integration-test-message";

    // Create provider (use local for integration tests)
    auto provider_handle = router_provider_create(topic_name, true);
    ASSERT_NE(provider_handle, nullptr);

    // Create subscriber using C interface (use local for integration tests)
    auto subscriber_handle = router_subscriber_create(topic_name, subscriber_id, true);
    ASSERT_NE(subscriber_handle, nullptr);

    // Reset callback counter
    g_integration_callback_count = 0;
    g_integration_last_message.clear();

    // Subscribe with callback
    int subscribe_result = router_subscriber_subscribe(subscriber_handle, integration_test_callback);
    EXPECT_EQ(subscribe_result, 0);

    // Give some time for subscription to be established
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Send message from provider (include null terminator)
    int send_result = router_provider_send(provider_handle, test_message, strlen(test_message) + 1);
    EXPECT_EQ(send_result, 0);

    // Wait for callback to be called
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Verify callback was called with correct message
    EXPECT_GT(g_integration_callback_count.load(), 0);
    {
        std::lock_guard<std::mutex> lock(g_integration_message_mutex);
        EXPECT_EQ(g_integration_last_message, test_message);
    }

    // Clean up
    router_subscriber_unsubscribe(subscriber_handle);
    router_subscriber_destroy(subscriber_handle);
    router_provider_destroy(provider_handle);
}

/**
 * @brief Integration test: Multiple C interface subscribers on same topic
 */
TEST_F(RouterCInterfaceTest, TestMultipleSubscribersSameTopic)
{
    const char* topic_name = "multi-subscriber-topic";
    const char* test_message = "multi-subscriber-message";
    const int num_subscribers = 3;

    // Create provider (use local)
    auto provider_handle = router_provider_create(topic_name, true);
    ASSERT_NE(provider_handle, nullptr);

    // Create multiple subscribers
    std::vector<ROUTER_SUBSCRIBER_HANDLE> subscriber_handles;
    std::vector<std::atomic<int>> callback_counts(num_subscribers);

    for (int i = 0; i < num_subscribers; ++i)
    {
        std::string subscriber_id = "multi-subscriber-" + std::to_string(i);
        auto handle = router_subscriber_create(topic_name, subscriber_id.c_str(), true);
        ASSERT_NE(handle, nullptr);
        subscriber_handles.push_back(handle);

        callback_counts[i] = 0;

        // Create unique callback for each subscriber
        static std::vector<std::function<void(const char*)>> callbacks;
        callbacks.push_back(
            [&callback_counts, i](const char* message)
            {
                if (message != nullptr)
                {
                    callback_counts[i]++;
                }
            });

        int result = router_subscriber_subscribe(handle, integration_test_callback);
        EXPECT_EQ(result, 0);
    }

    // Reset global counter
    g_integration_callback_count = 0;

    // Give time for subscriptions to be established
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Send message
    int send_result = router_provider_send(provider_handle, test_message, strlen(test_message) + 1);
    EXPECT_EQ(send_result, 0);

    // Wait for callbacks
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Verify at least one callback was called (all subscribers use same callback function)
    EXPECT_GT(g_integration_callback_count.load(), 0);

    // Clean up
    for (auto handle : subscriber_handles)
    {
        router_subscriber_unsubscribe(handle);
        router_subscriber_destroy(handle);
    }
    EXPECT_NO_THROW(router_provider_destroy(provider_handle));
}

/**
 * @brief Integration test: Large message handling through C interface
 */
TEST_F(RouterCInterfaceTest, TestLargeMessageCInterface)
{
    const char* topic_name = "large-message-topic";
    const char* subscriber_id = "large-message-subscriber";

    // Create large message (10KB) with null terminator
    std::string large_message(10 * 1024, 'L');
    large_message += '\0'; // Add null terminator

    // Create provider and subscriber (use local)
    auto provider_handle = router_provider_create(topic_name, true);
    ASSERT_NE(provider_handle, nullptr);

    auto subscriber_handle = router_subscriber_create(topic_name, subscriber_id, true);
    ASSERT_NE(subscriber_handle, nullptr);

    // Subscribe
    g_integration_callback_count = 0;
    g_integration_last_message.clear();

    int subscribe_result = router_subscriber_subscribe(subscriber_handle, integration_test_callback);
    EXPECT_EQ(subscribe_result, 0);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Send large message
    int send_result = router_provider_send(provider_handle, large_message.c_str(), large_message.size());
    EXPECT_EQ(send_result, 0);

    // Wait for callback
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Verify callback was called and message received correctly
    EXPECT_GT(g_integration_callback_count.load(), 0);
    {
        std::lock_guard<std::mutex> lock(g_integration_message_mutex);
        // The callback receives data without the null terminator
        EXPECT_EQ(g_integration_last_message.size(), large_message.size() - 1); // -1 for null terminator
    }

    // Clean up
    router_subscriber_unsubscribe(subscriber_handle);
    router_subscriber_destroy(subscriber_handle);
    router_provider_destroy(provider_handle);
}

/**
 * @brief Integration test: Multiple topics with C interface subscribers
 */
TEST_F(RouterCInterfaceTest, TestMultipleTopicsCInterface)
{
    const char* topic1 = "topic1";
    const char* topic2 = "topic2";
    const char* subscriber_id = "multi-topic-subscriber";
    const char* message1 = "message-for-topic1";
    const char* message2 = "message-for-topic2";

    // Create providers for different topics (use local)
    auto provider1 = router_provider_create(topic1, true);
    auto provider2 = router_provider_create(topic2, true);
    ASSERT_NE(provider1, nullptr);
    ASSERT_NE(provider2, nullptr);

    // Create subscribers for different topics (use local)
    auto subscriber1 = router_subscriber_create(topic1, subscriber_id, true);
    auto subscriber2 = router_subscriber_create(topic2, subscriber_id, true);
    ASSERT_NE(subscriber1, nullptr);
    ASSERT_NE(subscriber2, nullptr);

    // Subscribe both
    g_integration_callback_count = 0;

    router_subscriber_subscribe(subscriber1, integration_test_callback);
    router_subscriber_subscribe(subscriber2, integration_test_callback);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Send to topic1
    router_provider_send(provider1, message1, strlen(message1) + 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    int count_after_topic1 = g_integration_callback_count.load();
    EXPECT_GT(count_after_topic1, 0);

    // Send to topic2
    router_provider_send(provider2, message2, strlen(message2) + 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    int count_after_topic2 = g_integration_callback_count.load();
    EXPECT_GT(count_after_topic2, count_after_topic1);

    // Clean up
    router_subscriber_destroy(subscriber1);
    router_subscriber_destroy(subscriber2);
    router_provider_destroy(provider1);
    router_provider_destroy(provider2);
}

/**
 * @brief Integration test: Function pointer usage in real scenario
 */
TEST_F(RouterCInterfaceTest, TestFunctionPointersIntegration)
{
    // Get function pointers
    router_subscriber_create_func create_func = router_subscriber_create;
    router_subscriber_subscribe_func subscribe_func = router_subscriber_subscribe;
    router_subscriber_unsubscribe_func unsubscribe_func = router_subscriber_unsubscribe;
    router_subscriber_destroy_func destroy_func = router_subscriber_destroy;

    const char* topic_name = "function-pointer-topic";
    const char* subscriber_id = "function-pointer-subscriber";
    const char* test_message = "function-pointer-message";

    // Create provider (use local)
    auto provider_handle = router_provider_create(topic_name, true);
    ASSERT_NE(provider_handle, nullptr);

    // Use function pointers to create and manage subscriber (use local)
    auto subscriber_handle = create_func(topic_name, subscriber_id, true);
    ASSERT_NE(subscriber_handle, nullptr);

    // Subscribe using function pointer
    g_integration_callback_count = 0;
    int result = subscribe_func(subscriber_handle, integration_test_callback);
    EXPECT_EQ(result, 0);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Send message
    router_provider_send(provider_handle, test_message, strlen(test_message) + 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Verify callback was called
    EXPECT_GT(g_integration_callback_count.load(), 0);

    // Clean up using function pointers
    unsubscribe_func(subscriber_handle);
    destroy_func(subscriber_handle);
    router_provider_destroy(provider_handle);
}
