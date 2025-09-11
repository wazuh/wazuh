/*
 * Wazuh router - Router Subscriber C Interface tests
 * Copyright (C) 2015, Wazuh Inc.
 * September 11, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "router.h"
#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <thread>
#include <vector>

/**
 * @brief Runs unit tests for Router Subscriber C Interface
 */
class RouterSubscriberCInterfaceTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Start router for each test
        ASSERT_EQ(router_start(), 0);
    }

    void TearDown() override
    {
        // Stop router after each test
        ASSERT_EQ(router_stop(), 0);
    }
};

/**
 * @brief Test router_subscriber_create with valid parameters
 */
TEST_F(RouterSubscriberCInterfaceTest, TestCreateSubscriberValid)
{
    const char* topic_name = "test-topic";
    const char* subscriber_id = "test-subscriber";

    auto handle = router_subscriber_create(topic_name, subscriber_id, true);
    EXPECT_NE(handle, nullptr);

    if (handle != nullptr)
    {
        router_subscriber_destroy(handle);
    }
}

/**
 * @brief Test router_subscriber_create with remote subscriber
 */
TEST_F(RouterSubscriberCInterfaceTest, TestCreateSubscriberRemote)
{
    const char* topic_name = "remote-topic";
    const char* subscriber_id = "remote-subscriber";

    auto handle = router_subscriber_create(topic_name, subscriber_id, false);
    EXPECT_NE(handle, nullptr);

    if (handle != nullptr)
    {
        router_subscriber_destroy(handle);
    }
}

/**
 * @brief Test router_subscriber_create with null topic name
 */
TEST_F(RouterSubscriberCInterfaceTest, TestCreateSubscriberNullTopicName)
{
    const char* subscriber_id = "test-subscriber";

    auto handle = router_subscriber_create(nullptr, subscriber_id, true);
    EXPECT_EQ(handle, nullptr);
}

/**
 * @brief Test router_subscriber_create with null subscriber ID
 */
TEST_F(RouterSubscriberCInterfaceTest, TestCreateSubscriberNullSubscriberId)
{
    const char* topic_name = "test-topic";

    auto handle = router_subscriber_create(topic_name, nullptr, true);
    EXPECT_EQ(handle, nullptr);
}

/**
 * @brief Test router_subscriber_create with empty topic name
 */
TEST_F(RouterSubscriberCInterfaceTest, TestCreateSubscriberEmptyTopicName)
{
    const char* topic_name = "";
    const char* subscriber_id = "test-subscriber";

    auto handle = router_subscriber_create(topic_name, subscriber_id, true);
    // Should handle empty topic name gracefully
    if (handle != nullptr)
    {
        router_subscriber_destroy(handle);
    }
}

/**
 * @brief Test router_subscriber_create with empty subscriber ID
 */
TEST_F(RouterSubscriberCInterfaceTest, TestCreateSubscriberEmptySubscriberId)
{
    const char* topic_name = "test-topic";
    const char* subscriber_id = "";

    auto handle = router_subscriber_create(topic_name, subscriber_id, true);
    // Should handle empty subscriber ID gracefully
    if (handle != nullptr)
    {
        router_subscriber_destroy(handle);
    }
}

/**
 * @brief Test router_subscriber_create with very long topic name
 */
TEST_F(RouterSubscriberCInterfaceTest, TestCreateSubscriberLongTopicName)
{
    std::string long_topic(1000, 'T');
    const char* subscriber_id = "test-subscriber";

    auto handle = router_subscriber_create(long_topic.c_str(), subscriber_id, true);
    EXPECT_NE(handle, nullptr);

    if (handle != nullptr)
    {
        router_subscriber_destroy(handle);
    }
}

/**
 * @brief Test router_subscriber_create with very long subscriber ID
 */
TEST_F(RouterSubscriberCInterfaceTest, TestCreateSubscriberLongSubscriberId)
{
    const char* topic_name = "test-topic";
    std::string long_id(1000, 'S');

    auto handle = router_subscriber_create(topic_name, long_id.c_str(), true);
    EXPECT_NE(handle, nullptr);

    if (handle != nullptr)
    {
        router_subscriber_destroy(handle);
    }
}

/**
 * @brief Test router_subscriber_create with special characters
 */
TEST_F(RouterSubscriberCInterfaceTest, TestCreateSubscriberSpecialCharacters)
{
    const char* topic_name = "test-topic!@#$%^&*()";
    const char* subscriber_id = "test-subscriber!@#$%^&*()";

    auto handle = router_subscriber_create(topic_name, subscriber_id, true);
    EXPECT_NE(handle, nullptr);

    if (handle != nullptr)
    {
        router_subscriber_destroy(handle);
    }
}

/**
 * @brief Test multiple subscribers with same topic and ID
 */
TEST_F(RouterSubscriberCInterfaceTest, TestCreateMultipleSubscribersSameId)
{
    const char* topic_name = "same-topic";
    const char* subscriber_id = "same-id";

    auto handle1 = router_subscriber_create(topic_name, subscriber_id, true);
    auto handle2 = router_subscriber_create(topic_name, subscriber_id, true);

    EXPECT_NE(handle1, nullptr);
    EXPECT_NE(handle2, nullptr);
    EXPECT_NE(handle1, handle2); // Should be different handles

    if (handle1 != nullptr)
    {
        router_subscriber_destroy(handle1);
    }
    if (handle2 != nullptr)
    {
        router_subscriber_destroy(handle2);
    }
}

/**
 * @brief Global callback function for testing
 */
static std::atomic<int> g_callback_count {0};
static std::string g_last_message;

void test_callback(const char* message)
{
    if (message != nullptr)
    {
        g_last_message = std::string(message);
        g_callback_count++;
    }
}

/**
 * @brief Test router_subscriber_subscribe with valid handle and callback
 */
TEST_F(RouterSubscriberCInterfaceTest, TestSubscribeValid)
{
    const char* topic_name = "test-topic";
    const char* subscriber_id = "test-subscriber";

    auto handle = router_subscriber_create(topic_name, subscriber_id, true);
    ASSERT_NE(handle, nullptr);

    g_callback_count = 0;
    g_last_message.clear();

    int result = router_subscriber_subscribe(handle, test_callback);
    EXPECT_EQ(result, 0); // Assuming 0 means success

    router_subscriber_destroy(handle);
}

/**
 * @brief Test router_subscriber_subscribe with null handle
 */
TEST_F(RouterSubscriberCInterfaceTest, TestSubscribeNullHandle)
{
    int result = router_subscriber_subscribe(nullptr, test_callback);
    EXPECT_NE(result, 0); // Should return error code
}

/**
 * @brief Test router_subscriber_subscribe with null callback
 */
TEST_F(RouterSubscriberCInterfaceTest, TestSubscribeNullCallback)
{
    const char* topic_name = "test-topic";
    const char* subscriber_id = "test-subscriber";

    auto handle = router_subscriber_create(topic_name, subscriber_id, true);
    ASSERT_NE(handle, nullptr);

    int result = router_subscriber_subscribe(handle, nullptr);
    EXPECT_NE(result, 0); // Should return error code

    router_subscriber_destroy(handle);
}

/**
 * @brief Test router_subscriber_subscribe multiple times on same handle
 */
TEST_F(RouterSubscriberCInterfaceTest, TestSubscribeMultipleTimes)
{
    const char* topic_name = "test-topic";
    const char* subscriber_id = "test-subscriber";

    auto handle = router_subscriber_create(topic_name, subscriber_id, true);
    ASSERT_NE(handle, nullptr);

    g_callback_count = 0;

    // First subscription
    int result1 = router_subscriber_subscribe(handle, test_callback);
    EXPECT_EQ(result1, 0);

    // Second subscription (might overwrite first)
    int result2 = router_subscriber_subscribe(handle, test_callback);
    EXPECT_EQ(result2, 0);

    router_subscriber_destroy(handle);
}

/**
 * @brief Test router_subscriber_unsubscribe with valid handle
 */
TEST_F(RouterSubscriberCInterfaceTest, TestUnsubscribeValid)
{
    const char* topic_name = "test-topic";
    const char* subscriber_id = "test-subscriber";

    auto handle = router_subscriber_create(topic_name, subscriber_id, true);
    ASSERT_NE(handle, nullptr);

    g_callback_count = 0;
    router_subscriber_subscribe(handle, test_callback);

    EXPECT_NO_THROW(router_subscriber_unsubscribe(handle));

    router_subscriber_destroy(handle);
}

/**
 * @brief Test router_subscriber_unsubscribe with null handle
 */
TEST_F(RouterSubscriberCInterfaceTest, TestUnsubscribeNullHandle)
{
    // Should not crash with null handle
    EXPECT_NO_THROW(router_subscriber_unsubscribe(nullptr));
}

/**
 * @brief Test router_subscriber_unsubscribe without prior subscribe
 */
TEST_F(RouterSubscriberCInterfaceTest, TestUnsubscribeWithoutSubscribe)
{
    const char* topic_name = "test-topic";
    const char* subscriber_id = "test-subscriber";

    auto handle = router_subscriber_create(topic_name, subscriber_id, true);
    ASSERT_NE(handle, nullptr);

    // Unsubscribe without subscribing first
    EXPECT_NO_THROW(router_subscriber_unsubscribe(handle));

    router_subscriber_destroy(handle);
}

/**
 * @brief Test router_subscriber_destroy with valid handle
 */
TEST_F(RouterSubscriberCInterfaceTest, TestDestroyValid)
{
    const char* topic_name = "test-topic";
    const char* subscriber_id = "test-subscriber";

    auto handle = router_subscriber_create(topic_name, subscriber_id, true);
    ASSERT_NE(handle, nullptr);

    EXPECT_NO_THROW(router_subscriber_destroy(handle));
}

/**
 * @brief Test router_subscriber_destroy with null handle
 */
TEST_F(RouterSubscriberCInterfaceTest, TestDestroyNullHandle)
{
    // Should not crash with null handle
    EXPECT_NO_THROW(router_subscriber_destroy(nullptr));
}

/**
 * @brief Test router_subscriber_destroy after subscribe
 */
TEST_F(RouterSubscriberCInterfaceTest, TestDestroyAfterSubscribe)
{
    const char* topic_name = "test-topic";
    const char* subscriber_id = "test-subscriber";

    auto handle = router_subscriber_create(topic_name, subscriber_id, true);
    ASSERT_NE(handle, nullptr);

    g_callback_count = 0;
    router_subscriber_subscribe(handle, test_callback);

    // Destroy should automatically unsubscribe
    EXPECT_NO_THROW(router_subscriber_destroy(handle));
}

/**
 * @brief Test double destroy (should be safe)
 */
TEST_F(RouterSubscriberCInterfaceTest, TestDoubleDestroy)
{
    const char* topic_name = "test-topic";
    const char* subscriber_id = "test-subscriber";

    auto handle = router_subscriber_create(topic_name, subscriber_id, true);
    ASSERT_NE(handle, nullptr);

    router_subscriber_destroy(handle);

    // Second destroy should be safe
    EXPECT_NO_THROW(router_subscriber_destroy(handle));
}

/**
 * @brief Test full lifecycle: create -> subscribe -> unsubscribe -> destroy
 */
TEST_F(RouterSubscriberCInterfaceTest, TestFullLifecycle)
{
    const char* topic_name = "lifecycle-topic";
    const char* subscriber_id = "lifecycle-subscriber";

    // Create
    auto handle = router_subscriber_create(topic_name, subscriber_id, true);
    ASSERT_NE(handle, nullptr);

    // Subscribe
    g_callback_count = 0;
    int subscribe_result = router_subscriber_subscribe(handle, test_callback);
    EXPECT_EQ(subscribe_result, 0);

    // Unsubscribe
    EXPECT_NO_THROW(router_subscriber_unsubscribe(handle));

    // Destroy
    EXPECT_NO_THROW(router_subscriber_destroy(handle));
}

/**
 * @brief Test concurrent subscriber creation
 */
TEST_F(RouterSubscriberCInterfaceTest, TestConcurrentSubscriberCreation)
{
    const int num_threads = 4;
    const int subscribers_per_thread = 10;
    std::vector<std::thread> threads;
    std::vector<ROUTER_SUBSCRIBER_HANDLE> handles;
    std::mutex handles_mutex;

    threads.reserve(num_threads);

    for (int t = 0; t < num_threads; ++t)
    {
        threads.emplace_back(
            [&handles, &handles_mutex, t, subscribers_per_thread]()
            {
                for (int i = 0; i < subscribers_per_thread; ++i)
                {
                    std::string topic = "thread-" + std::to_string(t) + "-topic-" + std::to_string(i);
                    std::string subscriber_id = "thread-" + std::to_string(t) + "-subscriber-" + std::to_string(i);

                    auto handle = router_subscriber_create(topic.c_str(), subscriber_id.c_str(), true);
                    if (handle != nullptr)
                    {
                        std::lock_guard<std::mutex> lock(handles_mutex);
                        handles.push_back(handle);
                    }
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(handles.size(), static_cast<size_t>(num_threads * subscribers_per_thread));

    // Clean up
    for (auto handle : handles)
    {
        router_subscriber_destroy(handle);
    }
}

/**
 * @brief Test function pointer typedefs
 */
TEST_F(RouterSubscriberCInterfaceTest, TestFunctionPointers)
{
    // Test that function pointers can be assigned
    router_subscriber_create_func create_func = router_subscriber_create;
    router_subscriber_subscribe_func subscribe_func = router_subscriber_subscribe;
    router_subscriber_unsubscribe_func unsubscribe_func = router_subscriber_unsubscribe;
    router_subscriber_destroy_func destroy_func = router_subscriber_destroy;

    EXPECT_NE(create_func, nullptr);
    EXPECT_NE(subscribe_func, nullptr);
    EXPECT_NE(unsubscribe_func, nullptr);
    EXPECT_NE(destroy_func, nullptr);

    // Test using function pointers
    const char* topic_name = "func-ptr-topic";
    const char* subscriber_id = "func-ptr-subscriber";

    auto handle = create_func(topic_name, subscriber_id, true);
    EXPECT_NE(handle, nullptr);

    if (handle != nullptr)
    {
        g_callback_count = 0;
        int result = subscribe_func(handle, test_callback);
        EXPECT_EQ(result, 0);

        unsubscribe_func(handle);
        destroy_func(handle);
    }
}

/**
 * @brief Test rapid create/destroy cycles
 */
TEST_F(RouterSubscriberCInterfaceTest, TestRapidCreateDestroyCycles)
{
    const int num_cycles = 100;

    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < num_cycles; ++i)
    {
        std::string topic = "rapid-topic-" + std::to_string(i);
        std::string subscriber_id = "rapid-subscriber-" + std::to_string(i);

        auto handle = router_subscriber_create(topic.c_str(), subscriber_id.c_str(), true);
        EXPECT_NE(handle, nullptr);

        if (handle != nullptr)
        {
            router_subscriber_destroy(handle);
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    // Should complete in reasonable time (less than 100ms)
    EXPECT_LT(duration.count(), 100000);
}
