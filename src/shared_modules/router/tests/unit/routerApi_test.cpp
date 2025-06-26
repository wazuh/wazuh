/*
 * Wazuh router - C API tests
 * Copyright (C) 2015, Wazuh Inc.
 * June 25, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "router.h"
#include <gtest/gtest.h>
#include <string>
#include <thread>
#include <vector>

// Simple log callback for testing
void test_log_callback(const modules_log_level_t /*level*/, const char* /*message*/, const char* /*tag*/)
{
    // Just capture calls, don't do anything
}

/**
 * @brief Runs unit tests for Router C API
 */
class RouterAPITest : public ::testing::Test
{
protected:
    RouterAPITest() = default;
    ~RouterAPITest() override = default;

    void SetUp() override
    {
        // Initialize router for each test
        router_initialize(test_log_callback);
    }

    void TearDown() override
    {
        // Clean up after each test
        router_stop();
    }
};

/*
 * @brief Tests router initialization
 */
TEST_F(RouterAPITest, TestRouterInitialize)
{
    // Test with valid callback
    EXPECT_EQ(0, router_initialize(test_log_callback));

    // Test with null callback
    EXPECT_EQ(0, router_initialize(nullptr));
}

/*
 * @brief Tests router start
 */
TEST_F(RouterAPITest, TestRouterStart)
{
    EXPECT_EQ(0, router_start());
}

/*
 * @brief Tests router stop
 */
TEST_F(RouterAPITest, TestRouterStop)
{
    router_start();
    EXPECT_EQ(0, router_stop());
}

/*
 * @brief Tests router start/stop cycle
 */
TEST_F(RouterAPITest, TestRouterStartStopCycle)
{
    EXPECT_EQ(0, router_start());
    EXPECT_EQ(0, router_stop());

    // Should be able to start again
    EXPECT_EQ(0, router_start());
    EXPECT_EQ(0, router_stop());
}

/*
 * @brief Tests provider creation with valid parameters
 */
TEST_F(RouterAPITest, TestProviderCreateValid)
{
    router_start();

    const char* providerName = "test-provider";
    ROUTER_PROVIDER_HANDLE handle = router_provider_create(providerName, true);

    EXPECT_NE(nullptr, handle);

    router_provider_destroy(handle);
}

/*
 * @brief Tests provider creation with null name
 */
TEST_F(RouterAPITest, TestProviderCreateNullName)
{
    router_start();

    ROUTER_PROVIDER_HANDLE handle = router_provider_create(nullptr, true);
    EXPECT_EQ(nullptr, handle);
}

/*
 * @brief Tests provider creation with empty name
 */
TEST_F(RouterAPITest, TestProviderCreateEmptyName)
{
    router_start();

    const char* providerName = "";
    ROUTER_PROVIDER_HANDLE handle = router_provider_create(providerName, true);
    EXPECT_EQ(nullptr, handle);
}

/*
 * @brief Tests provider creation for both local and remote
 */
TEST_F(RouterAPITest, TestProviderCreateLocalAndRemote)
{
    router_start();

    const char* providerName = "test-provider";

    // Test local provider
    ROUTER_PROVIDER_HANDLE localHandle = router_provider_create(providerName, true);
    EXPECT_NE(nullptr, localHandle);

    // Test remote provider
    ROUTER_PROVIDER_HANDLE remoteHandle = router_provider_create("remote-provider", false);
    EXPECT_NE(nullptr, remoteHandle);

    router_provider_destroy(localHandle);
    router_provider_destroy(remoteHandle);
}

/*
 * @brief Tests provider send with valid data
 */
TEST_F(RouterAPITest, TestProviderSendValid)
{
    router_start();

    const char* providerName = "test-provider";
    ROUTER_PROVIDER_HANDLE handle = router_provider_create(providerName, true);
    EXPECT_NE(nullptr, handle);

    const char* message = "test message";
    unsigned int messageSize = strlen(message);

    EXPECT_EQ(0, router_provider_send(handle, message, messageSize));

    router_provider_destroy(handle);
}

/*
 * @brief Tests provider send with null handle
 */
TEST_F(RouterAPITest, TestProviderSendNullHandle)
{
    router_start();

    const char* message = "test message";
    unsigned int messageSize = strlen(message);

    EXPECT_EQ(-1, router_provider_send(nullptr, message, messageSize));
}

/*
 * @brief Tests provider send with null message
 */
TEST_F(RouterAPITest, TestProviderSendNullMessage)
{
    router_start();

    const char* providerName = "test-provider";
    ROUTER_PROVIDER_HANDLE handle = router_provider_create(providerName, true);
    EXPECT_NE(nullptr, handle);

    EXPECT_EQ(-1, router_provider_send(handle, nullptr, 10));

    router_provider_destroy(handle);
}

/*
 * @brief Tests provider send with zero size
 */
TEST_F(RouterAPITest, TestProviderSendZeroSize)
{
    router_start();

    const char* providerName = "test-provider";
    ROUTER_PROVIDER_HANDLE handle = router_provider_create(providerName, true);
    EXPECT_NE(nullptr, handle);

    const char* message = "test message";

    EXPECT_NE(0, router_provider_send(handle, message, 0));

    router_provider_destroy(handle);
}

/*
 * @brief Tests provider send flatbuffer with null handle
 */
TEST_F(RouterAPITest, TestProviderSendFlatbufferNullHandle)
{
    router_start();

    const char* message = "test message";
    const char* schema = "test schema";

    EXPECT_EQ(-1, router_provider_send_fb(nullptr, message, schema));
}

/*
 * @brief Tests provider send flatbuffer with null message
 */
TEST_F(RouterAPITest, TestProviderSendFlatbufferNullMessage)
{
    router_start();

    const char* providerName = "test-provider";
    ROUTER_PROVIDER_HANDLE handle = router_provider_create(providerName, true);
    EXPECT_NE(nullptr, handle);

    const char* schema = "test schema";

    EXPECT_EQ(-1, router_provider_send_fb(handle, nullptr, schema));

    router_provider_destroy(handle);
}

/*
 * @brief Tests provider send flatbuffer with null schema
 */
TEST_F(RouterAPITest, TestProviderSendFlatbufferNullSchema)
{
    router_start();

    const char* providerName = "test-provider";
    ROUTER_PROVIDER_HANDLE handle = router_provider_create(providerName, true);
    EXPECT_NE(nullptr, handle);

    const char* message = "test message";

    EXPECT_EQ(-1, router_provider_send_fb(handle, message, nullptr));

    router_provider_destroy(handle);
}

/*
 * @brief Tests provider destroy with valid handle
 */
TEST_F(RouterAPITest, TestProviderDestroyValid)
{
    router_start();

    const char* providerName = "test-provider";
    ROUTER_PROVIDER_HANDLE handle = router_provider_create(providerName, true);
    EXPECT_NE(nullptr, handle);

    EXPECT_NO_THROW(router_provider_destroy(handle));
}

/*
 * @brief Tests provider destroy with null handle
 */
TEST_F(RouterAPITest, TestProviderDestroyNull)
{
    router_start();

    EXPECT_NO_THROW(router_provider_destroy(nullptr));
}

/*
 * @brief Tests multiple provider creation and destruction
 */
TEST_F(RouterAPITest, TestMultipleProviders)
{
    router_start();

    std::vector<ROUTER_PROVIDER_HANDLE> handles;

    // Create multiple providers
    for (int i = 0; i < 5; ++i)
    {
        std::string providerName = "provider-" + std::to_string(i);
        ROUTER_PROVIDER_HANDLE handle = router_provider_create(providerName.c_str(), true);
        EXPECT_NE(nullptr, handle);
        handles.push_back(handle);
    }

    // Send messages to all providers
    for (auto handle : handles)
    {
        const char* message = "test message";
        EXPECT_EQ(0, router_provider_send(handle, message, strlen(message)));
    }

    // Destroy all providers
    for (auto handle : handles)
    {
        router_provider_destroy(handle);
    }
}

/*
 * @brief Tests API registration with valid parameters
 */
TEST_F(RouterAPITest, TestRegisterAPIEndpoint)
{
    router_start();

    const char* module = "test-module";
    const char* socketPath = "test-socket";
    const char* method = "GET";
    const char* endpoint = "/test";

    EXPECT_NO_THROW(router_register_api_endpoint(module, socketPath, method, endpoint, nullptr, nullptr));
}

/*
 * @brief Tests API start with valid socket path
 */
TEST_F(RouterAPITest, TestStartAPI)
{
    router_start();

    const char* socketPath = "test-socket";
    const char* module = "test-module";
    const char* method = "GET";
    const char* endpoint = "/test";

    EXPECT_NO_THROW(router_register_api_endpoint(module, socketPath, method, endpoint, nullptr, nullptr));
    EXPECT_NO_THROW(router_start_api(socketPath));

    // Clean up
    router_stop_api(socketPath);
}

/*
 * @brief Tests API stop with valid socket path
 */
TEST_F(RouterAPITest, TestStopAPI)
{
    router_start();

    const char* socketPath = "test-socket";
    router_start_api(socketPath);

    EXPECT_NO_THROW(router_stop_api(socketPath));
}

/*
 * @brief Tests API registration with null module
 */
TEST_F(RouterAPITest, TestRegisterAPIEndpointNullModule)
{
    router_start();

    const char* socketPath = "test-socket";
    const char* method = "GET";
    const char* endpoint = "/test";

    EXPECT_NO_THROW(router_register_api_endpoint(nullptr, socketPath, method, endpoint, nullptr, nullptr));
}

/*
 * @brief Tests API registration with null socket path
 */
TEST_F(RouterAPITest, TestRegisterAPIEndpointNullSocketPath)
{
    router_start();

    const char* module = "test-module";
    const char* method = "GET";
    const char* endpoint = "/test";

    EXPECT_NO_THROW(router_register_api_endpoint(module, nullptr, method, endpoint, nullptr, nullptr));
}

/*
 * @brief Tests API registration with null method
 */
TEST_F(RouterAPITest, TestRegisterAPIEndpointNullMethod)
{
    router_start();

    const char* module = "test-module";
    const char* socketPath = "test-socket";
    const char* endpoint = "/test";

    EXPECT_NO_THROW(router_register_api_endpoint(module, socketPath, nullptr, endpoint, nullptr, nullptr));
}

/*
 * @brief Tests API registration with null endpoint
 */
TEST_F(RouterAPITest, TestRegisterAPIEndpointNullEndpoint)
{
    router_start();

    const char* module = "test-module";
    const char* socketPath = "test-socket";
    const char* method = "GET";

    EXPECT_NO_THROW(router_register_api_endpoint(module, socketPath, method, nullptr, nullptr, nullptr));
}

/*
 * @brief Tests API registration with POST method
 */
TEST_F(RouterAPITest, TestRegisterAPIEndpointPOST)
{
    router_start();

    const char* module = "test-module";
    const char* socketPath = "test-socket-post";
    const char* method = "POST";
    const char* endpoint = "/test";

    EXPECT_NO_THROW(router_register_api_endpoint(module, socketPath, method, endpoint, nullptr, nullptr));
}

/*
 * @brief Tests API registration with invalid method
 */
TEST_F(RouterAPITest, TestRegisterAPIEndpointInvalidMethod)
{
    router_start();

    const char* module = "test-module";
    const char* socketPath = "test-socket";
    const char* method = "PUT"; // Invalid method
    const char* endpoint = "/test";

    EXPECT_NO_THROW(router_register_api_endpoint(module, socketPath, method, endpoint, nullptr, nullptr));
}

/*
 * @brief Tests API start with null socket path
 */
TEST_F(RouterAPITest, TestStartAPINullSocketPath)
{
    router_start();

    EXPECT_NO_THROW(router_start_api(nullptr));
}

/*
 * @brief Tests API start with non-existent socket path
 */
TEST_F(RouterAPITest, TestStartAPINonExistentSocketPath)
{
    router_start();

    const char* socketPath = "non-existent-socket";

    EXPECT_NO_THROW(router_start_api(socketPath));
}

/*
 * @brief Tests API stop with null socket path
 */
TEST_F(RouterAPITest, TestStopAPINullSocketPath)
{
    router_start();

    EXPECT_NO_THROW(router_stop_api(nullptr));
}

/*
 * @brief Tests API stop with non-existent socket path
 */
TEST_F(RouterAPITest, TestStopAPINonExistentSocketPath)
{
    router_start();

    const char* socketPath = "non-existent-socket";

    EXPECT_NO_THROW(router_stop_api(socketPath));
}

/*
 * @brief Tests multiple API endpoints on same socket
 */
TEST_F(RouterAPITest, TestMultipleAPIEndpointsSameSocket)
{
    router_start();

    const char* module = "test-module";
    const char* socketPath = "shared-socket";

    // Register multiple endpoints
    EXPECT_NO_THROW(router_register_api_endpoint(module, socketPath, "GET", "/endpoint1", nullptr, nullptr));
    EXPECT_NO_THROW(router_register_api_endpoint(module, socketPath, "POST", "/endpoint2", nullptr, nullptr));
    EXPECT_NO_THROW(router_register_api_endpoint(module, socketPath, "GET", "/endpoint3", nullptr, nullptr));

    EXPECT_NO_THROW(router_start_api(socketPath));
    EXPECT_NO_THROW(router_stop_api(socketPath));
}

/*
 * @brief Tests router functionality without initialization
 */
// TEST_F(RouterAPITest, TestOperationsWithoutInitialization)
// {
//     // Note: This test runs without calling router_initialize first
//     EXPECT_EQ(-1, router_start());
//     EXPECT_EQ(-1, router_stop());

//     ROUTER_PROVIDER_HANDLE handle = router_provider_create("test", true);
//     EXPECT_EQ(nullptr, handle);
// }

/*
 * @brief Tests provider operations with invalid handle
 */
TEST_F(RouterAPITest, TestProviderOperationsInvalidHandle)
{
    router_start();

    // Create fake handle
    auto fakeHandle = reinterpret_cast<ROUTER_PROVIDER_HANDLE>(0xDEADBEEF);

    const char* message = "test";
    EXPECT_EQ(-1, router_provider_send(fakeHandle, message, strlen(message)));
    EXPECT_EQ(-1, router_provider_send_fb(fakeHandle, message, "schema"));

    EXPECT_NO_THROW(router_provider_destroy(fakeHandle));
}

/*
 * @brief Tests concurrent provider operations
 */
TEST_F(RouterAPITest, TestConcurrentProviderOperations)
{
    router_start();

    const int numThreads = 4;
    const int numProvidersPerThread = 5;
    std::vector<std::thread> threads;
    threads.reserve(numThreads);
    std::vector<std::vector<ROUTER_PROVIDER_HANDLE>> allHandles(numThreads);

    // Create providers concurrently
    for (int t = 0; t < numThreads; ++t)
    {
        threads.emplace_back(
            [&, t]()
            {
                for (int i = 0; i < numProvidersPerThread; ++i)
                {
                    std::string providerName = "thread-" + std::to_string(t) + "-provider-" + std::to_string(i);
                    ROUTER_PROVIDER_HANDLE handle = router_provider_create(providerName.c_str(), true);
                    EXPECT_NE(nullptr, handle);
                    allHandles[t].push_back(handle);
                }
            });
    }

    // Wait for all creation threads
    for (auto& thread : threads)
    {
        thread.join();
    }

    threads.clear();

    // Send messages concurrently
    for (int t = 0; t < numThreads; ++t)
    {
        threads.emplace_back(
            [&, t]()
            {
                for (auto handle : allHandles[t])
                {
                    const char* message = "concurrent test message";
                    EXPECT_EQ(0, router_provider_send(handle, message, strlen(message)));
                }
            });
    }

    // Wait for all send threads
    for (auto& thread : threads)
    {
        thread.join();
    }

    // Clean up
    for (int t = 0; t < numThreads; ++t)
    {
        for (auto handle : allHandles[t])
        {
            router_provider_destroy(handle);
        }
    }
}

/*
 * @brief Tests large message sending
 */
TEST_F(RouterAPITest, TestLargeMessageSend)
{
    router_start();

    const char* providerName = "large-message-provider";
    ROUTER_PROVIDER_HANDLE handle = router_provider_create(providerName, true);
    EXPECT_NE(nullptr, handle);

    // Create a large message (1MB)
    const size_t largeSize = 1024 * 1024;
    std::vector<char> largeMessage(largeSize, 'A');

    EXPECT_EQ(0, router_provider_send(handle, largeMessage.data(), largeMessage.size()));

    router_provider_destroy(handle);
}

/*
 * @brief Tests empty message sending
 */
TEST_F(RouterAPITest, TestEmptyMessageSend)
{
    router_start();

    const char* providerName = "empty-message-provider";
    ROUTER_PROVIDER_HANDLE handle = router_provider_create(providerName, true);
    EXPECT_NE(nullptr, handle);

    const char* emptyMessage = "";
    EXPECT_NE(0, router_provider_send(handle, emptyMessage, 0));

    router_provider_destroy(handle);
}

/*
 * @brief Tests provider creation with very long name
 */
// TEST_F(RouterAPITest, TestProviderCreateLongName)
// {
//     router_start();

//     // Create a very long provider name
//     std::string longName(1024, 'X');
//     ROUTER_PROVIDER_HANDLE handle = router_provider_create(longName.c_str(), true);
//     EXPECT_NE(nullptr, handle);

//     router_provider_destroy(handle);
// }

/*
 * @brief Tests router double stop without start
 */
TEST_F(RouterAPITest, TestDoubleStopWithoutStart)
{
    EXPECT_EQ(-1, router_stop());
    EXPECT_EQ(-1, router_stop());
}

/*
 * @brief Tests multiple consecutive start calls
 */
TEST_F(RouterAPITest, TestMultipleStartCalls)
{
    EXPECT_EQ(0, router_start());
    EXPECT_EQ(-1, router_start()); // Second start should fail
    EXPECT_EQ(0, router_stop());
}

/*
 * @brief Tests provider operations after router stop
 */
// TEST_F(RouterAPITest, TestProviderOperationsAfterStop)
// {
//     router_start();

//     const char* providerName = "test-provider";
//     ROUTER_PROVIDER_HANDLE handle = router_provider_create(providerName, true);
//     EXPECT_NE(nullptr, handle);

//     router_stop();

//     // Operations should still work with existing handles
//     const char* message = "test message";
//     EXPECT_EQ(0, router_provider_send(handle, message, strlen(message)));

//     router_provider_destroy(handle);
// }
