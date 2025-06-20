/*
 * Wazuh router - C API tests
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "router.h"
#include <gtest/gtest.h>
#include <string>
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
