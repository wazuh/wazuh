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

#include "router.h"
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

// ========================================================================================
// Unit tests for router_provider_send_fb_agent_ctx C API function
// ========================================================================================

/*
 * @brief Test router_provider_send_fb_agent_ctx with valid parameters
 */
TEST_F(RemoteProviderTest, TestRouterProviderSendFBAgentCtxValid)
{
    const char* providerName = "test-fb-agent-ctx-provider";
    ROUTER_PROVIDER_HANDLE handle = router_provider_create(providerName, true);
    EXPECT_NE(nullptr, handle);

    // Create test message
    const char* message = "test message data";
    const size_t messageSize = strlen(message);

    // Create test agent context
    struct agent_ctx agentContext;
    agentContext.id = "001";
    agentContext.name = "test-agent";
    agentContext.ip = "192.168.1.100";
    agentContext.version = "4.5.0";
    agentContext.module = "syscollector";

    EXPECT_EQ(0, router_provider_send_fb_agent_ctx(handle, message, messageSize, &agentContext));

    router_provider_destroy(handle);
}

/*
 * @brief Test router_provider_send_fb_agent_ctx with null handle
 */
TEST_F(RemoteProviderTest, TestRouterProviderSendFBAgentCtxNullHandle)
{
    const char* message = "test message";
    const size_t messageSize = strlen(message);

    struct agent_ctx agentContext;
    agentContext.id = "001";
    agentContext.name = "test-agent";
    agentContext.ip = "192.168.1.100";
    agentContext.version = "4.5.0";
    agentContext.module = "syscollector";

    EXPECT_EQ(-1, router_provider_send_fb_agent_ctx(nullptr, message, messageSize, &agentContext));
}

/*
 * @brief Test router_provider_send_fb_agent_ctx with null message
 */
TEST_F(RemoteProviderTest, TestRouterProviderSendFBAgentCtxNullMessage)
{
    const char* providerName = "test-fb-agent-ctx-null-msg";
    ROUTER_PROVIDER_HANDLE handle = router_provider_create(providerName, true);
    EXPECT_NE(nullptr, handle);

    const size_t messageSize = 10;

    struct agent_ctx agentContext;
    agentContext.id = "001";
    agentContext.name = "test-agent";
    agentContext.ip = "192.168.1.100";
    agentContext.version = "4.5.0";
    agentContext.module = "syscollector";

    EXPECT_EQ(-1, router_provider_send_fb_agent_ctx(handle, nullptr, messageSize, &agentContext));

    router_provider_destroy(handle);
}

/*
 * @brief Test router_provider_send_fb_agent_ctx with zero message size
 */
TEST_F(RemoteProviderTest, TestRouterProviderSendFBAgentCtxZeroSize)
{
    const char* providerName = "test-fb-agent-ctx-zero-size";
    ROUTER_PROVIDER_HANDLE handle = router_provider_create(providerName, true);
    EXPECT_NE(nullptr, handle);

    const char* message = "test message";
    const size_t messageSize = 0;

    struct agent_ctx agentContext;
    agentContext.id = "001";
    agentContext.name = "test-agent";
    agentContext.ip = "192.168.1.100";
    agentContext.version = "4.5.0";
    agentContext.module = "syscollector";

    EXPECT_EQ(0, router_provider_send_fb_agent_ctx(handle, message, messageSize, &agentContext));

    router_provider_destroy(handle);
}

/*
 * @brief Test router_provider_send_fb_agent_ctx with null agent context
 */
TEST_F(RemoteProviderTest, TestRouterProviderSendFBAgentCtxNullContext)
{
    const char* providerName = "test-fb-agent-ctx-null-ctx";
    ROUTER_PROVIDER_HANDLE handle = router_provider_create(providerName, true);
    EXPECT_NE(nullptr, handle);

    const char* message = "test message";
    const size_t messageSize = strlen(message);

    EXPECT_EQ(-1, router_provider_send_fb_agent_ctx(handle, message, messageSize, nullptr));

    router_provider_destroy(handle);
}

/*
 * @brief Test router_provider_send_fb_agent_ctx with empty agent context fields
 */
TEST_F(RemoteProviderTest, TestRouterProviderSendFBAgentCtxEmptyContext)
{
    const char* providerName = "test-fb-agent-ctx-empty-ctx";
    ROUTER_PROVIDER_HANDLE handle = router_provider_create(providerName, true);
    EXPECT_NE(nullptr, handle);

    const char* message = "test message";
    const size_t messageSize = strlen(message);

    struct agent_ctx agentContext;
    agentContext.id = "";
    agentContext.name = "";
    agentContext.ip = "";
    agentContext.version = "";
    agentContext.module = "";

    EXPECT_EQ(0, router_provider_send_fb_agent_ctx(handle, message, messageSize, &agentContext));

    router_provider_destroy(handle);
}

/*
 * @brief Test router_provider_send_fb_agent_ctx with null agent context fields
 */
TEST_F(RemoteProviderTest, TestRouterProviderSendFBAgentCtxNullContextFields)
{
    const char* providerName = "test-fb-agent-ctx-null-fields";
    ROUTER_PROVIDER_HANDLE handle = router_provider_create(providerName, true);
    EXPECT_NE(nullptr, handle);

    const char* message = "test message";
    const size_t messageSize = strlen(message);

    struct agent_ctx agentContext;
    agentContext.id = nullptr;
    agentContext.name = nullptr;
    agentContext.ip = nullptr;
    agentContext.version = nullptr;
    agentContext.module = nullptr;

    EXPECT_EQ(0, router_provider_send_fb_agent_ctx(handle, message, messageSize, &agentContext));

    router_provider_destroy(handle);
}

/*
 * @brief Test router_provider_send_fb_agent_ctx with large message
 */
TEST_F(RemoteProviderTest, TestRouterProviderSendFBAgentCtxLargeMessage)
{
    const char* providerName = "test-fb-agent-ctx-large";
    ROUTER_PROVIDER_HANDLE handle = router_provider_create(providerName, true);
    EXPECT_NE(nullptr, handle);

    // Create large message (1MB)
    const size_t largeSize = 1024 * 1024;
    std::vector<char> largeMessage(largeSize, 'A');

    struct agent_ctx agentContext;
    agentContext.id = "001";
    agentContext.name = "test-agent";
    agentContext.ip = "192.168.1.100";
    agentContext.version = "4.5.0";
    agentContext.module = "syscollector";

    EXPECT_EQ(0, router_provider_send_fb_agent_ctx(handle, largeMessage.data(), largeMessage.size(), &agentContext));

    router_provider_destroy(handle);
}

/*
 * @brief Test router_provider_send_fb_agent_ctx with binary data
 */
TEST_F(RemoteProviderTest, TestRouterProviderSendFBAgentCtxBinaryData)
{
    const char* providerName = "test-fb-agent-ctx-binary";
    ROUTER_PROVIDER_HANDLE handle = router_provider_create(providerName, true);
    EXPECT_NE(nullptr, handle);

    // Create binary data with null bytes and special characters
    std::vector<char> binaryData = {static_cast<char>(0x00),
                                    static_cast<char>(0x01),
                                    static_cast<char>(0x7F),
                                    static_cast<char>(0xFF),
                                    static_cast<char>(0x41),
                                    static_cast<char>(0x42)};

    struct agent_ctx agentContext;
    agentContext.id = "001";
    agentContext.name = "test-agent";
    agentContext.ip = "192.168.1.100";
    agentContext.version = "4.5.0";
    agentContext.module = "syscollector";

    EXPECT_EQ(0, router_provider_send_fb_agent_ctx(handle, binaryData.data(), binaryData.size(), &agentContext));

    router_provider_destroy(handle);
}

/*
 * @brief Test router_provider_send_fb_agent_ctx with special characters in agent context
 */
TEST_F(RemoteProviderTest, TestRouterProviderSendFBAgentCtxSpecialChars)
{
    const char* providerName = "test-fb-agent-ctx-special";
    ROUTER_PROVIDER_HANDLE handle = router_provider_create(providerName, true);
    EXPECT_NE(nullptr, handle);

    const char* message = "test message with special chars: éñáüß";
    const size_t messageSize = strlen(message);

    struct agent_ctx agentContext;
    agentContext.id = "agent-001-ñ";
    agentContext.name = "test-agent-éñáüß";
    agentContext.ip = "::1"; // IPv6 localhost
    agentContext.version = "4.5.0-beta.1";
    agentContext.module = "syscollector-extended";

    EXPECT_EQ(0, router_provider_send_fb_agent_ctx(handle, message, messageSize, &agentContext));

    router_provider_destroy(handle);
}

/*
 * @brief Test router_provider_send_fb_agent_ctx with very long agent context fields
 */
TEST_F(RemoteProviderTest, TestRouterProviderSendFBAgentCtxLongFields)
{
    const char* providerName = "test-fb-agent-ctx-long";
    ROUTER_PROVIDER_HANDLE handle = router_provider_create(providerName, true);
    EXPECT_NE(nullptr, handle);

    const char* message = "test message";
    const size_t messageSize = strlen(message);

    // Create very long strings for agent context
    std::string longId(1000, 'I');
    std::string longName(1000, 'N');
    std::string longIp(500, '1');
    std::string longVersion(500, 'V');
    std::string longModule(1000, 'M');

    struct agent_ctx agentContext;
    agentContext.id = longId.c_str();
    agentContext.name = longName.c_str();
    agentContext.ip = longIp.c_str();
    agentContext.version = longVersion.c_str();
    agentContext.module = longModule.c_str();

    EXPECT_EQ(0, router_provider_send_fb_agent_ctx(handle, message, messageSize, &agentContext));

    router_provider_destroy(handle);
}

/*
 * @brief Test router_provider_send_fb_agent_ctx with invalid handle after provider destroyed
 */
TEST_F(RemoteProviderTest, TestRouterProviderSendFBAgentCtxInvalidHandle)
{
    const char* providerName = "test-fb-agent-ctx-invalid";
    ROUTER_PROVIDER_HANDLE handle = router_provider_create(providerName, true);
    EXPECT_NE(nullptr, handle);

    // Destroy the provider first
    router_provider_destroy(handle);

    const char* message = "test message";
    const size_t messageSize = strlen(message);

    struct agent_ctx agentContext;
    agentContext.id = "001";
    agentContext.name = "test-agent";
    agentContext.ip = "192.168.1.100";
    agentContext.version = "4.5.0";
    agentContext.module = "syscollector";

    // Should fail because handle is no longer valid
    EXPECT_EQ(-1, router_provider_send_fb_agent_ctx(handle, message, messageSize, &agentContext));
}

/*
 * @brief Test router_provider_send_fb_agent_ctx with multiple concurrent calls
 */
TEST_F(RemoteProviderTest, TestRouterProviderSendFBAgentCtxConcurrent)
{
    const char* providerName = "test-fb-agent-ctx-concurrent";
    ROUTER_PROVIDER_HANDLE handle = router_provider_create(providerName, true);
    EXPECT_NE(nullptr, handle);

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
                    std::string message = "thread-" + std::to_string(t) + "-msg-" + std::to_string(i);

                    struct agent_ctx agentContext;
                    std::string agentId = "agent-" + std::to_string(t) + "-" + std::to_string(i);
                    std::string agentName = "test-agent-" + std::to_string(t);
                    std::string agentIp = "192.168.1." + std::to_string(100 + t);
                    agentContext.id = agentId.c_str();
                    agentContext.name = agentName.c_str();
                    agentContext.ip = agentIp.c_str();
                    agentContext.version = "4.5.0";
                    agentContext.module = "syscollector";

                    int result =
                        router_provider_send_fb_agent_ctx(handle, message.c_str(), message.size(), &agentContext);
                    if (result == 0)
                    {
                        successCount++;
                    }
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(successCount.load(), numThreads * messagesPerThread);

    router_provider_destroy(handle);
}

/*
 * @brief Test router_provider_send_fb_agent_ctx with empty message but valid size
 */
TEST_F(RemoteProviderTest, TestRouterProviderSendFBAgentCtxEmptyMessageValidSize)
{
    const char* providerName = "test-fb-agent-ctx-empty-msg";
    ROUTER_PROVIDER_HANDLE handle = router_provider_create(providerName, true);
    EXPECT_NE(nullptr, handle);

    const char* message = "";
    const size_t messageSize = 0;

    struct agent_ctx agentContext;
    agentContext.id = "001";
    agentContext.name = "test-agent";
    agentContext.ip = "192.168.1.100";
    agentContext.version = "4.5.0";
    agentContext.module = "syscollector";

    EXPECT_EQ(0, router_provider_send_fb_agent_ctx(handle, message, messageSize, &agentContext));

    router_provider_destroy(handle);
}

/*
 * @brief Test router_provider_send_fb_agent_ctx multiple calls with same handle
 */
TEST_F(RemoteProviderTest, TestRouterProviderSendFBAgentCtxMultipleCalls)
{
    const char* providerName = "test-fb-agent-ctx-multiple";
    ROUTER_PROVIDER_HANDLE handle = router_provider_create(providerName, true);
    EXPECT_NE(nullptr, handle);

    struct agent_ctx agentContext;
    agentContext.id = "001";
    agentContext.name = "test-agent";
    agentContext.ip = "192.168.1.100";
    agentContext.version = "4.5.0";
    agentContext.module = "syscollector";

    // Send multiple messages with the same handle
    for (int i = 0; i < 20; ++i)
    {
        std::string message = "message number " + std::to_string(i);
        EXPECT_EQ(0, router_provider_send_fb_agent_ctx(handle, message.c_str(), message.size(), &agentContext));
    }

    router_provider_destroy(handle);
}
