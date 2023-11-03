/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * May 24, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "socket_test.hpp"
#include "../socketClient.hpp"
#include "../socketServer.hpp"
#include <chrono>
#include <future>

TYPED_TEST_SUITE_P(SocketTest);

TYPED_TEST_P(SocketTest, SingleDelayedServerStart)
{
    constexpr size_t MESSAGE_QUANTITY {1000000};
    std::string socketPath {"/tmp/echo_sock"};
    std::promise<void> promise;
    std::atomic<size_t> counter {0};

    auto thread = std::thread(
        [&]()
        {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            SocketServer<Socket<OSPrimitives, TypeParam>, EpollWrapper> server {socketPath};
            server.listen(
                [&](const int fd, const char* data, uint32_t size, const char* dataHeader, uint32_t sizeHeader)
                {
                    std::ignore = fd;
                    std::ignore = dataHeader;
                    std::ignore = sizeHeader;

                    std::string message(data, size);
                    EXPECT_EQ(message, std::to_string(counter));
                    counter++;

                    if (counter == MESSAGE_QUANTITY)
                    {
                        promise.set_value();
                    }
                });

            promise.get_future().wait_for(std::chrono::seconds(10));
        });

    SocketClient<Socket<OSPrimitives, TypeParam>, EpollWrapper> client {socketPath};
    client.connect(
        [](const char* data, uint32_t size, const char* dataHeader, uint32_t sizeHeader)
        {
            std::ignore = dataHeader;
            std::ignore = sizeHeader;
            std::ignore = size;
            std::ignore = data;
        });

    for (size_t i {0}; i < MESSAGE_QUANTITY; ++i)
    {
        auto message {std::to_string(i)};
        client.send(message.c_str(), message.size());
    }
    thread.join();
    EXPECT_EQ(counter, MESSAGE_QUANTITY);
}

TYPED_TEST_P(SocketTest, SingleDelayedClient)
{
    constexpr size_t MESSAGE_QUANTITY {1000000};
    std::string socketPath {"/tmp/echo_sock"};
    std::promise<void> promise;

    SocketServer<Socket<OSPrimitives, TypeParam>, EpollWrapper> server {socketPath};
    std::atomic<size_t> counter {0};
    server.listen(
        [&](const int fd, const char* data, uint32_t size, const char* dataHeader, uint32_t sizeHeader)
        {
            std::ignore = fd;
            std::ignore = dataHeader;
            std::ignore = sizeHeader;
            std::string message(data, size);
            EXPECT_EQ(message, std::to_string(counter));
            counter++;

            if (counter == MESSAGE_QUANTITY)
            {
                promise.set_value();
            }
        });

    SocketClient<Socket<OSPrimitives, TypeParam>, EpollWrapper> client {socketPath};
    client.connect(
        [](const char* data, uint32_t size, const char* dataHeader, uint32_t sizeHeader)
        {
            std::ignore = dataHeader;
            std::ignore = sizeHeader;
            std::ignore = size;
            std::ignore = data;
        });

    for (size_t i {0}; i < MESSAGE_QUANTITY; ++i)
    {
        auto message {std::to_string(i)};
        client.send(message.c_str(), message.size());
    }

    promise.get_future().wait_for(std::chrono::seconds(10));

    EXPECT_EQ(counter, MESSAGE_QUANTITY);
}

TYPED_TEST_P(SocketTest, MultipleClients)
{
    constexpr size_t MESSAGE_QUANTITY {10000};
    std::string socketPath {"/tmp/echo_sock"};
    std::promise<void> promise;
    constexpr size_t CLIENTS {10};

    SocketServer<Socket<OSPrimitives, TypeParam>, EpollWrapper> server {socketPath};
    std::atomic<size_t> counter {0};
    server.listen(
        [&](const int fd, const char* data, uint32_t size, const char* dataHeader, uint32_t sizeHeader)
        {
            std::ignore = fd;
            std::ignore = dataHeader;
            std::ignore = sizeHeader;
            std::string message(data, size);
            counter++;

            if (counter == MESSAGE_QUANTITY)
            {
                promise.set_value();
            }
        });

    std::vector<std::thread> threads;
    for (size_t i {0}; i < CLIENTS; ++i)
    {
        threads.emplace_back(
            [&]()
            {
                SocketClient<Socket<OSPrimitives, TypeParam>, EpollWrapper> client {socketPath};
                client.connect(
                    [](const char* data, uint32_t size, const char* dataHeader, uint32_t sizeHeader)
                    {
                        std::ignore = dataHeader;
                        std::ignore = sizeHeader;
                        std::ignore = size;
                        std::ignore = data;
                    });

                for (size_t i {0}; i < MESSAGE_QUANTITY / CLIENTS; ++i)
                {
                    auto message {std::to_string(i)};
                    client.send(message.c_str(), message.size());
                }

                std::this_thread::sleep_for(std::chrono::seconds(5));
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    promise.get_future().wait();

    EXPECT_EQ(counter, MESSAGE_QUANTITY);
}

TYPED_TEST_P(SocketTest, SingleDelayedClientWithReconnectionSendMessageOffline)
{
    constexpr size_t MESSAGE_QUANTITY {100};
    std::string socketPath {"/tmp/echo_sock"};
    std::promise<void> promise;

    SocketServer<Socket<OSPrimitives, TypeParam>, EpollWrapper> server {socketPath};
    std::atomic<size_t> counter {0};
    server.listen(
        [&](const int fd, const char* data, uint32_t size, const char* dataHeader, uint32_t sizeHeader)
        {
            std::ignore = fd;
            std::ignore = dataHeader;
            std::ignore = sizeHeader;
            std::string message(data, size);
            EXPECT_EQ(message, std::to_string(counter));
            counter++;

            if (counter == MESSAGE_QUANTITY)
            {
                promise.set_value();
            }
        });

    SocketClient<Socket<OSPrimitives, TypeParam>, EpollWrapper> client {socketPath};
    client.connect(
        [](const char* data, uint32_t size, const char* dataHeader, uint32_t sizeHeader)
        {
            std::ignore = dataHeader;
            std::ignore = sizeHeader;
            std::ignore = size;
            std::ignore = data;
        });

    for (size_t i {0}; i < MESSAGE_QUANTITY; ++i)
    {
        auto message {std::to_string(i)};
        client.send(message.c_str(), message.size());
    }

    promise.get_future().wait_for(std::chrono::seconds(10));

    EXPECT_EQ(counter, MESSAGE_QUANTITY);
    server.stop();

    for (size_t i {0}; i < MESSAGE_QUANTITY; ++i)
    {
        auto message {std::to_string(i)};
        client.send(message.c_str(), message.size());
    }

    std::promise<void> promise2;
    counter = 0;
    server.listen(
        [&](const int fd, const char* data, uint32_t size, const char* dataHeader, uint32_t sizeHeader)
        {
            std::ignore = fd;
            std::ignore = dataHeader;
            std::ignore = sizeHeader;
            std::string message(data, size);
            EXPECT_EQ(message, std::to_string(counter));
            counter++;
            if (counter == MESSAGE_QUANTITY)
            {
                promise2.set_value();
            }
        });

    promise2.get_future().wait_for(std::chrono::seconds(10));

    EXPECT_EQ(counter, MESSAGE_QUANTITY);
}

TYPED_TEST_P(SocketTest, SingleDelayedClientWithReconnectionOnline)
{
    constexpr size_t MESSAGE_QUANTITY {100};
    std::string socketPath {"/tmp/echo_sock"};
    std::promise<void> promise;

    SocketServer<Socket<OSPrimitives, TypeParam>, EpollWrapper> server {socketPath};
    std::atomic<size_t> counter {0};
    server.listen(
        [&](const int fd, const char* data, uint32_t size, const char* dataHeader, uint32_t sizeHeader)
        {
            std::ignore = fd;
            std::ignore = dataHeader;
            std::ignore = sizeHeader;
            std::string message(data, size);
            EXPECT_EQ(message, std::to_string(counter));
            counter++;

            if (counter == MESSAGE_QUANTITY)
            {
                promise.set_value();
            }
        });

    SocketClient<Socket<OSPrimitives, TypeParam>, EpollWrapper> client {socketPath};
    client.connect(
        [](const char* data, uint32_t size, const char* dataHeader, uint32_t sizeHeader)
        {
            std::ignore = dataHeader;
            std::ignore = sizeHeader;
            std::ignore = size;
            std::ignore = data;
        });

    for (size_t i {0}; i < MESSAGE_QUANTITY; ++i)
    {
        auto message {std::to_string(i)};
        client.send(message.c_str(), message.size());
    }

    promise.get_future().wait_for(std::chrono::seconds(10));

    EXPECT_EQ(counter, MESSAGE_QUANTITY);
    server.stop();

    std::promise<void> promise2;
    counter = 0;
    server.listen(
        [&](const int fd, const char* data, uint32_t size, const char* dataHeader, uint32_t sizeHeader)
        {
            std::ignore = fd;
            std::ignore = dataHeader;
            std::ignore = sizeHeader;
            std::string message(data, size);
            EXPECT_EQ(message, std::to_string(counter));
            counter++;
            if (counter == MESSAGE_QUANTITY)
            {
                promise2.set_value();
            }
        });

    for (size_t i {0}; i < MESSAGE_QUANTITY; ++i)
    {
        auto message {std::to_string(i)};
        client.send(message.c_str(), message.size());
    }

    promise2.get_future().wait_for(std::chrono::seconds(10));

    EXPECT_EQ(counter, MESSAGE_QUANTITY);
}

TYPED_TEST_P(SocketTest, SingleDelayedClientWithReconnectionServerReset)
{
    constexpr size_t MESSAGE_QUANTITY {100};
    std::string socketPath {"/tmp/echo_sock"};
    std::promise<void> promise;

    auto server = std::make_unique<SocketServer<Socket<OSPrimitives, TypeParam>, EpollWrapper>>(socketPath);
    std::atomic<size_t> counter {0};
    server->listen(
        [&](const int fd, const char* data, uint32_t size, const char* dataHeader, uint32_t sizeHeader)
        {
            std::ignore = fd;
            std::ignore = dataHeader;
            std::ignore = sizeHeader;
            std::string message(data, size);
            EXPECT_EQ(message, std::to_string(counter));
            counter++;

            if (counter == MESSAGE_QUANTITY)
            {
                promise.set_value();
            }
        });

    SocketClient<Socket<OSPrimitives, TypeParam>, EpollWrapper> client {socketPath};
    client.connect(
        [](const char* data, uint32_t size, const char* dataHeader, uint32_t sizeHeader)
        {
            std::ignore = dataHeader;
            std::ignore = sizeHeader;
            std::ignore = size;
            std::ignore = data;
        });

    for (size_t i {0}; i < MESSAGE_QUANTITY; ++i)
    {
        auto message {std::to_string(i)};
        client.send(message.c_str(), message.size());
    }

    promise.get_future().wait_for(std::chrono::seconds(10));

    EXPECT_EQ(counter, MESSAGE_QUANTITY);
    server.reset();

    for (size_t i {0}; i < MESSAGE_QUANTITY; ++i)
    {
        auto message {std::to_string(i)};
        client.send(message.c_str(), message.size());
    }

    std::promise<void> promise2;
    counter = 0;
    server = std::make_unique<SocketServer<Socket<OSPrimitives, TypeParam>, EpollWrapper>>(socketPath);

    server->listen(
        [&](const int fd, const char* data, uint32_t size, const char* dataHeader, uint32_t sizeHeader)
        {
            std::ignore = fd;
            std::ignore = dataHeader;
            std::ignore = sizeHeader;
            std::string message(data, size);
            EXPECT_EQ(message, std::to_string(counter));
            counter++;
            if (counter == MESSAGE_QUANTITY)
            {
                promise2.set_value();
            }
        });

    promise2.get_future().wait_for(std::chrono::seconds(10));

    EXPECT_EQ(counter, MESSAGE_QUANTITY);
}

// All tests must be registered

REGISTER_TYPED_TEST_SUITE_P(SocketTest,
                            SingleDelayedServerStart,
                            SingleDelayedClient,
                            MultipleClients,
                            SingleDelayedClientWithReconnectionSendMessageOffline,
                            SingleDelayedClientWithReconnectionOnline,
                            SingleDelayedClientWithReconnectionServerReset);

// Configuring typed-tests
using ProtocolTypes = ::testing::Types<AppendHeaderProtocol, SizeHeaderProtocol>;
INSTANTIATE_TYPED_TEST_SUITE_P(TypedSocketTests, SocketTest, ProtocolTypes);
