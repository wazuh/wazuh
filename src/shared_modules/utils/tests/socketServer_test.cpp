/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * May 1, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "socketServer_test.hpp"
#include <future>
#define private public
#define protected public
#include "socketServer.hpp"
#undef private
#undef protected
#include <gmock/gmock.h>

void SocketServerTest::SetUp() {
    // Not used
};
void SocketServerTest::TearDown() {
    // Not used
};

class MockSocket
{
public:
    MOCK_METHOD(void, listen, (const SocketAddress&), ());
    MOCK_METHOD(int, accept, (), ());
    MOCK_METHOD(void, closeSocket, (), ());
    MOCK_METHOD(void, send, (const char*, size_t, const char*, size_t), ());
    MOCK_METHOD(void, read, (const std::function<void(const int, const char*, uint32_t, const char*, uint32_t)>&), ());
    MOCK_METHOD(void, sendUnsentMessages, (), ());
    int fileDescriptor() const
    {
        return 0;
    }
    // Mock constructor
    MockSocket() = default;
    explicit MockSocket([[maybe_unused]] int fd) {}
};

// Mock class for TEpoll
class MockEpollWrapper
{
public:
    void addDescriptor(int, uint32_t) const
    {
        // Empty
    }
    MOCK_METHOD(void, deleteDescriptor, (int), ());
    MOCK_METHOD(void, modifyDescriptor, (int, uint32_t), ());
    MOCK_METHOD(int, wait, (struct epoll_event*, int, int), ());
};

TEST_F(SocketServerTest, SocketServerMultipleEventsWithHup)
{
    std::promise<void> promise;
    SocketServer<MockSocket, MockEpollWrapper> server("test");
    EXPECT_CALL(*server.m_epoll, wait(testing::_, testing::_, testing::_))
        .WillOnce(
            [&promise](struct epoll_event* events, int, int)
            {
                // Set the promise to indicate that the wait has been called, to avoid explicit wait in the test.
                promise.set_value();

                events[0].events = EPOLLIN | EPOLLOUT;
                events[0].data.fd = 0;
                events[1].events = EPOLLHUP;
                events[1].data.fd = 42;
                events[2].events = EPOLLHUP;
                events[2].data.fd = 42;
                return 3;
            })
        .WillRepeatedly([]([[maybe_unused]] const struct epoll_event* events, int, int) { return 0; });

    EXPECT_CALL(*server.m_listenSocket, accept()).WillOnce(testing::Return(42));
    EXPECT_CALL(*server.m_epoll, deleteDescriptor(testing::_)).Times(1);
    EXPECT_CALL(*server.m_listenSocket, listen(testing::_)).Times(1);
    EXPECT_CALL(*server.m_listenSocket, closeSocket()).Times(1);

    server.listen(
        [](const int, const char*, uint32_t, const char*, uint32_t)
        {
            // Not used
        });
    promise.get_future().wait_for(std::chrono::seconds(1));
}

TEST_F(SocketServerTest, SocketServerMultipleEventsWithErr)
{
    std::promise<void> promise;
    SocketServer<MockSocket, MockEpollWrapper> server("test");
    EXPECT_CALL(*server.m_epoll, wait(testing::_, testing::_, testing::_))
        .WillOnce(
            [&promise](struct epoll_event* events, int, int)
            {
                // Set the promise to indicate that the wait has been called, to avoid explicit wait in the test.
                promise.set_value();

                events[0].events = EPOLLIN | EPOLLOUT;
                events[0].data.fd = 0;
                events[1].events = EPOLLERR;
                events[1].data.fd = 42;
                events[2].events = EPOLLERR;
                events[2].data.fd = 42;
                return 3;
            })
        .WillRepeatedly([]([[maybe_unused]] const struct epoll_event* events, int, int) { return 0; });

    EXPECT_CALL(*server.m_listenSocket, accept()).WillOnce(testing::Return(42));
    EXPECT_CALL(*server.m_epoll, deleteDescriptor(testing::_)).Times(1);
    EXPECT_CALL(*server.m_listenSocket, listen(testing::_)).Times(1);
    EXPECT_CALL(*server.m_listenSocket, closeSocket()).Times(1);

    server.listen(
        [](const int, const char*, uint32_t, const char*, uint32_t)
        {
            // Not used.
        });
    promise.get_future().wait_for(std::chrono::seconds(1));
}

TEST_F(SocketServerTest, SocketServerSendAgentNotExist)
{
    SocketServer<MockSocket, MockEpollWrapper> server("test");
    EXPECT_THROW(server.send(1, "test", 4, "test", 4), std::out_of_range);
    EXPECT_CALL(*server.m_epoll, deleteDescriptor(testing::_)).Times(1);
    EXPECT_CALL(*server.m_listenSocket, closeSocket()).Times(1);
}

TEST_F(SocketServerTest, SocketServerSend)
{
    SocketServer<MockSocket, MockEpollWrapper> server("test");
    server.m_clients[1] = std::make_unique<MockSocket>();
    EXPECT_CALL(*server.m_clients[1], send(testing::_, testing::_, testing::_, testing::_)).Times(1);
    server.send(1, "test", 4, "test", 4);
    EXPECT_CALL(*server.m_epoll, deleteDescriptor(testing::_)).Times(1);
    EXPECT_CALL(*server.m_listenSocket, closeSocket()).Times(1);
}

TEST_F(SocketServerTest, SendThrowException)
{
    SocketServer<MockSocket, MockEpollWrapper> server("test");
    server.m_clients[1] = std::make_unique<MockSocket>();
    EXPECT_CALL(*server.m_clients[1], send(testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Throw(std::runtime_error("Error sending message")));
    EXPECT_CALL(*server.m_epoll, modifyDescriptor(testing::_, testing::_)).Times(1);
    EXPECT_NO_THROW(server.send(1, "test", 4, "test", 4));
    EXPECT_CALL(*server.m_epoll, deleteDescriptor(testing::_)).Times(1);
    EXPECT_CALL(*server.m_listenSocket, closeSocket()).Times(1);
}

TEST_F(SocketServerTest, ProcessEvent)
{
    // Create a SocketServer object
    SocketServer<MockSocket, MockEpollWrapper> server("test");

    // Create a mock client socket
    int clientFD = 123;
    auto clientSocket = std::make_shared<MockSocket>(clientFD);

    // Add the client socket to the server
    server.addClient(clientFD, clientSocket);

    // Create a mock onRead function
    auto onRead = [](const int, const char*, uint32_t, const char*, uint32_t)
    {
        // Not used
    };

    // Expect the sendUnsentMessages function to be called once
    EXPECT_CALL(*clientSocket, sendUnsentMessages()).Times(1);

    // Expect the read function to be called once
    EXPECT_CALL(*clientSocket, read(testing::_)).Times(1);

    // After sending the unsent messages, the client socket should be modified to listen for incoming messages
    EXPECT_CALL(*server.m_epoll, modifyDescriptor(testing::_, testing::_)).Times(1);

    // Call the processEvent function with EPOLLOUT event
    EXPECT_NO_THROW(server.processEvent(EPOLLOUT | EPOLLIN, clientFD, onRead));

    // Call the processEvent function with EPOLLERR event
    EXPECT_NO_THROW(server.processEvent(EPOLLERR, clientFD, onRead));

    // Assert that the client socket is removed from the server
    EXPECT_FALSE(server.getClient(clientFD));

    // Call the processEvent function with EPOLLHUP event
    EXPECT_NO_THROW(server.processEvent(EPOLLHUP, clientFD, onRead));

    // Assert that the client socket is removed from the server
    EXPECT_FALSE(server.getClient(clientFD));

    EXPECT_CALL(*server.m_epoll, deleteDescriptor(testing::_)).Times(1);
    EXPECT_CALL(*server.m_listenSocket, closeSocket()).Times(1);
}

TEST_F(SocketServerTest, AddClient)
{
    SocketServer<MockSocket, MockEpollWrapper> server("test_socket");

    // Create a mock client socket
    auto client = std::make_shared<MockSocket>();

    // Add the client to the server
    server.addClient(1, client);

    // Verify that the client was added successfully
    EXPECT_EQ(server.getClient(1), client);

    EXPECT_CALL(*server.m_epoll, deleteDescriptor(testing::_)).Times(1);
    EXPECT_CALL(*server.m_listenSocket, closeSocket()).Times(1);
}

TEST_F(SocketServerTest, RemoveClient)
{
    SocketServer<MockSocket, MockEpollWrapper> server("test_socket");

    // Create a mock client socket
    auto client = std::make_shared<MockSocket>();

    // Add the client to the server
    server.addClient(1, client);

    // Verify that the client was added successfully
    EXPECT_EQ(server.getClient(1), client);

    // Remove the client from the server
    server.removeClient(1);

    // Verify that the client was removed successfully
    EXPECT_FALSE(server.getClient(1));

    EXPECT_CALL(*server.m_epoll, deleteDescriptor(testing::_)).Times(1);
    EXPECT_CALL(*server.m_listenSocket, closeSocket()).Times(1);
}
