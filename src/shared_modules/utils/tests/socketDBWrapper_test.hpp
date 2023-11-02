/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * Oct 30, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SOCKET_DB_WRAPPER_TEST_HPP
#define _SOCKET_DB_WRAPPER_TEST_HPP

#include "socketServer.hpp"
#include "gtest/gtest.h"
#include <thread>
#include <chrono>

auto constexpr TEST_SOCKET {"/temp/temp_sock"};

class SocketDBWrapperTest : public ::testing::Test
{
protected:
    SocketDBWrapperTest(): m_sleepTime {0} {};
    virtual ~SocketDBWrapperTest() = default;

    void SetUp() override
    {
        m_socketServer =
            std::make_shared<SocketServer<Socket<OSPrimitives, sizeHeaderProtocol>, EpollWrapper>>(TEST_SOCKET);

        m_socketServer->listen(
            [&](const int fd, const char* data, uint32_t size, const char* dataHeader, uint32_t sizeHeader)
            {
                std::ignore = dataHeader;
                std::ignore = sizeHeader;

                std::string receivedMsg(data, size);
                ASSERT_EQ(receivedMsg, m_query);

                std::this_thread::sleep_for(std::chrono::milliseconds(m_sleepTime));

                m_socketServer->send(fd, m_response.c_str(), m_response.size());
            });
    };
    void TearDown() override
    {
        m_socketServer->stop();
        m_socketServer.reset();
        m_query.clear();
        m_response.clear();
        m_sleepTime = 0;
    };

    std::shared_ptr<SocketServer<Socket<OSPrimitives, sizeHeaderProtocol>, EpollWrapper>> m_socketServer;
    std::string m_query;
    std::string m_response;
    int m_sleepTime;
};

#endif // _SOCKET_DB_WRAPPER_TEST_HPP
