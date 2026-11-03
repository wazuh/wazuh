/*
 * Wazuh shared modules utils
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _SOCKET_DB_WRAPPER_TEST_HPP
#define _SOCKET_DB_WRAPPER_TEST_HPP

#include "socketDBWrapper.hpp"
#include "socketServer.hpp"
#include "gtest/gtest.h"
#include <chrono>
#include <thread>

auto constexpr TEST_SOCKET {"queue/sockets/wdb.sock"};

class SocketDBWrapperTest : public ::testing::Test
{
protected:
    SocketDBWrapperTest()
        : m_sleepTime {0}
    {
        SocketDBWrapper::instance().init();
    };
    ~SocketDBWrapperTest() override = default;

    void SetUp() override
    {
        m_socketServer =
            std::make_shared<SocketServer<Socket<OSPrimitives, SizeHeaderProtocol>, EpollWrapper>>(TEST_SOCKET);

        m_socketServer->listen(
            [&](const int fd, const char* data, uint32_t size, const char* dataHeader, uint32_t sizeHeader)
            {
                std::ignore = dataHeader;
                std::ignore = sizeHeader;

                std::string receivedMsg(data, size);
                ASSERT_EQ(receivedMsg, m_query);

                std::this_thread::sleep_for(std::chrono::milliseconds(m_sleepTime));

                for (const auto& response : m_responses)
                {
                    m_socketServer->send(fd, response.c_str(), response.size());
                }
            });
    };
    void TearDown() override
    {
        SocketDBWrapper::instance().teardown();
        m_socketServer->stop();
        m_socketServer.reset();
        m_query.clear();
        m_responses.clear();
        m_sleepTime = 0;
    };

    std::shared_ptr<SocketServer<Socket<OSPrimitives, SizeHeaderProtocol>, EpollWrapper>> m_socketServer;
    std::string m_query;
    std::vector<std::string> m_responses;
    int m_sleepTime;
};

class SocketDBWrapperTestNoSetUp : public ::testing::Test
{
protected:
    SocketDBWrapperTestNoSetUp() = default;
    ~SocketDBWrapperTestNoSetUp() override = default;

    void SetUp() override {};
    void TearDown() override {};
};

#endif // _SOCKET_DB_WRAPPER_TEST_HPP
