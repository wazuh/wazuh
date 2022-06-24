/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 */

#include <iostream>
#include <sys/un.h>

#include <gtest/gtest.h>

#include <utils/socketInterface/unixDatagram.hpp>

#include "testAuxiliar/socketAuxiliarFunctions.hpp"

using namespace base::utils::socketInterface;

TEST(unixDatagramSocket, build)
{
    ASSERT_NO_THROW(unixDatagram uDgram());
    ASSERT_NO_THROW(unixDatagram uDgram(TEST_DGRAM_SOCK_PATH));
    ASSERT_NO_THROW(unixDatagram uDgram("qwertyuiop"));
}

TEST(unixDatagramSocket, SetMaxMsgSizeError)
{
    ASSERT_THROW({ unixDatagram uDgram(TEST_DGRAM_SOCK_PATH, 0); },
                 std::invalid_argument);

    ASSERT_THROW({ unixDatagram uDgram(TEST_DGRAM_SOCK_PATH, {}); },
                 std::invalid_argument);
}

TEST(unixDatagramSocket, GetMaxMsgSize)
{
    {
        unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);
        ASSERT_NO_THROW(ASSERT_EQ(uDgram.getMaxMsgSize(), DATAGRAM_MAX_MSG_SIZE));
    };

    {
        int setSize {99};
        unixDatagram uDgram(TEST_DGRAM_SOCK_PATH, setSize);
        ASSERT_NO_THROW(ASSERT_EQ(uDgram.getMaxMsgSize(), setSize));
    };

    {
        unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);
        ASSERT_NO_THROW(ASSERT_EQ(uDgram.getMaxMsgSize(), DATAGRAM_MAX_MSG_SIZE));
    };

    {
        int setSize {DATAGRAM_MAX_MSG_SIZE + 1};
        unixDatagram uDgram(TEST_DGRAM_SOCK_PATH, setSize);
        ASSERT_NO_THROW(ASSERT_EQ(uDgram.getMaxMsgSize(), setSize));
    };
}

TEST(unixDatagramSocket, GetPath)
{
    unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);
    ASSERT_NO_THROW(ASSERT_EQ(uDgram.getPath(), TEST_DGRAM_SOCK_PATH););
}

TEST(unixDatagramSocket, ConnectErrorInvalidPath)
{
    {
        unixDatagram uDgram("/invalid/path");
        ASSERT_THROW(uDgram.socketConnect(), std::runtime_error);
    }
    {
        unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);
        ASSERT_THROW(uDgram.socketConnect(), std::runtime_error);
    }
}

TEST(unixDatagramSocket, Connect)
{
    unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);

    auto serverSocketFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uDgram.socketConnect());

    close(serverSocketFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}

TEST(unixDatagramSocket, ConnectTwice)
{
    unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);

    auto serverSocketFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uDgram.socketConnect());
    ASSERT_NO_THROW(uDgram.socketConnect());

    close(serverSocketFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}

TEST(unixDatagramSocket, Disconnect)
{
    unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);
    ASSERT_NO_THROW(uDgram.socketDisconnect());
}

TEST(unixDatagramSocket, ConnectAndDisconnect)
{
    unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);

    auto serverSocketFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uDgram.socketConnect());
    ASSERT_NO_THROW(uDgram.socketDisconnect());

    close(serverSocketFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}

TEST(unixDatagramSocket, ConnectDisconnectConnect)
{
    unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);

    auto serverSocketFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uDgram.socketConnect());
    ASSERT_NO_THROW(uDgram.socketDisconnect());
    ASSERT_NO_THROW(uDgram.socketConnect());

    close(serverSocketFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}

TEST(unixDatagramSocket, isConnectedFalse)
{

    unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);

    ASSERT_FALSE(uDgram.isConnected());

    auto serverSocketFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uDgram.socketConnect());
    ASSERT_NO_THROW(uDgram.socketDisconnect());

    ASSERT_FALSE(uDgram.isConnected());

    close(serverSocketFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}

TEST(unixDatagramSocket, isConnectedTrue)
{
    unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);

    auto serverSocketFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uDgram.socketConnect());

    ASSERT_TRUE(uDgram.isConnected());

    ASSERT_NO_THROW(uDgram.socketDisconnect());
    ASSERT_NO_THROW(uDgram.socketConnect());

    ASSERT_TRUE(uDgram.isConnected());

    close(serverSocketFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}

TEST(unixDatagramSocket, ErrorSendMessageNoSocket)
{
    unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);
    ASSERT_THROW(uDgram.sendMsg(TEST_SEND_MESSAGE.data()), std::runtime_error);
}

TEST(unixDatagramSocket, ErrorSendEmptyMessage)
{
    const char msg[] = "";

    unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);

    auto serverSocketFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(ASSERT_EQ(uDgram.sendMsg(msg), SendRetval::SIZE_ZERO));

    close(serverSocketFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}

TEST(unixDatagramSocket, ErrorSendLongMessage)
{
    std::vector<char> msg = {};
    msg.resize(DATAGRAM_MAX_MSG_SIZE + 2);
    std::fill(msg.begin(), msg.end() - 1, 'x');
    msg.back() = '\0';

    unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);

    auto serverSocketFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(ASSERT_EQ(uDgram.sendMsg(msg.data()), SendRetval::SIZE_TOO_LONG));

    close(serverSocketFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}

TEST(unixDatagramSocket, SendMessage)
{
    unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);

    auto serverSocketFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uDgram.socketConnect());

    ASSERT_NO_THROW(uDgram.sendMsg(TEST_SEND_MESSAGE.data()));

    ASSERT_EQ(testRecvString(serverSocketFD, SOCK_DGRAM), TEST_SEND_MESSAGE);

    close(serverSocketFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}

TEST(unixDatagramSocket, SendMessageDisconnected)
{
    unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);

    auto serverSocketFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uDgram.sendMsg(TEST_SEND_MESSAGE.data()));

    ASSERT_EQ(testRecvString(serverSocketFD, SOCK_DGRAM), TEST_SEND_MESSAGE);

    close(serverSocketFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}
