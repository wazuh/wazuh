/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 */

#include <iostream>
#include <sys/un.h>

#include <gtest/gtest.h>

#include <utils/socketInterface/unixDatagram.hpp>
#include <logging/logging.hpp>

#include "testAuxiliar/socketAuxiliarFunctions.hpp"

using namespace base::utils::socketInterface;

class unixDatagramSocket : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Logging setup
        logging::LoggingConfig logConfig;
        logConfig.logLevel = spdlog::level::off;
        logConfig.filePath = logging::DEFAULT_TESTS_LOG_PATH;
        logging::loggingInit(logConfig);
    }

    void TearDown() override {}
};

TEST_F(unixDatagramSocket, build)
{
    ASSERT_NO_THROW(unixDatagram uDgram());
    ASSERT_NO_THROW(unixDatagram uDgram(TEST_DGRAM_SOCK_PATH));
    ASSERT_NO_THROW(unixDatagram uDgram("qwertyuiop"));
}

TEST_F(unixDatagramSocket, SetMaxMsgSizeError)
{
    ASSERT_THROW({ unixDatagram uDgram(TEST_DGRAM_SOCK_PATH, 0); },
                 std::invalid_argument);

    ASSERT_THROW({ unixDatagram uDgram(TEST_DGRAM_SOCK_PATH, {}); },
                 std::invalid_argument);
}

TEST_F(unixDatagramSocket, GetMaxMsgSize)
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

TEST_F(unixDatagramSocket, GetPath)
{
    unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);
    ASSERT_NO_THROW(ASSERT_EQ(uDgram.getPath(), TEST_DGRAM_SOCK_PATH););
}

TEST_F(unixDatagramSocket, ConnectErrorInvalidPath)
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

TEST_F(unixDatagramSocket, Connect)
{
    unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);

    auto serverSocketFD {testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uDgram.socketConnect());

    close(serverSocketFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}

TEST_F(unixDatagramSocket, ConnectTwice)
{
    unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);

    auto serverSocketFD {testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uDgram.socketConnect());
    ASSERT_NO_THROW(uDgram.socketConnect());

    close(serverSocketFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}

TEST_F(unixDatagramSocket, Disconnect)
{
    unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);
    ASSERT_NO_THROW(uDgram.socketDisconnect());
}

TEST_F(unixDatagramSocket, ConnectAndDisconnect)
{
    unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);

    auto serverSocketFD {testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uDgram.socketConnect());
    ASSERT_NO_THROW(uDgram.socketDisconnect());

    close(serverSocketFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}

TEST_F(unixDatagramSocket, ConnectDisconnectConnect)
{
    unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);

    auto serverSocketFD {testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uDgram.socketConnect());
    ASSERT_NO_THROW(uDgram.socketDisconnect());
    ASSERT_NO_THROW(uDgram.socketConnect());

    close(serverSocketFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}

TEST_F(unixDatagramSocket, isConnectedFalse)
{

    unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);

    ASSERT_FALSE(uDgram.isConnected());

    auto serverSocketFD {testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uDgram.socketConnect());
    ASSERT_NO_THROW(uDgram.socketDisconnect());

    ASSERT_FALSE(uDgram.isConnected());

    close(serverSocketFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}

TEST_F(unixDatagramSocket, isConnectedTrue)
{
    unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);

    auto serverSocketFD {testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uDgram.socketConnect());

    ASSERT_TRUE(uDgram.isConnected());

    ASSERT_NO_THROW(uDgram.socketDisconnect());
    ASSERT_NO_THROW(uDgram.socketConnect());

    ASSERT_TRUE(uDgram.isConnected());

    close(serverSocketFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}

TEST_F(unixDatagramSocket, ErrorSendMessageNoSocket)
{
    unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);
    ASSERT_THROW(uDgram.sendMsg(TEST_SEND_MESSAGE.data()), std::runtime_error);
}

TEST_F(unixDatagramSocket, ErrorSendEmptyMessage)
{
    const char msg[] = "";

    unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);

    auto serverSocketFD {testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(ASSERT_EQ(uDgram.sendMsg(msg), SendRetval::SIZE_ZERO));

    close(serverSocketFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}

TEST_F(unixDatagramSocket, ErrorSendLongMessage)
{
    std::vector<char> msg {{}};
    msg.resize(DATAGRAM_MAX_MSG_SIZE + 2);
    std::fill(msg.begin(), msg.end() - 1, 'x');
    msg.back() = '\0';

    unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);

    auto serverSocketFD {testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(ASSERT_EQ(uDgram.sendMsg(msg.data()), SendRetval::SIZE_TOO_LONG));

    close(serverSocketFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}

TEST_F(unixDatagramSocket, SendMessage)
{
    unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);

    auto serverSocketFD {testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uDgram.socketConnect());

    ASSERT_NO_THROW(uDgram.sendMsg(TEST_SEND_MESSAGE.data()));

    ASSERT_STREQ(testRecvString(serverSocketFD, SOCK_DGRAM).data(), TEST_SEND_MESSAGE.data());

    close(serverSocketFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}

TEST_F(unixDatagramSocket, SendMessageDisconnected)
{
    unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);

    auto serverSocketFD {testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uDgram.sendMsg(TEST_SEND_MESSAGE.data()));

    ASSERT_STREQ(testRecvString(serverSocketFD, SOCK_DGRAM).data(), TEST_SEND_MESSAGE.data());

    close(serverSocketFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}
