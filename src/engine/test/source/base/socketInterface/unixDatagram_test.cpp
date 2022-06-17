#include <gtest/gtest.h>
#include <iostream>
#include <sys/un.h>

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
    ASSERT_NO_THROW({
        unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);
        ASSERT_EQ(uDgram.getMaxMsgSize(), DATAGRAM_MAX_MSG_SIZE);
    });

    ASSERT_NO_THROW({
        int setSize {99};
        unixDatagram uDgram(TEST_DGRAM_SOCK_PATH, setSize);
        ASSERT_EQ(uDgram.getMaxMsgSize(), setSize);
    });

    ASSERT_NO_THROW({
        unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);
        ASSERT_EQ(uDgram.getMaxMsgSize(), DATAGRAM_MAX_MSG_SIZE);
    });

    ASSERT_NO_THROW({
        int setSize {DATAGRAM_MAX_MSG_SIZE + 1};
        unixDatagram uDgram(TEST_DGRAM_SOCK_PATH, setSize);
        ASSERT_EQ(uDgram.getMaxMsgSize(), setSize);
    });
}

TEST(unixDatagramSocket, GetPath)
{
    ASSERT_NO_THROW({
        unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);
        ASSERT_EQ(uDgram.getPath(), TEST_DGRAM_SOCK_PATH);
    });
}

TEST(unixDatagramSocket, ConnectErrorInvalidPath)
{
    ASSERT_THROW(
        {
            unixDatagram uDgram("/invalid/path");
            uDgram.socketConnect();
        },
        std::runtime_error);

    ASSERT_THROW(
        {
            unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);
            uDgram.socketConnect();
        },
        std::runtime_error);
}

TEST(unixDatagramSocket, Connect)
{
    ASSERT_NO_THROW({
        unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);
        auto serverSockFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
        uDgram.socketConnect();
        close(serverSockFD);
    });
}

TEST(unixDatagramSocket, ConnectTwice)
{
    ASSERT_NO_THROW({
        unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);
        auto serverSockFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
        uDgram.socketConnect();
        uDgram.socketConnect();
        close(serverSockFD);
    });
}

TEST(unixDatagramSocket, Disconnect)
{
    ASSERT_NO_THROW({
        unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);
        uDgram.socketDisconnect();
    });
}

TEST(unixDatagramSocket, ConnectAndDisconnect)
{
    ASSERT_NO_THROW({
        unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);
        auto serverSockFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
        uDgram.socketConnect();
        uDgram.socketDisconnect();
        close(serverSockFD);
    });
}

TEST(unixDatagramSocket, ConnectDisconnectConnect)
{
    ASSERT_NO_THROW({
        unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);
        auto serverSockFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
        uDgram.socketConnect();
        uDgram.socketDisconnect();
        uDgram.socketConnect();
        close(serverSockFD);
    });
}

TEST(unixDatagramSocket, isConnectedFalse)
{
    ASSERT_NO_THROW({
        unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);
        ASSERT_FALSE(uDgram.isConnected());
        auto serverSockFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
        uDgram.socketConnect();
        uDgram.socketDisconnect();
        ASSERT_FALSE(uDgram.isConnected());
        close(serverSockFD);
    });
}

TEST(unixDatagramSocket, isConnectedTrue)
{
    ASSERT_NO_THROW({
        unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);
        auto serverSockFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
        uDgram.socketConnect();
        ASSERT_TRUE(uDgram.isConnected());
        uDgram.socketDisconnect();
        uDgram.socketConnect();
        ASSERT_TRUE(uDgram.isConnected());
        close(serverSockFD);
    });
}

TEST(unixDatagramSocket, ErrorSendMessageNoSocket)
{
    ASSERT_THROW(
        {
            unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);
            uDgram.sendMsg(TEST_SEND_MESSAGE.data());
        },
        std::runtime_error);
}

TEST(unixDatagramSocket, ErrorSendEmptyMessage)
{
    const char msg[] = "";

    ASSERT_NO_THROW({
        unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);
        auto serverSockFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
        ASSERT_EQ(uDgram.sendMsg(msg), SendRetval::SIZE_ZERO);
        close(serverSockFD);
    });
}

TEST(unixDatagramSocket, ErrorSendLongMessage)
{
    std::vector<char> msg = {};
    msg.resize(base::utils::socketInterface::DATAGRAM_MAX_MSG_SIZE + 2);
    std::fill(msg.begin(), msg.end() - 1, 'x');
    msg.back() = '\0';

    ASSERT_NO_THROW({
        unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);
        auto serverSockFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
        ASSERT_EQ(uDgram.sendMsg(msg.data()), SendRetval::SIZE_TOO_LONG);
        close(serverSockFD);
    });
}

TEST(unixDatagramSocket, SendMessage)
{
    ASSERT_NO_THROW({
        unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);
        auto serverSockFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
        uDgram.socketConnect();
        uDgram.sendMsg(TEST_SEND_MESSAGE.data());
        ASSERT_EQ(testRecvString(serverSockFD, SOCK_DGRAM), TEST_SEND_MESSAGE);
        close(serverSockFD);
    });
}

TEST(unixDatagramSocket, SendMessageDisconnected)
{
    ASSERT_NO_THROW({
        unixDatagram uDgram(TEST_DGRAM_SOCK_PATH);
        auto serverSockFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
        uDgram.sendMsg(TEST_SEND_MESSAGE.data());
        ASSERT_EQ(testRecvString(serverSockFD, SOCK_DGRAM), TEST_SEND_MESSAGE);
        close(serverSockFD);
    });
}
