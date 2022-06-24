/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 */

#include <iostream>
#include <unistd.h>

#include <gtest/gtest.h>

#include <utils/socketInterface/unixSecureStream.hpp>

#include "testAuxiliar/socketAuxiliarFunctions.hpp"

using namespace base::utils::socketInterface;

TEST(unixSecureStreamSocket, build)
{
    ASSERT_NO_THROW(unixSecureStream uStream());
    ASSERT_NO_THROW(unixSecureStream uStream(TEST_STREAM_SOCK_PATH));
    ASSERT_NO_THROW(unixSecureStream uStream("qwertyuiop"));
}

TEST(unixSecureStreamSocket, SetMaxMsgSizeError)
{
    ASSERT_THROW({ unixSecureStream uStream(TEST_STREAM_SOCK_PATH, 0); },
                 std::invalid_argument);

    ASSERT_THROW({ unixSecureStream uStream(TEST_STREAM_SOCK_PATH, {}); },
                 std::invalid_argument);
}

TEST(unixSecureStreamSocket, GetMaxMsgSize)
{
    {
        unixSecureStream uStream(TEST_STREAM_SOCK_PATH);
        ASSERT_EQ(uStream.getMaxMsgSize(), STREAM_MAX_MSG_SIZE);
    }

    {
        int setSize {99};
        unixSecureStream uStream(TEST_STREAM_SOCK_PATH, setSize);
        ASSERT_EQ(uStream.getMaxMsgSize(), setSize);
    }

    {
        unixSecureStream uStream(TEST_STREAM_SOCK_PATH);
        ASSERT_EQ(uStream.getMaxMsgSize(), STREAM_MAX_MSG_SIZE);
    }

    {
        int setSize {STREAM_MAX_MSG_SIZE + 1};
        unixSecureStream uStream(TEST_STREAM_SOCK_PATH, setSize);
        ASSERT_EQ(uStream.getMaxMsgSize(), setSize);
    }
}

TEST(unixSecureStreamSocket, GetPath)
{
    unixSecureStream uStream(TEST_STREAM_SOCK_PATH);
    ASSERT_NO_THROW(ASSERT_EQ(uStream.getPath(), TEST_STREAM_SOCK_PATH););
}

TEST(unixSecureStreamSocket, ConnectErrorInvalidPath)
{
    {
        unixSecureStream uStream("/invalid/path");
        ASSERT_THROW(uStream.socketConnect(), std::runtime_error);
    }
    {
        unixSecureStream uStream(TEST_STREAM_SOCK_PATH);
        ASSERT_THROW(uStream.socketConnect(), std::runtime_error);
    }
}

TEST(unixSecureStreamSocket, Connect)
{
    unixSecureStream uStream(TEST_STREAM_SOCK_PATH);

    auto serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uStream.socketConnect());

    close(serverSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixSecureStreamSocket, ConnectTwice)
{
    unixSecureStream uStream(TEST_STREAM_SOCK_PATH);

    auto serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uStream.socketConnect());
    ASSERT_NO_THROW(uStream.socketConnect());

    close(serverSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixSecureStreamSocket, Disconnect)
{
    unixSecureStream uStream(TEST_STREAM_SOCK_PATH);
    ASSERT_NO_THROW(uStream.socketDisconnect());
}

TEST(unixSecureStreamSocket, ConnectAndDisconnect)
{
    unixSecureStream uStream(TEST_STREAM_SOCK_PATH);

    auto serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uStream.socketConnect());
    ASSERT_NO_THROW(uStream.socketDisconnect());

    close(serverSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixSecureStreamSocket, ConnectDisconnectConnect)
{
    unixSecureStream uStream(TEST_STREAM_SOCK_PATH);

    auto serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uStream.socketConnect());
    ASSERT_NO_THROW(uStream.socketDisconnect());
    ASSERT_NO_THROW(uStream.socketConnect());

    close(serverSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixSecureStreamSocket, isConnectedFalse)
{
    unixSecureStream uStream(TEST_STREAM_SOCK_PATH);

    ASSERT_FALSE(uStream.isConnected());

    auto serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uStream.socketConnect());
    ASSERT_NO_THROW(uStream.socketDisconnect());

    ASSERT_FALSE(uStream.isConnected());

    close(serverSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixSecureStreamSocket, isConnectedTrue)
{
    unixSecureStream uStream(TEST_STREAM_SOCK_PATH);

    auto serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uStream.socketConnect());

    ASSERT_TRUE(uStream.isConnected());

    ASSERT_NO_THROW(uStream.socketDisconnect());
    ASSERT_NO_THROW(uStream.socketConnect());

    ASSERT_TRUE(uStream.isConnected());

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixSecureStreamSocket, ErrorSendMessageNoSocket)
{
    unixSecureStream uStream(TEST_STREAM_SOCK_PATH);
    ASSERT_THROW(uStream.sendMsg(TEST_SEND_MESSAGE.data());, std::runtime_error);
}

TEST(unixSecureStreamSocket, ErrorSendEmptyMessage)
{
    const char msg[] = "";

    unixSecureStream uStream(TEST_STREAM_SOCK_PATH);

    auto serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(ASSERT_EQ(uStream.sendMsg(msg), SendRetval::SIZE_ZERO));

    close(serverSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixSecureStreamSocket, ErrorSendLongMessage)
{
    std::vector<char> msg = {};
    msg.resize(STREAM_MAX_MSG_SIZE + 2);
    std::fill(msg.begin(), msg.end() - 1, 'x');
    msg.back() = '\0';

    unixSecureStream uStream(TEST_STREAM_SOCK_PATH);

    auto serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(ASSERT_EQ(uStream.sendMsg(msg.data()), SendRetval::SIZE_TOO_LONG));

    close(serverSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixSecureStreamSocket, SendMessage)
{
    unixSecureStream uStream(TEST_STREAM_SOCK_PATH);

    auto acceptSocketFd = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(acceptSocketFd, 0);

    ASSERT_NO_THROW(uStream.socketConnect());

    auto serverSocketFD = testAcceptConnection(acceptSocketFd);
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uStream.sendMsg(TEST_SEND_MESSAGE.data()));
    ASSERT_NO_THROW(
        ASSERT_EQ(testRecvString(serverSocketFD, SOCK_STREAM), TEST_SEND_MESSAGE));

    close(acceptSocketFd);
    close(serverSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixSecureStreamSocket, SendMessageDisconnected)
{
    unixSecureStream uStream(TEST_STREAM_SOCK_PATH);

    auto acceptSocketFd = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(acceptSocketFd, 0);

    ASSERT_NO_THROW(uStream.sendMsg(TEST_SEND_MESSAGE.data()));

    auto serverSocketFD = testAcceptConnection(acceptSocketFd);
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(
        ASSERT_EQ(testRecvString(serverSocketFD, SOCK_STREAM), TEST_SEND_MESSAGE));

    close(acceptSocketFd);
    close(serverSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixSecureStreamSocket, ReceiveMessage)
{
    unixSecureStream uStream(TEST_STREAM_SOCK_PATH);

    auto acceptSocketFd = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(acceptSocketFd, 0);

    ASSERT_NO_THROW(uStream.socketConnect());

    auto serverSocketFD = testAcceptConnection(acceptSocketFd);
    ASSERT_GT(serverSocketFD, 0);

    auto commRetval = testSendMsg(serverSocketFD, TEST_SEND_MESSAGE.data());
    ASSERT_EQ(commRetval, CommRetval::SUCCESS);

    auto receivedMessage = uStream.recvMsg();
    ASSERT_STREQ(receivedMessage.data(), TEST_SEND_MESSAGE.data());

    close(acceptSocketFd);
    close(serverSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixSecureStreamSocket, SendAndReceiveMessage)
{
    unixSecureStream uStream(TEST_STREAM_SOCK_PATH);

    auto acceptSocketFd = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(acceptSocketFd, 0);

    ASSERT_NO_THROW(uStream.socketConnect());

    auto serverSocketFD = testAcceptConnection(acceptSocketFd);
    ASSERT_GT(serverSocketFD, 0);

    uStream.sendMsg(TEST_SEND_MESSAGE.data());

    auto serverRcvMsg = testRecvString(serverSocketFD, SOCK_STREAM);
    ASSERT_STREQ(serverRcvMsg.data(), TEST_SEND_MESSAGE.data());

    auto commRetval = testSendMsg(serverSocketFD, TEST_SEND_MESSAGE.data());
    ASSERT_EQ(commRetval, CommRetval::SUCCESS);

    auto clientRcvMsg = uStream.recvMsg();
    ASSERT_STREQ(clientRcvMsg.data(), TEST_SEND_MESSAGE.data());

    close(acceptSocketFd);
    close(serverSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixSecureStreamSocket, SendLongestMessage)
{
    unixSecureStream uStream(TEST_STREAM_SOCK_PATH);

    char msg[uStream.getMaxMsgSize()] = {};
    memset(msg, 'x', uStream.getMaxMsgSize());

    // Create server
    const int acceptSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(acceptSocketFD, 0);

    // Connect client
    ASSERT_NO_THROW(uStream.socketConnect());

    const int serverSocketFD = testAcceptConnection(acceptSocketFD);
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_EQ(uStream.sendMsg(msg), SendRetval::SUCCESS);

    auto payload = testRecvString(serverSocketFD, SOCK_STREAM);
    ASSERT_EQ(strlen(payload.c_str()), uStream.getMaxMsgSize());
    ASSERT_STREQ(payload.c_str(), msg);

    close(acceptSocketFD);
    close(serverSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixSecureStreamSocket, RemoteCloseBeforeSend)
{
    unixSecureStream uStream(TEST_STREAM_SOCK_PATH);

    // Create server
    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    // Connect client
    ASSERT_NO_THROW(uStream.socketConnect());

    // Accept connection
    const int clientRemote = testAcceptConnection(serverSocketFD);
    ASSERT_GT(clientRemote, 0);

    // close remote before send
    close(clientRemote);

    ASSERT_THROW(uStream.sendMsg(TEST_SEND_MESSAGE.data()), std::runtime_error);

    // Broken pipe
    ASSERT_EQ(errno, EPIPE);

    close(serverSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixSecureStreamSocket, RemoteCloseBeforeRcv)
{
    unixSecureStream uStream(TEST_STREAM_SOCK_PATH);

    // Create server
    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    // Connect client
    ASSERT_NO_THROW(uStream.socketConnect());

    // Accept connection
    const int clientRemote = testAcceptConnection(serverSocketFD);
    ASSERT_GT(clientRemote, 0);

    // close remote before recv
    close(clientRemote);

    // gracefully closed
    ASSERT_THROW(
        try { uStream.recvMsg(); } catch (const std::runtime_error& e) {
            ASSERT_STREQ(e.what(), "recvMsg: socket disconnected.");
            throw;
        },
        std::runtime_error);

    close(serverSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixSecureStreamSocket, LocalSendremoteCloseBeforeRcv)
{
    unixSecureStream uStream(TEST_STREAM_SOCK_PATH);

    // Create server
    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    // Connect client
    ASSERT_NO_THROW(uStream.socketConnect());

    // Accept connection
    const int clientRemote = testAcceptConnection(serverSocketFD);
    ASSERT_GT(clientRemote, 0);

    // Send to remote
    ASSERT_EQ(uStream.sendMsg(TEST_SEND_MESSAGE.data()), SendRetval::SUCCESS);
    // Remote dont read and close the socket
    close(clientRemote);

    ASSERT_THROW(uStream.recvMsg(), std::runtime_error);
    ASSERT_EQ(errno, ECONNRESET);

    close(serverSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}
