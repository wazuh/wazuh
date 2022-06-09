#include <iostream>

#include <gtest/gtest.h>

#include <utils/socketInterface/unixDatagram.hpp>

#include "testAuxiliar/socketAuxiliarFunctions.hpp"

using namespace base::utils::socketInterface;

TEST(unixDatagramSocket, ConnectErrorWrongPath)
{
    ASSERT_THROW(unixDatagram::socketConnect(TEST_DGRAM_SOCK_PATH), std::runtime_error);
}

TEST(unixDatagramSocket, ConnectErrorEmptyPath)
{
    ASSERT_THROW(unixDatagram::socketConnect(""), std::runtime_error);
}

TEST(unixDatagramSocket, Connect)
{
    const int readSockFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(readSockFD, 0);

    const int writeSockFD = unixDatagram::socketConnect(TEST_DGRAM_SOCK_PATH);
    ASSERT_GT(writeSockFD, 0);

    close(writeSockFD);
    close(readSockFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}

TEST(unixDatagramSocket, SendInvalidSocketError)
{
    ASSERT_EQ(unixDatagram::sendMsg(0, TEST_SEND_MESSAGE.data()),
              CommRetval::INVALID_SOCKET);
    ASSERT_EQ(unixDatagram::sendMsg(-5, TEST_SEND_MESSAGE.data()),
              CommRetval::INVALID_SOCKET);
}

TEST(unixDatagramSocket, SendWrongSocketFDError)
{
    ASSERT_EQ(unixDatagram::sendMsg(999, TEST_SEND_MESSAGE.data()),
              CommRetval::SOCKET_ERROR);
}

TEST(unixDatagramSocket, SendMsgCloseSocketError)
{
    const int readSockFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(readSockFD, 0);

    const int writeSockFD = unixDatagram::socketConnect(TEST_DGRAM_SOCK_PATH);
    ASSERT_GT(writeSockFD, 0);

    // Force error by closing the reading socket
    close(readSockFD);
    ASSERT_EQ(unixDatagram::sendMsg(writeSockFD, TEST_SEND_MESSAGE.data()),
              CommRetval::SOCKET_ERROR);

    close(writeSockFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}

TEST(unixDatagramSocket, SendLongMessageError)
{
    const int readSockFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(readSockFD, 0);

    const int writeSockFD = unixDatagram::socketConnect(TEST_DGRAM_SOCK_PATH);
    ASSERT_GT(writeSockFD, 0);

    // Force error by sending a message that is too long
    char msg[unixDatagram::MSG_MAX_SIZE + 2] = {};
    memset(msg, 'x', unixDatagram::MSG_MAX_SIZE + 1);
    auto retval = unixDatagram::sendMsg(writeSockFD, msg);
    ASSERT_EQ(retval, CommRetval::SIZE_TOO_LONG);

    close(readSockFD);
    close(writeSockFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixDatagramSocket, SendEmptyMessageError)
{
    const int readSockFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(readSockFD, 0);

    const int writeSockFD = unixDatagram::socketConnect(TEST_DGRAM_SOCK_PATH);
    ASSERT_GT(writeSockFD, 0);

    // Force error by sending an empty message
    char msg[2] = {};
    auto retval = unixDatagram::sendMsg(writeSockFD, msg);
    ASSERT_EQ(retval, CommRetval::SIZE_ZERO);

    close(readSockFD);
    close(writeSockFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixDatagramSocket, SendMsg)
{
    const int readSockFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(readSockFD, 0);

    const int writeSockFD = unixDatagram::socketConnect(TEST_DGRAM_SOCK_PATH);
    ASSERT_GT(writeSockFD, 0);

    auto retval = unixDatagram::sendMsg(writeSockFD, TEST_SEND_MESSAGE.data());
    ASSERT_EQ(retval, CommRetval::SUCCESS);

    // Set-up sockaddr structure
    socklen_t len {};
    struct sockaddr_un peer_sock;
    memset(&peer_sock, 0, sizeof(peer_sock));

    char buff[MAX_BUFFER_SIZE] = {};
    recvfrom(readSockFD, buff, MAX_BUFFER_SIZE, 0, (struct sockaddr*)&peer_sock, &len);
    ASSERT_STREQ(buff, TEST_SEND_MESSAGE.data());

    close(readSockFD);
    close(writeSockFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}
