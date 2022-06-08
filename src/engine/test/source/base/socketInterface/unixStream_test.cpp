
#include <iostream>

#include <fcntl.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <utils/socketInterface/unixStream.hpp>
#include "testAuxiliar/socketAuxiliarFunctions.hpp"

using namespace base::utils::socketInterface::unixStream;
using namespace base::utils::socketInterface;

TEST(wdbTests_SocketInterface, SocketConnectError)
{
    ASSERT_THROW(socketConnect(TEST_SOCKET_PATH), std::runtime_error);
}

TEST(wdbTests_SocketInterface, SocketConnect)
{
    // Create server
    const int acceptSocketFD = testBindUnixSocket(TEST_SOCKET_PATH);
    ASSERT_GT(acceptSocketFD, 0);

    // Connect client
    const int clientSocketFD = socketConnect(TEST_SOCKET_PATH);
    ASSERT_GT(clientSocketFD, 0);

    close(acceptSocketFD);
    close(clientSocketFD);

    unlink(TEST_SOCKET_PATH.data());
}

TEST(wdbTests_SocketInterface, SendMessageError)
{
    // Create server
    const int acceptSocketFD = testBindUnixSocket(TEST_SOCKET_PATH);
    ASSERT_GT(acceptSocketFD, 0);

    // Connect client
    const int clientSocketFD = socketConnect(TEST_SOCKET_PATH);
    ASSERT_GT(clientSocketFD, 0);

    // Force error
    close(clientSocketFD);
    // ASSERT_EQ(sendMsg(clientSocketFD, TEST_SEND_MESSAGE, TEST_SEND_MESSAGE.length()),
    //          -1);
    ASSERT_EQ(sendMsg(clientSocketFD, TEST_SEND_MESSAGE.data()),
              CommRetval::SOCKET_ERROR);

    close(acceptSocketFD);

    unlink(TEST_SOCKET_PATH.data());
}

TEST(wdbTests_SocketInterface, SendLongMessageError)
{
    char msg[MSG_MAX_SIZE + 2] = {};
    memset(msg, 'x', MSG_MAX_SIZE + 1);

    // Create server
    const int acceptSocketFD = testBindUnixSocket(TEST_SOCKET_PATH);
    ASSERT_GT(acceptSocketFD, 0);

    // Connect client
    const int clientSocketFD = socketConnect(TEST_SOCKET_PATH);
    ASSERT_GT(clientSocketFD, 0);

    // Force error
    ASSERT_EQ(sendMsg(clientSocketFD, msg), CommRetval::SIZE_TOO_LONG);

    close(acceptSocketFD);
    close(clientSocketFD);

    unlink(TEST_SOCKET_PATH.data());
}

TEST(wdbTests_SocketInterface, SendEmptyMessageError)
{
    // Create server
    const int acceptSocketFD = testBindUnixSocket(TEST_SOCKET_PATH);
    ASSERT_GT(acceptSocketFD, 0);

    // Connect client
    const int clientSocketFD = socketConnect(TEST_SOCKET_PATH);
    ASSERT_GT(clientSocketFD, 0);

    char msg[2] = {};
    ASSERT_EQ(sendMsg(clientSocketFD, msg), CommRetval::SIZE_ZERO);

    close(acceptSocketFD);
    close(clientSocketFD);

    unlink(TEST_SOCKET_PATH.data());
}

TEST(wdbTests_SocketInterface, SendInvalidSocketError)
{
    ASSERT_EQ(sendMsg(0, TEST_SEND_MESSAGE.data()), CommRetval::INVALID_SOCKET);
    ASSERT_EQ(sendMsg(-5, TEST_SEND_MESSAGE.data()), CommRetval::INVALID_SOCKET);
}

TEST(wdbTests_SocketInterface, SendWrongSocketFDError)
{
    ASSERT_EQ(sendMsg(999, TEST_SEND_MESSAGE.data()), CommRetval::SOCKET_ERROR);
}

TEST(wdbTests_SocketInterface, SendMessage)
{
    // Create server
    const int acceptSocketFD = testBindUnixSocket(TEST_SOCKET_PATH);
    ASSERT_GT(acceptSocketFD, 0);

    // Connect client
    const int clientSocketFD = socketConnect(TEST_SOCKET_PATH);
    ASSERT_GT(clientSocketFD, 0);

    ASSERT_EQ(sendMsg(clientSocketFD, TEST_SEND_MESSAGE.data()), CommRetval::SUCCESS);

    close(acceptSocketFD);
    close(clientSocketFD);

    unlink(TEST_SOCKET_PATH.data());
}

TEST(wdbTests_SocketInterface, RecvMessage)
{

    // Create server
    const int acceptSocketFD = testBindUnixSocket(TEST_SOCKET_PATH);
    ASSERT_GT(acceptSocketFD, 0);

    // Connect client
    const int clientSocketFD = socketConnect(TEST_SOCKET_PATH);
    ASSERT_GT(clientSocketFD, 0);

    const int serverSocketFD = testAcceptConnection(acceptSocketFD);
    ASSERT_GT(serverSocketFD, 0);

    const int msgLen = TEST_SEND_MESSAGE.length();
    ASSERT_EQ(sendMsg(serverSocketFD, TEST_SEND_MESSAGE.data()), CommRetval::SUCCESS);

    auto payload = recvString(clientSocketFD);
    const char* msg = static_cast<const char*>(payload.data());
    ASSERT_STREQ(msg, TEST_SEND_MESSAGE.data());

    close(acceptSocketFD);
    close(serverSocketFD);
    close(clientSocketFD);

    unlink(TEST_SOCKET_PATH.data());
}

TEST(wdbTests_SocketInterface, SendRecvMessage)
{
    char msg[MAX_BUFFER_SIZE] = {};

    // Create server
    const int acceptSocketFD = testBindUnixSocket(TEST_SOCKET_PATH);
    ASSERT_GT(acceptSocketFD, 0);

    // Connect client
    const int clientSocketFD = socketConnect(TEST_SOCKET_PATH);
    ASSERT_GT(clientSocketFD, 0);

    const int serverSocketFD = testAcceptConnection(acceptSocketFD);
    ASSERT_GT(serverSocketFD, 0);

    const int msgLen = TEST_SEND_MESSAGE.length();
    ASSERT_EQ(sendMsg(clientSocketFD, TEST_SEND_MESSAGE.data()), CommRetval::SUCCESS);

    auto payload = recvString(serverSocketFD);
    ASSERT_STREQ(payload.c_str(), TEST_SEND_MESSAGE.data());

    ASSERT_EQ(sendMsg(serverSocketFD, TEST_SEND_MESSAGE.data()), CommRetval::SUCCESS);

    payload = recvString(clientSocketFD);
    ASSERT_STREQ(payload.c_str(), TEST_SEND_MESSAGE.data());

    close(acceptSocketFD);
    close(clientSocketFD);
    close(serverSocketFD);

    unlink(TEST_SOCKET_PATH.data());
}

TEST(wdbTests_SocketInterface, SendRecvLongestMessage)
{
    char msg[MSG_MAX_SIZE + 1] = {};
    memset(msg, 'x', MSG_MAX_SIZE);

    // Create server
    const int acceptSocketFD = testBindUnixSocket(TEST_SOCKET_PATH);
    ASSERT_GT(acceptSocketFD, 0);

    // Connect client
    const int clientSocketFD = socketConnect(TEST_SOCKET_PATH);
    ASSERT_GT(clientSocketFD, 0);

    const int serverSocketFD = testAcceptConnection(acceptSocketFD);
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_EQ(sendMsg(clientSocketFD, msg), CommRetval::SUCCESS);

    auto payload = recvString(serverSocketFD);
    ASSERT_STREQ(payload.c_str(), msg);
    ASSERT_EQ(strlen(payload.c_str()), MSG_MAX_SIZE);

    close(acceptSocketFD);
    close(clientSocketFD);
    close(serverSocketFD);

    unlink(TEST_SOCKET_PATH.data());
}

TEST(wdbTests_SocketInterface, remoteCloseBeforeSend)
{

    // Create server
    const int serverSocketFD = testBindUnixSocket(TEST_SOCKET_PATH);
    ASSERT_GT(serverSocketFD, 0);

    // Connect client
    const int clientLocal = socketConnect(TEST_SOCKET_PATH);
    ASSERT_GT(clientLocal, 0);

    // Accept connection
    const int clientRemote = testAcceptConnection(serverSocketFD);
    ASSERT_GT(clientRemote, 0);

    // close remote before send
    close(clientRemote);

    ASSERT_THROW(sendMsg(clientLocal, TEST_SEND_MESSAGE.data()), RecoverableError);

    // Broken pipe
    ASSERT_EQ(errno, EPIPE);

    close(serverSocketFD);
    close(clientLocal);

    unlink(TEST_SOCKET_PATH.data());
}

TEST(wdbTests_SocketInterface, remoteCloseBeforeRcv)
{

    // Create server
    const int serverSocketFD = testBindUnixSocket(TEST_SOCKET_PATH);
    ASSERT_GT(serverSocketFD, 0);

    // Connect client
    const int clientLocal = socketConnect(TEST_SOCKET_PATH);
    ASSERT_GT(clientLocal, 0);

    // Accept connection
    const int clientRemote = testAcceptConnection(serverSocketFD);
    ASSERT_GT(clientRemote, 0);

    // close remote before recv
    close(clientRemote);

    // gracefully closed
    ASSERT_THROW(
        try { recvString(clientLocal); } catch (const RecoverableError& e) {
            ASSERT_STREQ(e.what(), "recvMsg: socket disconnected");
            throw;
        },
        RecoverableError);

    close(serverSocketFD);
    close(clientLocal);

    unlink(TEST_SOCKET_PATH.data());
}

TEST(wdbTests_SocketInterface, localSendremoteCloseBeforeRcv)
{

    // Create server
    const int serverSocketFD = testBindUnixSocket(TEST_SOCKET_PATH);
    ASSERT_GT(serverSocketFD, 0);

    // Connect client
    const int clientLocal = socketConnect(TEST_SOCKET_PATH);
    ASSERT_GT(clientLocal, 0);

    // Accept connection
    const int clientRemote = testAcceptConnection(serverSocketFD);
    ASSERT_GT(clientRemote, 0);

    // Send to remote
    ASSERT_EQ(sendMsg(clientLocal, TEST_SEND_MESSAGE.data()), CommRetval::SUCCESS);
    // Remote dont read and close the socket
    close(clientRemote);

    ASSERT_THROW(recvString(clientLocal), RecoverableError);
    ASSERT_EQ(errno, ECONNRESET);

    close(serverSocketFD);
    close(clientLocal);

    unlink(TEST_SOCKET_PATH.data());
}
