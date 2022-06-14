
#include <iostream>

#include <fcntl.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <utils/socketInterface/unixStream.hpp>
#include <utils/socketInterface/unixSecureStream.hpp>

#include "testAuxiliar/socketAuxiliarFunctions.hpp"

using namespace base::utils::socketInterface;

// TODO move interface test to a separate file
TEST(unixStreamSocket, ConnectError)
{
    ASSERT_THROW(unixStream::socketConnect(TEST_STREAM_SOCK_PATH), std::runtime_error);
}

// TODO move interface tests to a separate file
TEST(unixStreamSocket, Connect)
{
    // Create server
    const int acceptSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(acceptSocketFD, 0);

    // Connect client
    const int clientSocketFD = unixStream::socketConnect(TEST_STREAM_SOCK_PATH);
    ASSERT_GT(clientSocketFD, 0);

    close(acceptSocketFD);
    close(clientSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

// TODO Add test move semantics
// TODO check reconnection
// TODO CHeck disconnection
TEST(unixStreamSocket, SendMessageError)
{
    // Create server
    const int acceptSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(acceptSocketFD, 0);

    // Connect client
    const int clientSocketFD = unixStream::socketConnect(TEST_STREAM_SOCK_PATH);
    ASSERT_GT(clientSocketFD, 0);

    // Force error
    close(clientSocketFD);

    ASSERT_EQ(unixStream::sendMsg(clientSocketFD, TEST_SEND_MESSAGE.data()),
              CommRetval::SOCKET_ERROR);

    close(acceptSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

// TODO RENAME AND RE CHECK ALL TEST
// TODO ADD DESCRIPTION - ESCENARIO to CHECK
TEST(unixStreamSocket, SendLongMessageError)
{
    unixSecureStream clientSocket(TEST_STREAM_SOCK_PATH);

    std::vector<char> msg = {};
    msg.resize(clientSocket.getMaxMsgSize() + 2);
    std::fill(msg.begin(), msg.end() - 1, 'x');
    msg.back() = '\0';


    // Create server
    const int acceptSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(acceptSocketFD, 0);

    // Connect client (This is not necessary)
    clientSocket.socketConnect();

    // Force error
    ASSERT_EQ(clientSocket.sendMsg(msg.data()), SendRetval::SIZE_TOO_LONG);

    close(acceptSocketFD);
    clientSocket.socketDisconnect();

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixStreamSocket, SendEmptyMessageError)
{
    // Create server
    const int acceptSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(acceptSocketFD, 0);

    // Connect client
    const int clientSocketFD = unixStream::socketConnect(TEST_STREAM_SOCK_PATH);
    ASSERT_GT(clientSocketFD, 0);

    char msg[2] = {};
    ASSERT_EQ(unixStream::sendMsg(clientSocketFD, msg), CommRetval::SIZE_ZERO);

    close(acceptSocketFD);
    close(clientSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixStreamSocket, SendInvalidSocketError)
{
    ASSERT_EQ(unixStream::sendMsg(0, TEST_SEND_MESSAGE.data()),
              CommRetval::INVALID_SOCKET);
    ASSERT_EQ(unixStream::sendMsg(-5, TEST_SEND_MESSAGE.data()),
              CommRetval::INVALID_SOCKET);
}

TEST(unixStreamSocket, SendWrongSocketFDError)
{
    ASSERT_EQ(unixStream::sendMsg(999, TEST_SEND_MESSAGE.data()),
              CommRetval::SOCKET_ERROR);
}

TEST(unixStreamSocket, SendMessage)
{
    // Create server
    const int acceptSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(acceptSocketFD, 0);

    // Connect client
    const int clientSocketFD = unixStream::socketConnect(TEST_STREAM_SOCK_PATH);
    ASSERT_GT(clientSocketFD, 0);

    ASSERT_EQ(unixStream::sendMsg(clientSocketFD, TEST_SEND_MESSAGE.data()),
              CommRetval::SUCCESS);

    close(acceptSocketFD);
    close(clientSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixStreamSocket, RecvMessage)
{

    // Create server
    const int acceptSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(acceptSocketFD, 0);

    // Connect client
    const int clientSocketFD = unixStream::socketConnect(TEST_STREAM_SOCK_PATH);
    ASSERT_GT(clientSocketFD, 0);

    const int serverSocketFD = testAcceptConnection(acceptSocketFD);
    ASSERT_GT(serverSocketFD, 0);

    const int msgLen = TEST_SEND_MESSAGE.length();
    ASSERT_EQ(unixStream::sendMsg(serverSocketFD, TEST_SEND_MESSAGE.data()),
              CommRetval::SUCCESS);

    auto payload = unixStream::recvString(clientSocketFD);
    const char* msg = static_cast<const char*>(payload.data());
    ASSERT_STREQ(msg, TEST_SEND_MESSAGE.data());

    close(acceptSocketFD);
    close(serverSocketFD);
    close(clientSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixStreamSocket, SendRecvMessage)
{
    char msg[MAX_BUFFER_SIZE] = {};

    // Create server
    const int acceptSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(acceptSocketFD, 0);

    // Connect client
    const int clientSocketFD = unixStream::socketConnect(TEST_STREAM_SOCK_PATH);
    ASSERT_GT(clientSocketFD, 0);

    const int serverSocketFD = testAcceptConnection(acceptSocketFD);
    ASSERT_GT(serverSocketFD, 0);

    const int msgLen = TEST_SEND_MESSAGE.length();
    ASSERT_EQ(unixStream::sendMsg(clientSocketFD, TEST_SEND_MESSAGE.data()),
              CommRetval::SUCCESS);

    auto payload = unixStream::recvString(serverSocketFD);
    ASSERT_STREQ(payload.c_str(), TEST_SEND_MESSAGE.data());

    ASSERT_EQ(unixStream::sendMsg(serverSocketFD, TEST_SEND_MESSAGE.data()),
              CommRetval::SUCCESS);

    payload = unixStream::recvString(clientSocketFD);
    ASSERT_STREQ(payload.c_str(), TEST_SEND_MESSAGE.data());

    close(acceptSocketFD);
    close(clientSocketFD);
    close(serverSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixStreamSocket, SendRecvLongestMessage)
{
    char msg[unixStream::MSG_MAX_SIZE + 1] = {};
    memset(msg, 'x', unixStream::MSG_MAX_SIZE);

    // Create server
    const int acceptSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(acceptSocketFD, 0);

    // Connect client
    const int clientSocketFD = unixStream::socketConnect(TEST_STREAM_SOCK_PATH);
    ASSERT_GT(clientSocketFD, 0);

    const int serverSocketFD = testAcceptConnection(acceptSocketFD);
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_EQ(unixStream::sendMsg(clientSocketFD, msg), CommRetval::SUCCESS);

    auto payload = unixStream::recvString(serverSocketFD);
    ASSERT_STREQ(payload.c_str(), msg);
    ASSERT_EQ(strlen(payload.c_str()), unixStream::MSG_MAX_SIZE);

    close(acceptSocketFD);
    close(clientSocketFD);
    close(serverSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixStreamSocket, RemoteCloseBeforeSend)
{

    // Create server
    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    // Connect client
    const int clientLocal = unixStream::socketConnect(TEST_STREAM_SOCK_PATH);
    ASSERT_GT(clientLocal, 0);

    // Accept connection
    const int clientRemote = testAcceptConnection(serverSocketFD);
    ASSERT_GT(clientRemote, 0);

    // close remote before send
    close(clientRemote);

    ASSERT_THROW(unixStream::sendMsg(clientLocal, TEST_SEND_MESSAGE.data()),
                 unixStream::RecoverableError);

    // Broken pipe
    ASSERT_EQ(errno, EPIPE);

    close(serverSocketFD);
    close(clientLocal);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixStreamSocket, RemoteCloseBeforeRcv)
{

    // Create server
    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    // Connect client
    const int clientLocal = unixStream::socketConnect(TEST_STREAM_SOCK_PATH);
    ASSERT_GT(clientLocal, 0);

    // Accept connection
    const int clientRemote = testAcceptConnection(serverSocketFD);
    ASSERT_GT(clientRemote, 0);

    // close remote before recv
    close(clientRemote);

    // gracefully closed
    ASSERT_THROW(
        try {
            unixStream::recvString(clientLocal);
        } catch (const unixStream::RecoverableError& e) {
            ASSERT_STREQ(e.what(), "recvMsg: socket disconnected");
            throw;
        },
        unixStream::RecoverableError);

    close(serverSocketFD);
    close(clientLocal);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixStreamSocket, LocalSendremoteCloseBeforeRcv)
{

    // Create server
    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    // Connect client
    const int clientLocal = unixStream::socketConnect(TEST_STREAM_SOCK_PATH);
    ASSERT_GT(clientLocal, 0);

    // Accept connection
    const int clientRemote = testAcceptConnection(serverSocketFD);
    ASSERT_GT(clientRemote, 0);

    // Send to remote
    ASSERT_EQ(unixStream::sendMsg(clientLocal, TEST_SEND_MESSAGE.data()),
              CommRetval::SUCCESS);
    // Remote dont read and close the socket
    close(clientRemote);

    ASSERT_THROW(unixStream::recvString(clientLocal), unixStream::RecoverableError);
    ASSERT_EQ(errno, ECONNRESET);

    close(serverSocketFD);
    close(clientLocal);

    unlink(TEST_STREAM_SOCK_PATH.data());
}
