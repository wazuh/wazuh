
#include <iostream>

#include <fcntl.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <utils/socketInterface/unixSecureStream.hpp>

#include "testAuxiliar/socketAuxiliarFunctions.hpp"

using namespace base::utils::socketInterface;

// TODO move interface test to a separate file
TEST(unixSecureStreamSocket, ConnectError)
{
    ASSERT_THROW(testSocketConnect(TEST_STREAM_SOCK_PATH, SOCK_STREAM), std::runtime_error);
}

// TODO move interface tests to a separate file
TEST(unixSecureStreamSocket, Connect)
{
    // Create server
    const int acceptSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(acceptSocketFD, 0);

    // Connect client
    const int clientSocketFD = testSocketConnect(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(clientSocketFD, 0);

    close(acceptSocketFD);
    close(clientSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

// TODO Add test move semantics
// TODO check reconnection
// TODO CHeck disconnection
TEST(unixSecureStreamSocket, SendMessageError)
{
    // Create server
    const int acceptSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(acceptSocketFD, 0);

    // Connect client
    const int clientSocketFD = testSocketConnect(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(clientSocketFD, 0);

    // Force error
    close(clientSocketFD);

    ASSERT_EQ(testSendMsg(clientSocketFD, TEST_SEND_MESSAGE.data()),
              CommRetval::COMMUNICATION_ERROR);

    close(acceptSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

// TODO RENAME AND RE CHECK ALL TEST
// TODO ADD DESCRIPTION - ESCENARIO to CHECK
TEST(unixSecureStreamSocket, SendLongMessageError)
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

TEST(unixSecureStreamSocket, SendEmptyMessageError)
{
    // Create server
    const int acceptSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(acceptSocketFD, 0);

    // Connect client
    const int clientSocketFD = testSocketConnect(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(clientSocketFD, 0);

    char msg[2] = {};
    ASSERT_EQ(testSendMsg(clientSocketFD, msg), CommRetval::SIZE_ZERO);

    close(acceptSocketFD);
    close(clientSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixSecureStreamSocket, SendInvalidSocketError)
{
    ASSERT_EQ(testSendMsg(0, TEST_SEND_MESSAGE.data()), CommRetval::INVALID_SOCKET);
    ASSERT_EQ(testSendMsg(-5, TEST_SEND_MESSAGE.data()), CommRetval::INVALID_SOCKET);
}

TEST(unixSecureStreamSocket, SendWrongSocketFDError)
{
    ASSERT_EQ(testSendMsg(999, TEST_SEND_MESSAGE.data()), CommRetval::COMMUNICATION_ERROR);
}

TEST(unixSecureStreamSocket, SendMessage)
{
    // Create server
    const int acceptSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(acceptSocketFD, 0);

    // Connect client
    const int clientSocketFD = testSocketConnect(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(clientSocketFD, 0);

    ASSERT_EQ(testSendMsg(clientSocketFD, TEST_SEND_MESSAGE.data()), CommRetval::SUCCESS);

    close(acceptSocketFD);
    close(clientSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixSecureStreamSocket, RecvMessage)
{

    // Create server
    const int acceptSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(acceptSocketFD, 0);

    // Connect client
    const int clientSocketFD = testSocketConnect(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(clientSocketFD, 0);

    const int serverSocketFD = testAcceptConnection(acceptSocketFD);
    ASSERT_GT(serverSocketFD, 0);

    const int msgLen = TEST_SEND_MESSAGE.length();
    ASSERT_EQ(testSendMsg(serverSocketFD, TEST_SEND_MESSAGE.data()), CommRetval::SUCCESS);

    auto payload = testRecvString(clientSocketFD);
    const char* msg = static_cast<const char*>(payload.data());
    ASSERT_STREQ(msg, TEST_SEND_MESSAGE.data());

    close(acceptSocketFD);
    close(serverSocketFD);
    close(clientSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixSecureStreamSocket, SendRecvMessage)
{
    char msg[MAX_BUFFER_SIZE] = {};

    // Create server
    const int acceptSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(acceptSocketFD, 0);

    // Connect client
    const int clientSocketFD = testSocketConnect(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(clientSocketFD, 0);

    const int serverSocketFD = testAcceptConnection(acceptSocketFD);
    ASSERT_GT(serverSocketFD, 0);

    const int msgLen = TEST_SEND_MESSAGE.length();
    ASSERT_EQ(testSendMsg(clientSocketFD, TEST_SEND_MESSAGE.data()), CommRetval::SUCCESS);

    auto payload = testRecvString(serverSocketFD);
    ASSERT_STREQ(payload.c_str(), TEST_SEND_MESSAGE.data());

    ASSERT_EQ(testSendMsg(serverSocketFD, TEST_SEND_MESSAGE.data()), CommRetval::SUCCESS);

    payload = testRecvString(clientSocketFD);
    ASSERT_STREQ(payload.c_str(), TEST_SEND_MESSAGE.data());

    close(acceptSocketFD);
    close(clientSocketFD);
    close(serverSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixSecureStreamSocket, SendRecvLongestMessage)
{
    char msg[MSG_MAX_SIZE + 1] = {};
    memset(msg, 'x', MSG_MAX_SIZE);

    // Create server
    const int acceptSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(acceptSocketFD, 0);

    // Connect client
    const int clientSocketFD = testSocketConnect(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(clientSocketFD, 0);

    const int serverSocketFD = testAcceptConnection(acceptSocketFD);
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_EQ(testSendMsg(clientSocketFD, msg), CommRetval::SUCCESS);

    auto payload = testRecvString(serverSocketFD);
    ASSERT_STREQ(payload.c_str(), msg);
    ASSERT_EQ(strlen(payload.c_str()), MSG_MAX_SIZE);

    close(acceptSocketFD);
    close(clientSocketFD);
    close(serverSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixSecureStreamSocket, RemoteCloseBeforeSend)
{

    // Create server
    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    // Connect client
    const int clientLocal = testSocketConnect(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(clientLocal, 0);

    // Accept connection
    const int clientRemote = testAcceptConnection(serverSocketFD);
    ASSERT_GT(clientRemote, 0);

    // close remote before send
    close(clientRemote);

    ASSERT_THROW(testSendMsg(clientLocal, TEST_SEND_MESSAGE.data()), std::runtime_error);

    // Broken pipe
    ASSERT_EQ(errno, EPIPE);

    close(serverSocketFD);
    close(clientLocal);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixSecureStreamSocket, RemoteCloseBeforeRcv)
{

    // Create server
    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    // Connect client
    const int clientLocal = testSocketConnect(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(clientLocal, 0);

    // Accept connection
    const int clientRemote = testAcceptConnection(serverSocketFD);
    ASSERT_GT(clientRemote, 0);

    // close remote before recv
    close(clientRemote);

    // gracefully closed
    ASSERT_THROW(
        try {
            testRecvString(clientLocal);
        } catch (const std::runtime_error& e) {
            ASSERT_STREQ(e.what(), "recvMsg: socket disconnected.");
            throw;
        },
        std::runtime_error);

    close(serverSocketFD);
    close(clientLocal);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(unixSecureStreamSocket, LocalSendremoteCloseBeforeRcv)
{

    // Create server
    const int serverSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(serverSocketFD, 0);

    // Connect client
    const int clientLocal = testSocketConnect(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(clientLocal, 0);

    // Accept connection
    const int clientRemote = testAcceptConnection(serverSocketFD);
    ASSERT_GT(clientRemote, 0);

    // Send to remote
    ASSERT_EQ(testSendMsg(clientLocal, TEST_SEND_MESSAGE.data()), CommRetval::SUCCESS);
    // Remote dont read and close the socket
    close(clientRemote);

    ASSERT_THROW(testRecvString(clientLocal), std::runtime_error);
    ASSERT_EQ(errno, ECONNRESET);

    close(serverSocketFD);
    close(clientLocal);

    unlink(TEST_STREAM_SOCK_PATH.data());
}
