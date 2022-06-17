
#include <fcntl.h>
#include <iostream>
#include <sys/un.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include "socketAuxiliarFunctions.hpp"

// Note: server DGRAM sockets are only able to receive and clients are only able to send.

TEST(socketAuxiliarFunctions, StreamConnectError)
{
    ASSERT_THROW(testSocketConnect(TEST_STREAM_SOCK_PATH, SOCK_STREAM),
                 std::runtime_error);
}

TEST(socketAuxiliarFunctions, DatagramConnectError)
{
    ASSERT_THROW(testSocketConnect(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM), std::runtime_error);
}

TEST(socketAuxiliarFunctions, StreamBind)
{
    // Create server
    const int acceptSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(acceptSocketFD, 0);

    close(acceptSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(socketAuxiliarFunctions, DatagramBind)
{
    // Create server
    const int socketFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(socketFD, 0);

    close(socketFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}

TEST(socketAuxiliarFunctions, StreamConnect)
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

TEST(socketAuxiliarFunctions, DatagramConnect)
{
    // Create server
    const int serverSocketFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(serverSocketFD, 0);

    // Connect client
    const int clientSocketFD = testSocketConnect(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(clientSocketFD, 0);

    close(serverSocketFD);
    close(clientSocketFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}

TEST(socketAuxiliarFunctions, StreamSendMessageError)
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

TEST(socketAuxiliarFunctions, DatagramSendMessageError)
{
    // Create server
    const int serverSocketFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(serverSocketFD, 0);

    // Connect client
    const int clientSocketFD = testSocketConnect(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(clientSocketFD, 0);

    // Force error
    close(clientSocketFD);

    ASSERT_EQ(testSendMsg(clientSocketFD, TEST_SEND_MESSAGE.data(), false),
              CommRetval::COMMUNICATION_ERROR);

    close(serverSocketFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}

TEST(socketAuxiliarFunctions, StreamSendLongMessageError)
{
    // Create server
    const int acceptSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(acceptSocketFD, 0);

    // Connect client
    const int clientSocketFD = testSocketConnect(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(clientSocketFD, 0);

    std::vector<char> msg = {};
    msg.resize(MSG_MAX_SIZE + 2);
    std::fill(msg.begin(), msg.end() - 1, 'x');
    msg.back() = '\0';

    ASSERT_EQ(testSendMsg(clientSocketFD, msg.data()), CommRetval::SIZE_TOO_LONG);

    close(acceptSocketFD);
    close(clientSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(socketAuxiliarFunctions, DatagramSendLongMessageError)
{
    // Create server
    const int serverSocketFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(serverSocketFD, 0);

    // Connect client
    const int clientSocketFD = testSocketConnect(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(clientSocketFD, 0);

    std::vector<char> msg = {};
    msg.resize(MSG_MAX_SIZE + 2);
    std::fill(msg.begin(), msg.end() - 1, 'x');
    msg.back() = '\0';

    ASSERT_EQ(testSendMsg(clientSocketFD, msg.data(), false), CommRetval::SIZE_TOO_LONG);

    close(serverSocketFD);
    close(clientSocketFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}

TEST(socketAuxiliarFunctions, StreamSendEmptyMessageError)
{
    // Create server
    const int acceptSocketFD = testBindUnixSocket(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(acceptSocketFD, 0);

    // Connect client
    const int clientSocketFD = testSocketConnect(TEST_STREAM_SOCK_PATH, SOCK_STREAM);
    ASSERT_GT(clientSocketFD, 0);

    char msg[] = "";

    ASSERT_EQ(testSendMsg(clientSocketFD, msg), CommRetval::SIZE_ZERO);

    close(acceptSocketFD);
    close(clientSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(socketAuxiliarFunctions, DatagramSendEmptyMessageError)
{
    // Create server
    const int serverSocketFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(serverSocketFD, 0);

    // Connect client
    const int clientSocketFD = testSocketConnect(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(clientSocketFD, 0);

    char msg[] = "";

    ASSERT_EQ(testSendMsg(clientSocketFD, msg, false), CommRetval::SIZE_ZERO);

    close(serverSocketFD);
    close(clientSocketFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}

TEST(socketAuxiliarFunctions, SendInvalidSocketError)
{
    ASSERT_EQ(testSendMsg(0, TEST_SEND_MESSAGE.data()), CommRetval::INVALID_SOCKET);
    ASSERT_EQ(testSendMsg(-5, TEST_SEND_MESSAGE.data()), CommRetval::INVALID_SOCKET);
}

TEST(socketAuxiliarFunctions, SendWrongSocketFDError)
{
    ASSERT_EQ(testSendMsg(999, TEST_SEND_MESSAGE.data()),
              CommRetval::COMMUNICATION_ERROR);
}

TEST(socketAuxiliarFunctions, StreamSendMessage)
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

TEST(socketAuxiliarFunctions, DatagramSendMessage)
{
    // Create server
    const int serverSocketFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(serverSocketFD, 0);

    // Connect client
    const int clientSocketFD = testSocketConnect(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(clientSocketFD, 0);

    ASSERT_EQ(testSendMsg(clientSocketFD, TEST_SEND_MESSAGE.data(), false),
              CommRetval::SUCCESS);

    close(serverSocketFD);
    close(clientSocketFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}

TEST(socketAuxiliarFunctions, StreamRecvMessage)
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

    auto payload = testRecvString(clientSocketFD, SOCK_STREAM);
    ASSERT_STREQ(payload.data(), TEST_SEND_MESSAGE.data());

    close(acceptSocketFD);
    close(serverSocketFD);
    close(clientSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(socketAuxiliarFunctions, DatagramRecvMessage)
{

    // Create server
    const int serverSocketFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(serverSocketFD, 0);

    // Connect client
    const int clientSocketFD = testSocketConnect(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(clientSocketFD, 0);

    ASSERT_EQ(testSendMsg(clientSocketFD, TEST_SEND_MESSAGE.data(), false),
              CommRetval::SUCCESS);

    // Set-up sockaddr structure
    auto payload = testRecvString(serverSocketFD, SOCK_DGRAM);
    ASSERT_STREQ(payload.data(), TEST_SEND_MESSAGE.data());

    close(serverSocketFD);
    close(clientSocketFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}

TEST(socketAuxiliarFunctions, StreamSendRecvMessage)
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

    ASSERT_EQ(testSendMsg(clientSocketFD, TEST_SEND_MESSAGE.data()), CommRetval::SUCCESS);

    auto payload = testRecvString(serverSocketFD, SOCK_STREAM);
    ASSERT_STREQ(payload.c_str(), TEST_SEND_MESSAGE.data());

    ASSERT_EQ(testSendMsg(serverSocketFD, TEST_SEND_MESSAGE.data()), CommRetval::SUCCESS);

    payload = testRecvString(clientSocketFD, SOCK_STREAM);
    ASSERT_STREQ(payload.c_str(), TEST_SEND_MESSAGE.data());

    close(acceptSocketFD);
    close(clientSocketFD);
    close(serverSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(socketAuxiliarFunctions, StreamSendRecvLongestMessage)
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

    auto payload = testRecvString(serverSocketFD, SOCK_STREAM);
    ASSERT_STREQ(payload.c_str(), msg);
    ASSERT_EQ(strlen(payload.c_str()), MSG_MAX_SIZE);

    close(acceptSocketFD);
    close(clientSocketFD);
    close(serverSocketFD);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(socketAuxiliarFunctions, DatagramSendRecvLongestMessage)
{
    char msg[MSG_MAX_SIZE + 1] = {};
    memset(msg, 'x', MSG_MAX_SIZE);

    // Create server
    const int serverSocketFD = testBindUnixSocket(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(serverSocketFD, 0);

    // Connect client
    const int clientSocketFD = testSocketConnect(TEST_DGRAM_SOCK_PATH, SOCK_DGRAM);
    ASSERT_GT(clientSocketFD, 0);

    ASSERT_EQ(testSendMsg(clientSocketFD, msg, false), CommRetval::SUCCESS);

    auto payload = testRecvString(serverSocketFD, SOCK_DGRAM);
    ASSERT_STREQ(payload.c_str(), msg);
    ASSERT_EQ(strlen(payload.c_str()), MSG_MAX_SIZE);

    close(serverSocketFD);
    close(clientSocketFD);

    unlink(TEST_DGRAM_SOCK_PATH.data());
}

TEST(socketAuxiliarFunctions, StreamRemoteCloseBeforeSend)
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

TEST(socketAuxiliarFunctions, StreamRemoteCloseBeforeRcv)
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
            testRecvString(clientLocal, SOCK_STREAM);
        } catch (const std::runtime_error& e) {
            ASSERT_STREQ(e.what(), "recvMsg: socket disconnected.");
            throw;
        },
        std::runtime_error);

    close(serverSocketFD);
    close(clientLocal);

    unlink(TEST_STREAM_SOCK_PATH.data());
}

TEST(socketAuxiliarFunctions, StreamLocalSendremoteCloseBeforeRcv)
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

    ASSERT_THROW(testRecvString(clientLocal, SOCK_STREAM), std::runtime_error);
    ASSERT_EQ(errno, ECONNRESET);

    close(serverSocketFD);
    close(clientLocal);

    unlink(TEST_STREAM_SOCK_PATH.data());
}
