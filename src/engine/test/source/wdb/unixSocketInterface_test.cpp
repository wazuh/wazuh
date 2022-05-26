#include "unixSocketInterface.hpp"

#include <iostream>

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <gtest/gtest.h>

using namespace socketinterface;

constexpr int MAX_BUFFER_SIZE = 1024;
constexpr int MESSAGE_HEADER_SIZE = sizeof(uint32_t);
constexpr std::string_view TEST_SEND_MESSAGE = "Test message to be send!\n";
constexpr std::string_view TEST_SOCKET_PATH = "/tmp/test.sock";

/**
 * @brief Test auxiliar function to bind a datagram UNIX socket
 *
 * @param path Socket pathname
 * @return int Socket file descriptor
 */
static int testBindUnixSocket(std::string_view path)
{
    int sockFD = 0;
    struct sockaddr_un n_us;

    /* Make sure the path isn't there */
    unlink(path.data());

    memset(&n_us, 0, sizeof(n_us));
    n_us.sun_family = AF_UNIX;
    strncpy(n_us.sun_path, path.data(), sizeof(n_us.sun_path) - 1);

    if ((sockFD = socket(PF_UNIX, SOCK_STREAM, 0)) < 0)
    {
        return (-1);
    }

    if (bind(sockFD, (struct sockaddr*)&n_us, SUN_LEN(&n_us)) < 0)
    {
        close(sockFD);
        return (-1);
    }

    /* Change permissions */
    if (chmod(path.data(), 0660) < 0)
    {
        close(sockFD);
        return (-1);
    }

    if (listen(sockFD, 1) < 0)
    {
        close(sockFD);
        return (-1);
    }

    return (sockFD);
}

/**
 * @brief Test auxiliar function to accept the socket connections
 *
 * @param serverSocketFD File descriptor of the connection socket
 * @return int File descriptor of the client socket
 */
static int testAcceptConnection(const int serverSocketFD)
{
    struct sockaddr_in _nc;
    memset(&_nc, 0, sizeof(_nc));
    socklen_t _ncl = sizeof(_nc);

    const int clientSocketFD = accept(serverSocketFD, (struct sockaddr*)&_nc, &_ncl);
    if (clientSocketFD < 0)
    {
        return (-1);
    }

    return (clientSocketFD);
}

// TESTS SECTION

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

    ASSERT_THROW(recvString(clientLocal), RecoverableError);

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

    close(serverSocketFD);
    close(clientLocal);

    unlink(TEST_SOCKET_PATH.data());
}
