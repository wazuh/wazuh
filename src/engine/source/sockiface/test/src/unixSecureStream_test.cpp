#include <filesystem>
#include <iostream>
#include <unistd.h>

#include <gtest/gtest.h>

#include <sockiface/unixSecureStream.hpp>

#include "testAuxiliar/socketAuxiliarFunctions.hpp"

using namespace sockiface;

namespace
{
std::filesystem::path uniquePath()
{
    auto pid = getpid();
    auto tid = std::this_thread::get_id();
    std::stringstream ss;
    ss << pid << "_" << tid; // Unique path per thread and process
    return std::filesystem::path("/tmp") / (ss.str() + "_unixStream_test.sock");
}
} // namespace

class unixSecureStreamSocket : public ::testing::Test
{
protected:
    std::string m_streamSockPath;
    void SetUp() override
    {
        logging::testInit();
        m_streamSockPath = uniquePath().string();
    }
};

TEST_F(unixSecureStreamSocket, build)
{
    ASSERT_NO_THROW(unixSecureStream uStream(m_streamSockPath));
    ASSERT_NO_THROW(unixSecureStream uStream("qwertyuiop"));
}

TEST_F(unixSecureStreamSocket, SetMaxMsgSizeError)
{
    ASSERT_THROW({ unixSecureStream uStream(m_streamSockPath, 0); }, std::invalid_argument);

    ASSERT_THROW({ unixSecureStream uStream(m_streamSockPath, {}); }, std::invalid_argument);
}

TEST_F(unixSecureStreamSocket, GetMaxMsgSize)
{
    {
        unixSecureStream uStream(m_streamSockPath);
        ASSERT_EQ(uStream.getMaxMsgSize(), STREAM_MAX_MSG_SIZE);
    }

    {
        int setSize {99};
        unixSecureStream uStream(m_streamSockPath, setSize);
        ASSERT_EQ(uStream.getMaxMsgSize(), setSize);
    }

    {
        unixSecureStream uStream(m_streamSockPath);
        ASSERT_EQ(uStream.getMaxMsgSize(), STREAM_MAX_MSG_SIZE);
    }

    {
        int setSize {STREAM_MAX_MSG_SIZE + 1};
        unixSecureStream uStream(m_streamSockPath, setSize);
        ASSERT_EQ(uStream.getMaxMsgSize(), setSize);
    }
}

TEST_F(unixSecureStreamSocket, GetPath)
{
    unixSecureStream uStream(m_streamSockPath);
    ASSERT_NO_THROW(ASSERT_EQ(uStream.getPath(), m_streamSockPath););
}

TEST_F(unixSecureStreamSocket, ConnectErrorInvalidPath)
{
    {
        unixSecureStream uStream("/invalid/path");
        ASSERT_THROW(uStream.socketConnect(), std::runtime_error);
    }
    {
        unixSecureStream uStream(m_streamSockPath);
        ASSERT_THROW(uStream.socketConnect(), std::runtime_error);
    }
}

TEST_F(unixSecureStreamSocket, Connect)
{
    unixSecureStream uStream(m_streamSockPath);

    auto serverSocketFD {testBindUnixSocket(m_streamSockPath, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uStream.socketConnect());

    close(serverSocketFD);

    unlink(m_streamSockPath.data());
}

TEST_F(unixSecureStreamSocket, ConnectTwice)
{
    unixSecureStream uStream(m_streamSockPath);

    auto serverSocketFD {testBindUnixSocket(m_streamSockPath, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uStream.socketConnect());
    ASSERT_NO_THROW(uStream.socketConnect());

    close(serverSocketFD);

    unlink(m_streamSockPath.data());
}

TEST_F(unixSecureStreamSocket, Disconnect)
{
    unixSecureStream uStream(m_streamSockPath);
    ASSERT_NO_THROW(uStream.socketDisconnect());
}

TEST_F(unixSecureStreamSocket, ConnectAndDisconnect)
{
    unixSecureStream uStream(m_streamSockPath);

    auto serverSocketFD {testBindUnixSocket(m_streamSockPath, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uStream.socketConnect());
    ASSERT_NO_THROW(uStream.socketDisconnect());

    close(serverSocketFD);

    unlink(m_streamSockPath.data());
}

TEST_F(unixSecureStreamSocket, ConnectDisconnectConnect)
{
    unixSecureStream uStream(m_streamSockPath);

    auto serverSocketFD {testBindUnixSocket(m_streamSockPath, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uStream.socketConnect());
    ASSERT_NO_THROW(uStream.socketDisconnect());
    ASSERT_NO_THROW(uStream.socketConnect());

    close(serverSocketFD);

    unlink(m_streamSockPath.data());
}

TEST_F(unixSecureStreamSocket, isConnectedFalse)
{
    unixSecureStream uStream(m_streamSockPath);

    ASSERT_FALSE(uStream.isConnected());

    auto serverSocketFD {testBindUnixSocket(m_streamSockPath, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uStream.socketConnect());
    ASSERT_NO_THROW(uStream.socketDisconnect());

    ASSERT_FALSE(uStream.isConnected());

    close(serverSocketFD);

    unlink(m_streamSockPath.data());
}

TEST_F(unixSecureStreamSocket, isConnectedTrue)
{
    unixSecureStream uStream(m_streamSockPath);

    auto serverSocketFD {testBindUnixSocket(m_streamSockPath, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uStream.socketConnect());

    ASSERT_TRUE(uStream.isConnected());

    ASSERT_NO_THROW(uStream.socketDisconnect());
    ASSERT_NO_THROW(uStream.socketConnect());

    ASSERT_TRUE(uStream.isConnected());

    unlink(m_streamSockPath.data());
}

TEST_F(unixSecureStreamSocket, ErrorSendMessageNoSocket)
{
    unixSecureStream uStream(m_streamSockPath);
    ASSERT_THROW(uStream.sendMsg(TEST_SEND_MESSAGE.data());, std::runtime_error);
}

TEST_F(unixSecureStreamSocket, ErrorSendEmptyMessage)
{
    const char msg[] = "";

    unixSecureStream uStream(m_streamSockPath);

    auto serverSocketFD {testBindUnixSocket(m_streamSockPath, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(ASSERT_EQ(uStream.sendMsg(msg), ISockHandler::SendRetval::SIZE_ZERO));

    close(serverSocketFD);

    unlink(m_streamSockPath.data());
}

TEST_F(unixSecureStreamSocket, ErrorSendLongMessage)
{
    std::vector<char> msg {{}};
    msg.resize(STREAM_MAX_MSG_SIZE + 2);
    std::fill(msg.begin(), msg.end() - 1, 'x');
    msg.back() = '\0';

    unixSecureStream uStream(m_streamSockPath);

    auto serverSocketFD {testBindUnixSocket(m_streamSockPath, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(ASSERT_EQ(uStream.sendMsg(msg.data()), ISockHandler::SendRetval::SIZE_TOO_LONG));

    close(serverSocketFD);

    unlink(m_streamSockPath.data());
}

TEST_F(unixSecureStreamSocket, SendMessage)
{
    unixSecureStream uStream(m_streamSockPath);

    auto acceptSocketFd {testBindUnixSocket(m_streamSockPath, SOCK_STREAM)};
    ASSERT_GT(acceptSocketFd, 0);

    ASSERT_NO_THROW(uStream.socketConnect());

    auto serverSocketFD {testAcceptConnection(acceptSocketFd)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uStream.sendMsg(TEST_SEND_MESSAGE.data()));
    ASSERT_NO_THROW(ASSERT_STREQ(testRecvString(serverSocketFD, SOCK_STREAM).data(), TEST_SEND_MESSAGE.data()));

    close(acceptSocketFd);
    close(serverSocketFD);

    unlink(m_streamSockPath.data());
}

TEST_F(unixSecureStreamSocket, SendMessageDisconnected)
{
    unixSecureStream uStream(m_streamSockPath);

    auto acceptSocketFd {testBindUnixSocket(m_streamSockPath, SOCK_STREAM)};
    ASSERT_GT(acceptSocketFd, 0);

    ASSERT_NO_THROW(uStream.sendMsg(TEST_SEND_MESSAGE.data()));

    auto serverSocketFD {testAcceptConnection(acceptSocketFd)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(ASSERT_STREQ(testRecvString(serverSocketFD, SOCK_STREAM).data(), TEST_SEND_MESSAGE.data()));

    close(acceptSocketFd);
    close(serverSocketFD);

    unlink(m_streamSockPath.data());
}

TEST_F(unixSecureStreamSocket, ReceiveMessage)
{
    unixSecureStream uStream(m_streamSockPath);

    auto acceptSocketFd {testBindUnixSocket(m_streamSockPath, SOCK_STREAM)};
    ASSERT_GT(acceptSocketFd, 0);

    ASSERT_NO_THROW(uStream.socketConnect());

    auto serverSocketFD {testAcceptConnection(acceptSocketFd)};
    ASSERT_GT(serverSocketFD, 0);

    auto commRetval {testSendMsg(serverSocketFD, TEST_SEND_MESSAGE.data())};
    ASSERT_EQ(commRetval, CommRetval::SUCCESS);

    auto receivedMessage {uStream.recvString()};
    ASSERT_STREQ(receivedMessage.data(), TEST_SEND_MESSAGE.data());

    close(acceptSocketFd);
    close(serverSocketFD);

    unlink(m_streamSockPath.data());
}

TEST_F(unixSecureStreamSocket, SendAndReceiveMessage)
{
    unixSecureStream uStream(m_streamSockPath);

    auto acceptSocketFd {testBindUnixSocket(m_streamSockPath, SOCK_STREAM)};
    ASSERT_GT(acceptSocketFd, 0);

    ASSERT_NO_THROW(uStream.socketConnect());

    auto serverSocketFD {testAcceptConnection(acceptSocketFd)};
    ASSERT_GT(serverSocketFD, 0);

    uStream.sendMsg(TEST_SEND_MESSAGE.data());

    auto serverRcvMsg {testRecvString(serverSocketFD, SOCK_STREAM)};
    ASSERT_STREQ(serverRcvMsg.data(), TEST_SEND_MESSAGE.data());

    auto commRetval {testSendMsg(serverSocketFD, TEST_SEND_MESSAGE.data())};
    ASSERT_EQ(commRetval, CommRetval::SUCCESS);

    auto clientRcvMsg {uStream.recvMsg()};
    ASSERT_STREQ(clientRcvMsg.data(), TEST_SEND_MESSAGE.data());

    close(acceptSocketFd);
    close(serverSocketFD);

    unlink(m_streamSockPath.data());
}

TEST_F(unixSecureStreamSocket, SendLongestMessage)
{
    unixSecureStream uStream(m_streamSockPath);

    char msg[uStream.getMaxMsgSize() + 1] {};
    memset(msg, 'x', uStream.getMaxMsgSize());

    // Create server
    const int acceptSocketFD {testBindUnixSocket(m_streamSockPath, SOCK_STREAM)};
    ASSERT_GT(acceptSocketFD, 0);

    // Connect client
    ASSERT_NO_THROW(uStream.socketConnect());

    const int serverSocketFD {testAcceptConnection(acceptSocketFD)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_EQ(uStream.sendMsg(msg), ISockHandler::SendRetval::SUCCESS);

    auto payload {testRecvString(serverSocketFD, SOCK_STREAM)};
    ASSERT_EQ(strlen(payload.c_str()), uStream.getMaxMsgSize());
    ASSERT_STREQ(payload.c_str(), msg);

    close(acceptSocketFD);
    close(serverSocketFD);

    unlink(m_streamSockPath.data());
}

TEST_F(unixSecureStreamSocket, RemoteCloseBeforeSend)
{
    unixSecureStream uStream(m_streamSockPath);

    // Create server
    const int serverSocketFD {testBindUnixSocket(m_streamSockPath, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    // Connect client
    ASSERT_NO_THROW(uStream.socketConnect());

    // Accept connection
    const int clientRemote {testAcceptConnection(serverSocketFD)};
    ASSERT_GT(clientRemote, 0);

    // close remote before send
    close(clientRemote);

    ASSERT_THROW(uStream.sendMsg(TEST_SEND_MESSAGE.data()), std::runtime_error);

    // Broken pipe
    ASSERT_EQ(errno, EPIPE);

    close(serverSocketFD);

    unlink(m_streamSockPath.data());
}

TEST_F(unixSecureStreamSocket, RemoteCloseBeforeRcv)
{
    unixSecureStream uStream(m_streamSockPath);

    // Create server
    const int serverSocketFD {testBindUnixSocket(m_streamSockPath, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    // Connect client
    ASSERT_NO_THROW(uStream.socketConnect());

    // Accept connection
    const int clientRemote {testAcceptConnection(serverSocketFD)};
    ASSERT_GT(clientRemote, 0);

    // close remote before recv
    close(clientRemote);

    // gracefully closed
    ASSERT_THROW(
        try { uStream.recvMsg(); } catch (const std::runtime_error& e) {
            ASSERT_STREQ(e.what(),
                         "Engine Unix Stream socket utils: recvMsg(): Socket "
                         "disconnected.");
            throw;
        },
        std::runtime_error);

    close(serverSocketFD);

    unlink(m_streamSockPath.data());
}

TEST_F(unixSecureStreamSocket, LocalSendremoteCloseBeforeRcv)
{
    unixSecureStream uStream(m_streamSockPath);

    // Create server
    const int serverSocketFD {testBindUnixSocket(m_streamSockPath, SOCK_STREAM)};
    ASSERT_GT(serverSocketFD, 0);

    // Connect client
    ASSERT_NO_THROW(uStream.socketConnect());

    // Accept connection
    const int clientRemote {testAcceptConnection(serverSocketFD)};
    ASSERT_GT(clientRemote, 0);

    // Send to remote
    ASSERT_EQ(uStream.sendMsg(TEST_SEND_MESSAGE.data()), ISockHandler::SendRetval::SUCCESS);
    // Remote dont read and close the socket
    close(clientRemote);

    ASSERT_THROW(uStream.recvMsg(), std::runtime_error);
    ASSERT_EQ(errno, ECONNRESET);

    close(serverSocketFD);

    unlink(m_streamSockPath.data());
}
