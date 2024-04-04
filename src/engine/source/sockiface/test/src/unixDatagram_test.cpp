#include <iostream>
#include <sys/un.h>
#include <filesystem>

#include <gtest/gtest.h>

#include <sockiface/unixDatagram.hpp>

#include "testAuxiliar/socketAuxiliarFunctions.hpp"

using namespace sockiface;

std::filesystem::path uniquePath() {
    auto pid = getpid();
    auto tid = std::this_thread::get_id();
    std::stringstream ss;
    ss << pid << "_" << tid; // Unique path per thread and process
    return std::filesystem::path ("/tmp") / (ss.str() + "_unixDatagram_test.sock");
}


class unixDatagramSocket : public ::testing::Test
{
protected:
    std::string m_datagramSockPath;
    void SetUp() override
    {
        logging::testInit();

        m_datagramSockPath = uniquePath().string();
    }

    void TearDown() override {}
};

TEST_F(unixDatagramSocket, build)
{
    ASSERT_NO_THROW(unixDatagram uDgram(m_datagramSockPath));
    ASSERT_NO_THROW(unixDatagram uDgram("qwertyuiop"));
}

TEST_F(unixDatagramSocket, SetMaxMsgSizeError)
{
    ASSERT_THROW({ unixDatagram uDgram(m_datagramSockPath, 0); }, std::invalid_argument);

    ASSERT_THROW({ unixDatagram uDgram(m_datagramSockPath, {}); }, std::invalid_argument);
}

TEST_F(unixDatagramSocket, GetMaxMsgSize)
{
    {
        unixDatagram uDgram(m_datagramSockPath);
        ASSERT_NO_THROW(ASSERT_EQ(uDgram.getMaxMsgSize(), DATAGRAM_MAX_MSG_SIZE));
    };

    {
        int setSize {99};
        unixDatagram uDgram(m_datagramSockPath, setSize);
        ASSERT_NO_THROW(ASSERT_EQ(uDgram.getMaxMsgSize(), setSize));
    };

    {
        unixDatagram uDgram(m_datagramSockPath);
        ASSERT_NO_THROW(ASSERT_EQ(uDgram.getMaxMsgSize(), DATAGRAM_MAX_MSG_SIZE));
    };

    {
        int setSize {DATAGRAM_MAX_MSG_SIZE + 1};
        unixDatagram uDgram(m_datagramSockPath, setSize);
        ASSERT_NO_THROW(ASSERT_EQ(uDgram.getMaxMsgSize(), setSize));
    };
}

TEST_F(unixDatagramSocket, GetPath)
{
    unixDatagram uDgram(m_datagramSockPath);
    ASSERT_NO_THROW(ASSERT_EQ(uDgram.getPath(), m_datagramSockPath););
}

TEST_F(unixDatagramSocket, ConnectErrorInvalidPath)
{
    {
        unixDatagram uDgram("/invalid/path");
        ASSERT_THROW(uDgram.socketConnect(), std::runtime_error);
    }
    {
        unixDatagram uDgram(m_datagramSockPath);
        ASSERT_THROW(uDgram.socketConnect(), std::runtime_error);
    }
}

TEST_F(unixDatagramSocket, Connect)
{
    unixDatagram uDgram(m_datagramSockPath);

    auto serverSocketFD {testBindUnixSocket(m_datagramSockPath, SOCK_DGRAM)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uDgram.socketConnect());

    close(serverSocketFD);

    unlink(m_datagramSockPath.c_str());
}

TEST_F(unixDatagramSocket, ConnectTwice)
{
    unixDatagram uDgram(m_datagramSockPath);

    auto serverSocketFD {testBindUnixSocket(m_datagramSockPath, SOCK_DGRAM)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uDgram.socketConnect());
    ASSERT_NO_THROW(uDgram.socketConnect());

    close(serverSocketFD);

    unlink(m_datagramSockPath.c_str());
}

TEST_F(unixDatagramSocket, Disconnect)
{
    unixDatagram uDgram(m_datagramSockPath);
    ASSERT_NO_THROW(uDgram.socketDisconnect());
}

TEST_F(unixDatagramSocket, ConnectAndDisconnect)
{
    unixDatagram uDgram(m_datagramSockPath);

    auto serverSocketFD {testBindUnixSocket(m_datagramSockPath, SOCK_DGRAM)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uDgram.socketConnect());
    ASSERT_NO_THROW(uDgram.socketDisconnect());

    close(serverSocketFD);

    unlink(m_datagramSockPath.c_str());
}

TEST_F(unixDatagramSocket, ConnectDisconnectConnect)
{
    unixDatagram uDgram(m_datagramSockPath);

    auto serverSocketFD {testBindUnixSocket(m_datagramSockPath, SOCK_DGRAM)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uDgram.socketConnect());
    ASSERT_NO_THROW(uDgram.socketDisconnect());
    ASSERT_NO_THROW(uDgram.socketConnect());

    close(serverSocketFD);

    unlink(m_datagramSockPath.c_str());
}

TEST_F(unixDatagramSocket, isConnectedFalse)
{

    unixDatagram uDgram(m_datagramSockPath);

    ASSERT_FALSE(uDgram.isConnected());

    auto serverSocketFD {testBindUnixSocket(m_datagramSockPath, SOCK_DGRAM)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uDgram.socketConnect());
    ASSERT_NO_THROW(uDgram.socketDisconnect());

    ASSERT_FALSE(uDgram.isConnected());

    close(serverSocketFD);

    unlink(m_datagramSockPath.c_str());
}

TEST_F(unixDatagramSocket, isConnectedTrue)
{
    unixDatagram uDgram(m_datagramSockPath);

    auto serverSocketFD {testBindUnixSocket(m_datagramSockPath, SOCK_DGRAM)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uDgram.socketConnect());

    ASSERT_TRUE(uDgram.isConnected());

    ASSERT_NO_THROW(uDgram.socketDisconnect());
    ASSERT_NO_THROW(uDgram.socketConnect());

    ASSERT_TRUE(uDgram.isConnected());

    close(serverSocketFD);

    unlink(m_datagramSockPath.c_str());
}

TEST_F(unixDatagramSocket, ErrorSendMessageNoSocket)
{
    unixDatagram uDgram(m_datagramSockPath);
    ASSERT_THROW(uDgram.sendMsg(TEST_SEND_MESSAGE.data()), std::runtime_error);
}

TEST_F(unixDatagramSocket, ErrorSendEmptyMessage)
{
    const char msg[] = "";

    unixDatagram uDgram(m_datagramSockPath);

    auto serverSocketFD {testBindUnixSocket(m_datagramSockPath, SOCK_DGRAM)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(ASSERT_EQ(uDgram.sendMsg(msg), ISockHandler::SendRetval::SIZE_ZERO));

    close(serverSocketFD);

    unlink(m_datagramSockPath.c_str());
}

TEST_F(unixDatagramSocket, ErrorSendLongMessage)
{
    std::vector<char> msg {{}};
    msg.resize(DATAGRAM_MAX_MSG_SIZE + 2);
    std::fill(msg.begin(), msg.end() - 1, 'x');
    msg.back() = '\0';

    unixDatagram uDgram(m_datagramSockPath);

    auto serverSocketFD {testBindUnixSocket(m_datagramSockPath, SOCK_DGRAM)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(ASSERT_EQ(uDgram.sendMsg(msg.data()), ISockHandler::SendRetval::SIZE_TOO_LONG));

    close(serverSocketFD);

    unlink(m_datagramSockPath.c_str());
}

TEST_F(unixDatagramSocket, SendMessage)
{
    unixDatagram uDgram(m_datagramSockPath);

    auto serverSocketFD {testBindUnixSocket(m_datagramSockPath, SOCK_DGRAM)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uDgram.socketConnect());

    ASSERT_NO_THROW(uDgram.sendMsg(TEST_SEND_MESSAGE.data()));

    ASSERT_STREQ(testRecvString(serverSocketFD, SOCK_DGRAM).data(), TEST_SEND_MESSAGE.data());

    close(serverSocketFD);

    unlink(m_datagramSockPath.c_str());
}

TEST_F(unixDatagramSocket, SendMessageDisconnected)
{
    unixDatagram uDgram(m_datagramSockPath);

    auto serverSocketFD {testBindUnixSocket(m_datagramSockPath, SOCK_DGRAM)};
    ASSERT_GT(serverSocketFD, 0);

    ASSERT_NO_THROW(uDgram.sendMsg(TEST_SEND_MESSAGE.data()));

    ASSERT_STREQ(testRecvString(serverSocketFD, SOCK_DGRAM).data(), TEST_SEND_MESSAGE.data());

    close(serverSocketFD);

    unlink(m_datagramSockPath.c_str());
}
