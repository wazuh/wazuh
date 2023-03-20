#include <thread>
#include <chrono>
#include <atomic>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <gtest/gtest.h>
#include <uvw.hpp>

#include <server/unixDatagram.hpp>

using namespace engineserver::endpoint;

class UnixDatagramTest : public ::testing::Test
{
protected:
    std::shared_ptr<uvw::Loop> loop;
    std::string socketPath = "/tmp/unix_datagram_test.sock";

    void SetUp() override
    {
        loop = uvw::Loop::create();
    }

    void TearDown() override
    {
        loop->close();
        unlink(socketPath.c_str());
    }

    int getSendFD(const std::string& path)
    {
        int sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (sockfd == -1)
        {
            perror("socket");
            exit(EXIT_FAILURE);
        }

        return sockfd;
    }

    int getSendBufSize(int fd) {
        int size = 0;
        socklen_t len = sizeof(size);
        if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, &len) == -1)
        {
            perror("getsockopt");
            exit(EXIT_FAILURE);
        }
        return size;
    }

    void sendUnixDatagram(int fd, const std::string& message) {
        struct sockaddr_un addr;

        memset(&addr, 0, sizeof(struct sockaddr_un));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path) - 1);

        if (sendto(fd, message.data(), message.size(), 0, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)) == -1)
        {
            perror("sendto");
            exit(EXIT_FAILURE);
        }
    }

    void sendUnixDatagram(const std::string& path, const std::string& message)
    {
        int sockfd = getSendFD(path);
        sendUnixDatagram(sockfd, message);
        close(sockfd);
    }


};

TEST_F(UnixDatagramTest, BindAndClose)
{
    UnixDatagram endpoint(socketPath, [](std::string&&) {});
    ASSERT_FALSE(endpoint.isBound());
    ASSERT_NO_THROW(endpoint.bind(loop));
    ASSERT_TRUE(endpoint.isBound());
    ASSERT_NO_THROW(endpoint.close());
    ASSERT_FALSE(endpoint.isBound());
}

TEST_F(UnixDatagramTest, PauseAndResume)
{
    UnixDatagram endpoint(socketPath, [](std::string&&) {});
    endpoint.bind(loop);
    ASSERT_TRUE(endpoint.resume());
    ASSERT_FALSE(endpoint.resume());
    ASSERT_TRUE(endpoint.pause());
    ASSERT_FALSE(endpoint.pause());
    endpoint.close();
}

TEST_F(UnixDatagramTest, ReceiveData)
{
    std::string receivedData;
    UnixDatagram endpoint(socketPath, [&](std::string&& data) { receivedData = std::move(data); });
    endpoint.bind(loop);
    endpoint.resume();

    std::string message = "Hello, Unix Datagram!";
    sendUnixDatagram(socketPath, message);

    loop->run<uvw::Loop::Mode::ONCE>();

    ASSERT_EQ(receivedData, message);
    endpoint.close();
}

TEST_F(UnixDatagramTest, PauseResumeReceiveData)
{
    std::atomic<bool> receivedData(false);
    UnixDatagram endpoint(socketPath, [&](std::string&& data) { receivedData = true; });
    endpoint.bind(loop);
    // Pause the endpoint and wait for some time
    endpoint.pause();

    std::string message = "Hello, Unix Datagram!";
    sendUnixDatagram(socketPath, message);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Run the loop once, data should not be received yet
    loop->run<uvw::Loop::Mode::ONCE>();
    ASSERT_FALSE(receivedData);

    // Resume the endpoint and wait for some time
    endpoint.resume();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Run the loop once, data should be received now
    loop->run<uvw::Loop::Mode::ONCE>();
    ASSERT_TRUE(receivedData);

    endpoint.close();
}

TEST_F(UnixDatagramTest, BufferOverflowTest)
{
    std::atomic<int> processedMessages(0);
    UnixDatagram endpoint(socketPath, [&](std::string&& data) { processedMessages++;});
    endpoint.bind(loop);
    endpoint.pause();

    const int RecvBufferSize = endpoint.getReciveBufferSize();
    const int messageSize = 128;
    const int numMessages = (RecvBufferSize / messageSize) * 2;

    std::atomic<bool> senderWaiting(false);
    std::thread senderThread(
        [this, messageSize, numMessages, &senderWaiting]()
        {
            int socketFD = getSendFD(socketPath);
            const int sendBufferSize = getSendBufSize(socketFD);
            for (int i = 0; i < numMessages; ++i)
            {
                std::string message(messageSize, 'A');
                senderWaiting = true;
                sendUnixDatagram(socketFD, message);
                senderWaiting = false;
            }
            close(socketFD);
        });

    // Attempt to receive data until the buffer is full
    const int maxAttempts = 500;
    int attempts = 0;


    // Sleep until the sender thread is waiting
    do
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        ASSERT_LE(attempts++, maxAttempts) << "Sender thread is not waiting for the buffer to be empty";
    } while (!senderWaiting && processedMessages > 0);

    // Resume the endpoint and wait for some time
    endpoint.resume();

    attempts = 0;
    while (processedMessages < numMessages)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        loop->run<uvw::Loop::Mode::ONCE>();
        ASSERT_LE(attempts++, maxAttempts) << "Not all messages were processed";
    }
    std::cout << "Attemps: " << attempts << std::endl;

    // Wait for the sender thread to finish
    senderThread.join();

}
