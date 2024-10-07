#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <mutex>
#include <thread>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <uvw.hpp>

#include <base/logging.hpp>
#include <base/mockSingletonManager.hpp>
#include <metrics/noOpManager.hpp>
#include <server/endpoints/unixDatagram.hpp>

using namespace engineserver::endpoint;

namespace
{
std::filesystem::path uniquePath()
{
    auto pid = getpid();
    auto tid = std::this_thread::get_id();
    std::stringstream ss;
    ss << pid << "_" << tid; // Unique path per thread and process
    return std::filesystem::path("/tmp") / (ss.str() + "_unixDatagram_test.sock");
}
} // namespace

class UnixDatagramTest : public ::testing::Test
{
protected:
    std::shared_ptr<uvw::Loop> loop;
    std::string socketPath;

    void SetUp() override
    {
        logging::testInit();
        socketPath = uniquePath().c_str();
        loop = uvw::Loop::create();
    }

    void TearDown() override
    {
        loop->close();
        unlink(socketPath.c_str());
    }

    static void SetUpTestSuite()
    {
        static metrics::mocks::NoOpManager mockManager;
        SingletonLocator::registerManager<metrics::IManager, base::test::MockSingletonManager<metrics::IManager>>();
        auto& mockStrategy = dynamic_cast<base::test::MockSingletonManager<metrics::IManager>&>(
            SingletonLocator::manager<metrics::IManager>());
        ON_CALL(mockStrategy, instance()).WillByDefault(testing::ReturnRef(mockManager));
        EXPECT_CALL(mockStrategy, instance()).Times(testing::AnyNumber());
    }

    static void TearDownTestSuite() { SingletonLocator::unregisterManager<metrics::IManager>(); }

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

    int getSendBufSize(int fd)
    {
        int size = 0;
        socklen_t len = sizeof(size);
        if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, &len) == -1)
        {
            perror("getsockopt");
            exit(EXIT_FAILURE);
        }
        return size;
    }

    void setSendBufSize(int fd, int size)
    {
        if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == -1)
        {
            perror("setsockopt");
            exit(EXIT_FAILURE);
        }
    }

    void sendUnixDatagram(int fd, const std::string& message)
    {
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
    UnixDatagram endpoint(socketPath, [](const std::string&) {});
    ASSERT_FALSE(endpoint.isBound());
    ASSERT_NO_THROW(endpoint.bind(loop));
    ASSERT_TRUE(endpoint.isBound());
    ASSERT_NO_THROW(endpoint.close());
    ASSERT_FALSE(endpoint.isBound());
}

TEST_F(UnixDatagramTest, PauseAndResume)
{
    UnixDatagram endpoint(socketPath, [](const std::string&) {});
    endpoint.bind(loop);
    ASSERT_TRUE(endpoint.pause());
    ASSERT_TRUE(endpoint.resume());
    ASSERT_FALSE(endpoint.resume());
    ASSERT_TRUE(endpoint.pause());
    ASSERT_FALSE(endpoint.pause());
    endpoint.close();
}

TEST_F(UnixDatagramTest, ReceiveData)
{
    std::string receivedData;
    UnixDatagram endpoint(socketPath, [&](const std::string& data) { receivedData = std::move(data); });
    endpoint.bind(loop);

    std::string message = "Hello, Unix Datagram!";
    sendUnixDatagram(socketPath, message);

    loop->run<uvw::Loop::Mode::ONCE>();

    ASSERT_EQ(receivedData, message);
    endpoint.close();
}

TEST_F(UnixDatagramTest, PauseResumeReceiveData)
{
    std::atomic<bool> receivedData(false);
    UnixDatagram endpoint(socketPath, [&](const std::string& data) { receivedData = true; });
    endpoint.bind(loop);
    // Pause the endpoint and wait for some time
    endpoint.pause();

    std::string message = "Hello, Unix Datagram!";
    sendUnixDatagram(socketPath, message);

    std::this_thread::sleep_for(std::chrono::milliseconds(1));

    // Run the loop once, data should not be received yet
    loop->run<uvw::Loop::Mode::ONCE>();
    ASSERT_FALSE(receivedData);

    // Resume the endpoint and wait for some time
    endpoint.resume();
    std::this_thread::sleep_for(std::chrono::milliseconds(1));

    // Run the loop once, data should be received now
    loop->run<uvw::Loop::Mode::ONCE>();
    ASSERT_TRUE(receivedData);

    endpoint.close();
}

TEST_F(UnixDatagramTest, taskQueueSizeTestAndOverflow)
{

    // Variables to block all the queue workers
    std::atomic<bool> enableBlockQueueWorkers = true;
    std::condition_variable BlockWokersCV;
    std::mutex BlockWokersMutex;

    // Queue of workers
    const std::size_t taskQueueSize = 16;
    const std::size_t numOfWorkers = 4;

    // Calculate the number of messages to send to block the queue workers
    const std::size_t numMessagesToSend =
        numOfWorkers + taskQueueSize; // 4 messages to block the 4 workers and the queue size to full the queue
    std::atomic<std::size_t> sendedMessages = 0;   // Number of messages sended
    std::atomic<std::size_t> processedMessages(0); // Number of messages processed
    std::atomic<bool> isClientBlocked = false;     // Flag to indicate that the client is blocked

    // Prepare the endpoint
    UnixDatagram endpoint(
        socketPath,
        [&, functionName = logging::getLambdaName(__FUNCTION__, "handleIncomingDataAndManageWorker")](
            const std::string& data)
        {
            if (enableBlockQueueWorkers)
            {

                std::ostringstream ss;
                ss << std::this_thread::get_id();
                std::string idstr = ss.str();

                LOG_INFO_L(functionName.c_str(), "Block the worker id: {}", idstr);
                // Block the worker
                std::unique_lock<std::mutex> lock(BlockWokersMutex);
                BlockWokersCV.wait(lock);
                LOG_INFO_L(functionName.c_str(), "Unblock the worker id: {}", idstr);
            }
            processedMessages++;
            LOG_INFO_L(functionName.c_str(),
                       "Processing message [{}]: {}",
                       static_cast<std::size_t>(processedMessages),
                       data.substr(0, 100).c_str());
        },
        taskQueueSize);

    ASSERT_NO_THROW(endpoint.bind(loop));
    ASSERT_TRUE(endpoint.isBound());

    // Prepare the loop stop handler
    auto stopHandler = loop->resource<uvw::AsyncHandle>();
    stopHandler->on<uvw::AsyncEvent>(
        [&, functionName = logging::getLambdaName(__FUNCTION__, "stopHandler")](const uvw::AsyncEvent&,
                                                                                uvw::AsyncHandle& handle)
        {
            LOG_INFO_L(functionName.c_str(), "Stopping the loop");
            handle.close();
            loop->walk([](auto& handle) { handle.close(); });
            loop->stop();
            loop->run<uvw::Loop::Mode::ONCE>();
        });
    // Prepare the loop thread
    std::thread loopThread(
        [&, functionName = logging::getLambdaName(__FUNCTION__, "loopThread")]()
        {
            loop->run<uvw::Loop::Mode::DEFAULT>();
            LOG_INFO_L(functionName.c_str(), "Loop thread finished");
        });

    // Prepare the sender thread
    const auto clientFD = getSendFD(socketPath);

    // Set the send buffer size to the same as the receive buffer size
    const auto recvBufferSize = endpoint.getReciveBufferSize();
    setSendBufSize(clientFD, recvBufferSize);

    std::thread senderThread(
        [clientFD,
         this,
         &sendedMessages,
         recvBufferSize,
         &isClientBlocked,
         functionName = logging::getLambdaName(__FUNCTION__, "sendThread")]()
        {
            for (std::size_t i = 0; i < numMessagesToSend; ++i)
            {
                std::string message = "Message " + std::to_string(i);
                LOG_INFO_L(functionName.c_str(),
                           "Sending message [{}]: {}",
                           static_cast<std::size_t>(sendedMessages),
                           message.substr(0, 100).c_str());
                sendUnixDatagram(clientFD, message);
                sendedMessages++;
            }
            // The queue is full, now fill the send buffer and resv buffer
            LOG_INFO_L(functionName.c_str(), "Queue is full");
            // Message to fill the recv buffer
            const auto fullRecvBufferMessage = std::string(recvBufferSize, 'B');
            sendUnixDatagram(clientFD, fullRecvBufferMessage);
            sendedMessages++;
            LOG_INFO_L(functionName.c_str(), "Recv buffer is full");
            // Message to fill the send buffer
            const auto fullBufferMessage = std::string(recvBufferSize, 'A');
            sendUnixDatagram(clientFD, fullBufferMessage);
            sendedMessages++;
            LOG_INFO_L(functionName.c_str(), "Send buffer is full");

            // Send a new message to block de client
            const auto blockMessage = std::string {"Blocked message"};
            LOG_INFO_L(functionName.c_str(), "Blocking client");
            isClientBlocked = true;
            sendUnixDatagram(clientFD, blockMessage);
            sendedMessages++;
            LOG_INFO_L(functionName.c_str(), "Client is unblocked");
            isClientBlocked = false;
        });

    // Wait for the sender thread to send all the messages
    const std::size_t maxAttempts = 500;
    std::size_t attempts = 0;
    while (sendedMessages < numMessagesToSend)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        ASSERT_LE(attempts++, maxAttempts) << "Queue is not full";
    }

    // Wait for the client to be blocked
    attempts = 0;
    while (!isClientBlocked)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        ASSERT_LE(attempts++, maxAttempts) << "Client is not blocked";
    }
    // Wait 10 milliseconds to be sure that the client is blocked and not only the send buffer is full
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    ASSERT_TRUE(isClientBlocked) << "Client is not blocked";

    // Unblock the queue workers
    enableBlockQueueWorkers = false;
    BlockWokersCV.notify_all();

    // Wait for the all the messages to be processed
    attempts = 0;
    // 3 messages to fill the send and recv buffers and the blocked message
    while (processedMessages < sendedMessages)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        ASSERT_LE(attempts++, maxAttempts)
            << "Not all messages were processed: " << processedMessages << " of " << sendedMessages;
    }

    // Close client
    close(clientFD);
    // Close the loop
    stopHandler->send();
    senderThread.join();
    loopThread.join();
}

TEST_F(UnixDatagramTest, StopWhenBufferIsFull)
{

    // Variables to block all the queue workers
    std::atomic<bool> enableBlockQueueWorkers = true;
    std::condition_variable BlockWokersCV;
    std::mutex BlockWokersMutex;

    // Queue of workers
    constexpr std::size_t taskQueueSize = 16;
    const std::size_t numOfWorkers = 4;

    // Calculate the number of messages to send to block the queue workers
    std::atomic<std::size_t> sendedMessages = 0;    // Number of messages sended
    std::atomic<std::size_t> processedMessages = 0; // Number of messages processed

    // Prepare the endpoint
    UnixDatagram endpoint(
        socketPath,
        [&, functionName = logging::getLambdaName(__FUNCTION__, "handleIncomingDataAndManageWorker")](
            const std::string& data)
        {
            if (enableBlockQueueWorkers)
            {

                std::ostringstream ss;
                ss << std::this_thread::get_id();
                std::string idstr = ss.str();

                LOG_INFO_L(functionName.c_str(), "Block the worker id: {}", idstr);
                // Block the worker
                std::unique_lock<std::mutex> lock(BlockWokersMutex);
                BlockWokersCV.wait(lock);
                LOG_INFO_L(functionName.c_str(), "Unblock the worker id: {}", idstr);
            }
            processedMessages++;
            LOG_INFO_L(functionName.c_str(),
                       "Processing message [{}]: {}",
                       static_cast<std::size_t>(processedMessages),
                       data.substr(0, 100).c_str());
        },
        taskQueueSize);

    ASSERT_NO_THROW(endpoint.bind(loop));
    ASSERT_TRUE(endpoint.isBound());

    // Prepare the loop stop handler
    auto stopHandler = loop->resource<uvw::AsyncHandle>();
    stopHandler->on<uvw::AsyncEvent>(
        [&, functionName = logging::getLambdaName(__FUNCTION__, "stopHanlder")](const uvw::AsyncEvent&,
                                                                                uvw::AsyncHandle& handle)
        {
            LOG_INFO_L(functionName.c_str(), "Stopping the loop");
            handle.close();
            loop->walk([](auto& handle) { handle.close(); });
            loop->stop();
            loop->run<uvw::Loop::Mode::ONCE>();
        });
    // Prepare the loop thread
    std::thread loopThread(
        [&, functionName = logging::getLambdaName(__FUNCTION__, "loopThread")]()
        {
            loop->run<uvw::Loop::Mode::DEFAULT>();
            LOG_INFO_L(functionName.c_str(), "Loop thread finished");
        });

    // Send messages to block the queue workers
    const auto clientFD = getSendFD(socketPath);
    for (std::size_t i = 0; i < taskQueueSize; ++i)
    {
        std::string message = "Message " + std::to_string(i);
        LOG_INFO("Sending message [{}]: {}", static_cast<std::size_t>(sendedMessages), message.substr(0, 100).c_str());
        sendUnixDatagram(clientFD, message);
        sendedMessages++;
    }
    LOG_INFO("Queue is full");
    std::this_thread::sleep_for(std::chrono::milliseconds(1));

    // Close the loop
    stopHandler->send();

    // Wait for the loop to be closed
    std::this_thread::sleep_for(std::chrono::milliseconds(1));

    // Unblock the queue workers
    enableBlockQueueWorkers = false;
    BlockWokersCV.notify_all();

    // Wait for the all the messages to be processed
    const auto maxAttempts = 500;
    auto attempts = 0;
    // 3 messages to fill the send and recv buffers and the blocked message
    while (processedMessages < sendedMessages)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        ASSERT_LE(attempts++, maxAttempts)
            << "Not all messages were processed: " << processedMessages << " of " << sendedMessages;
    }

    // Close client
    close(clientFD);
    loopThread.join();
}
