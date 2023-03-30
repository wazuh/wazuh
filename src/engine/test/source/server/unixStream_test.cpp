#include <chrono>
#include <cstring>
#include <memory>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <tuple>
#include <typeinfo>
#include <unistd.h>

#include <gtest/gtest.h>
#include <logging/logging.hpp>
#include <condition_variable>
#include <uvw.hpp>

#include <server/protocolHandler.hpp>
#include <server/unixStream.hpp>

using namespace engineserver;
using namespace engineserver::endpoint;
using SharedCounter = std::shared_ptr<std::atomic<std::size_t>>;

class TestProtocolHandler : public ProtocolHandler
{
private:
    SharedCounter m_processedMessages;
    std::string m_buffer;
    std::shared_ptr<std::atomic<bool>> enableBlockQueueWorkers;
    std::shared_ptr<std::condition_variable> BlockWokersCV;
    std::shared_ptr<std::mutex> BlockWokersMutex;


public:
    TestProtocolHandler(SharedCounter processedMessages,
                        std::shared_ptr<std::atomic<bool>> enableBlockQueueWorkers,
                        std::shared_ptr<std::condition_variable> BlockWokersCV,
                        std::shared_ptr<std::mutex> BlockWokersMutex)
        : m_processedMessages(processedMessages)
        , m_buffer()
        , enableBlockQueueWorkers(enableBlockQueueWorkers)
        , BlockWokersCV(BlockWokersCV)
        , BlockWokersMutex(BlockWokersMutex)
    {
    }

    // Separete the data by <END> and return a vector of messages without <END>
    std::optional<std::vector<std::string>> onData(std::string_view _data) override
    {
        std::string data = std::string(_data);
        // If there is data from last time, add it to the new data
        if (!m_buffer.empty())
        {
            data = m_buffer + data;
            m_buffer.clear();
        }
        // Split the data by <END> and return a vector of messages
        std::vector<std::string> messages;
        std::string message;
        std::string_view delimiter = "<END>";
        std::size_t pos = 0;
        while ((pos = data.find(delimiter)) != std::string::npos)
        {
            pos = pos + delimiter.length();
            message = data.substr(0, pos);
            messages.push_back(message);
            data.erase(0, pos);
        }
        // If there is no <END> on end of data, save it for next time
        if (!data.empty())
        {
            m_buffer = data;
        }

        return messages;

    }

    // Loopback
    std::string onMessage(const std::string& message) override {
        if (*enableBlockQueueWorkers)
        {

            std::ostringstream ss;
            ss << std::this_thread::get_id();
            std::string idstr = ss.str();

            WAZUH_LOG_INFO("Block the worker id: {}", idstr);
            // Block the worker
            std::unique_lock<std::mutex> lock(*BlockWokersMutex);
            BlockWokersCV->wait(lock);
            WAZUH_LOG_INFO("Unblock the worker id: {}", idstr);
        }
        (*m_processedMessages)++;

        return message;
    }

    // Do nothing
    std::tuple<std::unique_ptr<char[]>, std::size_t> streamToSend(std::shared_ptr<std::string> message) override
    {
        std::unique_ptr<char[]> buffer(new char[message->size()]);
        std::copy(message->begin(), message->end(), buffer.get());
        return std::make_tuple(std::move(buffer), message->size());
    }

    std::tuple<std::unique_ptr<char[]>, std::size_t> getBusyResponse() override
    {
        auto busyMessage = std::make_shared<std::string>("Server is busy");
        return streamToSend(busyMessage);
    }

    std::string getErrorResponse() override { return "Error Response"; }

    ~TestProtocolHandler() override = default;
};

class TestProtocolHandlerFactory : public ProtocolHandlerFactory
{
public:

    // Variables to block all the queue workers
    std::shared_ptr<std::atomic<bool>> enableBlockQueueWorkers;
    std::shared_ptr<std::condition_variable> BlockWokersCV;
    std::shared_ptr<std::mutex> BlockWokersMutex;


    SharedCounter m_processedMessages;
    SharedCounter m_totalConexions;
    TestProtocolHandlerFactory(SharedCounter processedMessages, SharedCounter conexions)
        : m_processedMessages(processedMessages)
        , m_totalConexions(conexions)
         {
            enableBlockQueueWorkers = std::make_shared<std::atomic<bool>>(false);
            BlockWokersCV = std::make_shared<std::condition_variable>();
            BlockWokersMutex = std::make_shared<std::mutex>();
         };
    std::shared_ptr<ProtocolHandler> create() override
    {
            auto result = std::make_shared<TestProtocolHandler>(
                m_processedMessages, enableBlockQueueWorkers, BlockWokersCV, BlockWokersMutex);
            (*m_totalConexions)++;
            return result;
    }
};

class UnixStreamTest : public ::testing::Test
{
protected:
    std::shared_ptr<uvw::Loop> m_loop;
    std::shared_ptr<TestProtocolHandlerFactory> m_factory;
    std::string m_socketPath;

    void SetUp() override
    {
        m_loop = uvw::Loop::getDefault();
        SharedCounter m_proccessdMessages = std::make_shared<std::atomic<std::size_t>>(0);
        SharedCounter m_conexions = std::make_shared<std::atomic<std::size_t>>(0);
        m_factory = std::make_shared<TestProtocolHandlerFactory>(m_proccessdMessages, m_conexions);
        m_socketPath = "/tmp/unix_stream_test.sock";
    }

    void TearDown() override { unlink(m_socketPath.c_str()); }
};


// Helper function to create and connect a Unix domain socket client
int createUnixSocketClient(const std::string& m_socketPath)
{
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        throw std::runtime_error("Failed to create Unix socket");
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, m_socketPath.c_str(), sizeof(addr.sun_path) - 1);

    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1)
    {
        close(sockfd);
        throw std::runtime_error("Failed to connect Unix socket");
    }

    return sockfd;
}

std::tuple<std::shared_ptr<uvw::AsyncHandle>, std::thread> startLoopThread(std::shared_ptr<uvw::Loop> m_loop)
{

    // Prepare the loop stop handler
    auto stopHandler = m_loop->resource<uvw::AsyncHandle>();
    stopHandler->on<uvw::AsyncEvent>(
        [m_loop](const uvw::AsyncEvent&, uvw::AsyncHandle& handle)
        {
            WAZUH_LOG_INFO("Stopping the loop");
            handle.close();
            m_loop->walk([](auto& handle) { handle.close(); });
            m_loop->stop();
            m_loop->run<uvw::Loop::Mode::ONCE>();
        });
    // Prepare the loop thread
    std::thread loopThread(
        [m_loop]()
        {
            m_loop->run<uvw::Loop::Mode::DEFAULT>();
            WAZUH_LOG_INFO("Loop thread finished");
        });

    return {stopHandler, std::move(loopThread)};
}

TEST_F(UnixStreamTest, BindAndClose)
{
    UnixStream server(m_socketPath, m_factory);
    server.bind(m_loop);
    server.close();
    m_loop->run();
}


TEST_F(UnixStreamTest, EchoMessage)
{
    // Configure UnixStream server
    UnixStream server(m_socketPath, m_factory);
    server.bind(m_loop);
    auto [stopHandler, thread] = startLoopThread(m_loop);

    // Create and connect Unix domain socket client
    // auto& processedMessages = ;
    int clientSockfd = createUnixSocketClient(m_socketPath);

    std::string message = "Hello, World!<END>";
    auto res = send(clientSockfd, message.c_str(), message.size(), 0);
    ASSERT_EQ(res, message.size());

    const auto maxAttempts = 10;
    auto attempts = 0;
    while (*(m_factory->m_processedMessages) == 0)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        ASSERT_LT(attempts++, maxAttempts) << "Message not processed";
    }

    char buffer[1024] = {};
    ssize_t received = recv(clientSockfd, buffer, sizeof(buffer), 0);
    ASSERT_GT(received, 0);

    std::string response(buffer, received);
    ASSERT_EQ(message, response);

    close(clientSockfd);
    server.close();
    stopHandler->send();

    thread.join();
}

TEST_F(UnixStreamTest, MultipleEchoMessages)
{
    // Configure UnixStream server
    UnixStream server(m_socketPath, m_factory);
    server.bind(m_loop);
    auto [stopHandler, thread] = startLoopThread(m_loop);

    // Create and connect Unix domain socket client
    int clientSockfd = createUnixSocketClient(m_socketPath);

    std::vector<std::string> messages = {
        "Hello, World!<END>", "Test message 1<END>", "Test message 2<END>", "Test message 3<END>"};
    std::size_t totalSize = 0;

    for (const auto& message : messages)
    {
        auto res = send(clientSockfd, message.c_str(), message.size(), 0);
        ASSERT_EQ(res, message.size());
        totalSize += message.size();
    }

    const auto maxAttempts = 10;
    auto attempts = 0;
    while (*(m_factory->m_processedMessages) < messages.size())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        ASSERT_LT(attempts++, maxAttempts) << "Messages not processed";
    }

    // Read the responses from the client
    std::string response {};
    response.reserve(totalSize);
    attempts = 0;
    auto totalReceived = 0;
    while (response.length() < totalSize) {
        ASSERT_LT(attempts++, maxAttempts) << "Messages not received from client";
        char buffer[1024] = {};
        // Non-blocking read
        ssize_t received = recv(clientSockfd, buffer, sizeof(buffer), MSG_DONTWAIT);
        if (received == 0)
        {
            // Connection closed
            FAIL() << "Connection closed";
        }
        if (received == -1)
        {
            // No data available
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        ASSERT_GT(received, 0);
        response.append(buffer, received);
    };

    // Check the responses
    std::size_t offset = 0;
    for (const auto& message : messages)
    {
        ASSERT_EQ(message, response.substr(offset, message.size()));
        offset += message.size();
    }

    close(clientSockfd);
    server.close();
    stopHandler->send();
    thread.join();
}

TEST_F(UnixStreamTest, MultipleConnections)
{
    // Configure UnixStream server
    UnixStream server(m_socketPath, m_factory);
    server.bind(m_loop);
    auto [stopHandler, thread] = startLoopThread(m_loop);

    // Create and connect multiple Unix domain socket clients
    int numClients = 5;
    std::vector<int> clientSockets;
    std::vector<std::string> messages;
    for (int i = 0; i < numClients; ++i)
    {
        clientSockets.push_back(createUnixSocketClient(m_socketPath));
        std::string message = "Hello, World! client-> ";
        message += std::to_string(i);
        message += "<END>";
        messages.push_back(std::move(message));
    }

    // Send messages to the server
    for (int i = 0; i < numClients; ++i)
    {
        auto res = send(clientSockets[i], messages[i].c_str(), messages[i].size(), 0);
        ASSERT_EQ(res, messages[i].size());
    }

    const auto maxAttempts = 10;
    auto attempts = 0;
    while (*(m_factory->m_totalConexions) < numClients)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        ASSERT_LT(attempts++, maxAttempts) << "Messages not processed";
    }

    // Read the responses from the clients
    std::vector<std::string> responses;
    responses.reserve(numClients);
    attempts = 0;
    while (responses.size() < numClients)
    {
        ASSERT_LT(attempts++, maxAttempts) << "Messages not received from client";
        for (int i = 0; i < numClients; ++i)
        {
            char buffer[1024] = {};
            // Non-blocking read
            ssize_t received = recv(clientSockets[i], buffer, sizeof(buffer), MSG_DONTWAIT);
            if (received == 0)
            {
                // Connection closed
                FAIL() << "Connection closed";
            }
            if (received == -1)
            {
                // No data available
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }
            ASSERT_GT(received, 0);
            responses.push_back(std::string(buffer, received));
        }
    };

    // Check the responses
    for (int i = 0; i < numClients; ++i)
    {
        ASSERT_EQ(messages[i], responses[i]);
    }

    server.close();
    stopHandler->send();
    thread.join();
}



TEST_F(UnixStreamTest, QueueWorker_SameClient)
{

    // Queue of workers
    const std::size_t taskQueueSize = 16;

    // Configure UnixStream server
    UnixStream server(m_socketPath, m_factory, taskQueueSize);
    server.bind(m_loop);
    auto [stopHandler, thread] = startLoopThread(m_loop);
    const auto maxAttempts = 10;

    // Create and connect Unix domain socket client
    int clientSockfd = createUnixSocketClient(m_socketPath);

    // Send messages taskQueueSize messages to the server
    std::string expectedResponse {};
    for (std::size_t i = 0; i < taskQueueSize; ++i)
    {
        std::string message = "Hello, World! ";
        message += std::to_string(i);
        message += "<END>";
        auto res = send(clientSockfd, message.c_str(), message.size(), 0);
        ASSERT_EQ(res, message.size());
        expectedResponse += message;
    }

    // Wait for the messages to be processed
    auto attempts = 0;
    while (*(m_factory->m_processedMessages) < taskQueueSize)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        ASSERT_LT(attempts++, maxAttempts) << "Messages not processed";
    }

    // Read the responses from the client
    std::string response {};
    attempts = 0;

    while (response.length() < expectedResponse.length())
    {
        ASSERT_LT(attempts++, maxAttempts) << "Messages not received from client";
        char buffer[1024] = {};
        // Non-blocking read
        ssize_t received = recv(clientSockfd, buffer, sizeof(buffer), MSG_DONTWAIT);
        if (received == 0)
        {
            // Connection closed
            FAIL() << "Connection closed";
        }
        if (received == -1)
        {
            // No data available
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        ASSERT_GT(received, 0);
        response.append(buffer, received);
    };

    // Check the responses (order is not guaranteed, so we check the length)
    ASSERT_EQ(expectedResponse.length(), response.length());

    server.close();
    stopHandler->send();
    thread.join();
}

TEST_F(UnixStreamTest, QueueWorker_multiplesClient)
{

    // Queue of workers
    const std::size_t taskQueueSize = 16;

    // Configure UnixStream server
    UnixStream server(m_socketPath, m_factory, taskQueueSize);
    server.bind(m_loop);
    auto [stopHandler, thread] = startLoopThread(m_loop);
    const auto maxAttempts = 10;
    const auto clients = taskQueueSize;

    // Create and connect Unix domain socket client
    std::vector<int> clientSockets;
    std::vector<std::string> messages;
    for (int i = 0; i < clients; ++i)
    {
        clientSockets.push_back(createUnixSocketClient(m_socketPath));
        std::string message = "Hello, World! client-> ";
        message += std::to_string(i);
        message += "<END>";
        messages.push_back(std::move(message));
    }

    // Send messages taskQueueSize messages to the server
    for (int i = 0; i < clients; ++i)
    {
        auto res = send(clientSockets[i], messages[i].c_str(), messages[i].size(), 0);
        ASSERT_EQ(res, messages[i].size());
    }

    // Wait for the messages to be processed
    auto attempts = 0;
    while (*(m_factory->m_processedMessages) < clients)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        ASSERT_LT(attempts++, maxAttempts) << "Messages not processed";
    }

    // Read the responses from the clients
    std::vector<std::string> responses;
    responses.reserve(clients);
    attempts = 0;

    for (int i = 0; i < clients; ++i)
    {
        ASSERT_LT(attempts++, maxAttempts) << "Messages not received from client";
        responses.push_back(std::string{});
        while (responses[i].length() < messages[i].length())
        {
            ASSERT_LT(attempts++, maxAttempts) << "Messages not received from client";
            char buffer[1024] = {};
            // Non-blocking read
            ssize_t received = recv(clientSockets[i], buffer, sizeof(buffer), MSG_DONTWAIT);
            if (received == 0)
            {
                // Connection closed
                FAIL() << "Connection closed";
            }
            if (received == -1)
            {
                // No data available
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }
            attempts = 0;
            ASSERT_GT(received, 0);
            responses[i].append(buffer, received);
        };
    }

    // Check the responses (order is guaranteed)
    for (int i = 0; i < clients; ++i)
    {
        ASSERT_EQ(messages[i], responses[i]);
    }

    server.close();
    stopHandler->send();
    thread.join();
}



TEST_F(UnixStreamTest, taskQueueSizeTestAndOverflow)
{

    // Queue of workers
    const std::size_t taskQueueSize = 4;
    const std::size_t numOfWorkers = 4;

    // Calculate the number of messages to send
    std::size_t sendedMessages = 0;
    std::size_t busyMessage = 0;

    // Configure UnixStream server
    UnixStream server(m_socketPath, m_factory, taskQueueSize);
    server.bind(m_loop);
    auto [stopHandler, thread] = startLoopThread(m_loop);
    const auto maxAttempts = 10;

    // Create and connect Unix domain socket client
    int clientSockfd = createUnixSocketClient(m_socketPath);

    *m_factory->enableBlockQueueWorkers = true;
    std::string expectedProcessedMessages = "";
    // Fill the queue of workers
    for (std::size_t i = 0; i < taskQueueSize; ++i)
    {
        std::string message = "Hello, World! message -> ";
        message += std::to_string(i);
        message += "<END>";
        auto res = send(clientSockfd, message.c_str(), message.size(), 0);
        ASSERT_EQ(res, message.size());
        sendedMessages++;
        expectedProcessedMessages += message;
    }

    // Create and connect Unix domain socket client (overflow)
    {
        int clientSockfd2 = createUnixSocketClient(m_socketPath);
        std::string message = "Hello, busy World! message<END>";
        auto res = send(clientSockfd2, message.c_str(), message.size(), 0);
        ASSERT_EQ(res, message.size());
        sendedMessages++;
        busyMessage++; // This message is sended but not processed

        // Read the response from the client
        const std::string expectedResponse = "Server is busy";
        std::string response {};
        response.reserve(expectedResponse.size());
        auto attempts = 0;
        while (response.length() < expectedResponse.size()) {
            ASSERT_LT(attempts++, maxAttempts) << "Messages not received from client";
            char buffer[1024] = {};
            // Non-blocking read
            ssize_t received = recv(clientSockfd2, buffer, sizeof(buffer), MSG_DONTWAIT);
            if (received == 0)
            {
                // Connection closed
                FAIL() << "Connection closed";
            }
            if (received == -1)
            {
                // No data available
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }
            ASSERT_GT(received, 0);
            response.append(buffer, received);
        };
        ASSERT_EQ(expectedResponse, response) << "Response not expected";
        close(clientSockfd2);
    }

    // Check the number of messages processed
    ASSERT_EQ(*(m_factory->m_processedMessages), 0);

    // Send 4 message to the server using de first client and wait for the messages of server is busy
    {
        std::string expectedResponse {};
        for (std::size_t i = 0; i < 4; ++i)
        {
            std::string message = "Hello, World! discart -> ";
            message += std::to_string(i);
            message += "<END>";
            auto res = send(clientSockfd, message.c_str(), message.size(), 0);
            ASSERT_EQ(res, message.size());
            sendedMessages++;
            busyMessage++; // This message is sended but not processed
            expectedResponse += "Server is busy";
        }

        // Read the response from the client
        std::string response {};
        response.reserve(expectedResponse.size());
        auto attempts = 0;
        while (response.length() < expectedResponse.size()) {
            ASSERT_LT(attempts++, maxAttempts) << "Messages not received from client";
            char buffer[1024] = {};
            // Non-blocking read
            ssize_t received = recv(clientSockfd, buffer, sizeof(buffer), MSG_DONTWAIT);
            if (received == 0)
            {
                // Connection closed
                FAIL() << "Connection closed";
            }
            if (received == -1)
            {
                // No data available
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }
            ASSERT_GT(received, 0);
            response.append(buffer, received);
        };
        ASSERT_EQ(expectedResponse, response) << "Response not expected";
    }

    // Check the number of messages processed
    ASSERT_EQ(*(m_factory->m_processedMessages), 0);

    // Enable the queue of workers
    *m_factory->enableBlockQueueWorkers = false;
    // Unblocking the queue of workers
    m_factory->BlockWokersCV->notify_all();

    // Check the number of messages processed
    auto attempts = 0;
    while (*(m_factory->m_processedMessages) < sendedMessages - busyMessage)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        ASSERT_LT(attempts++, maxAttempts) << "Messages not processed";
    }

    // Check the number of messages processed
    ASSERT_EQ(*(m_factory->m_processedMessages), sendedMessages - busyMessage);

    // Read the response from the client
    std::string response {};
    response.reserve(expectedProcessedMessages.size());
    attempts = 0;

    while (response.length() < expectedProcessedMessages.size()) {
        ASSERT_LT(attempts++, maxAttempts) << "Messages not received from client";
        char buffer[1024] = {};
        // Non-blocking read
        ssize_t received = recv(clientSockfd, buffer, sizeof(buffer), MSG_DONTWAIT);
        if (received == 0)
        {
            // Connection closed
            FAIL() << "Connection closed";
        }
        if (received == -1)
        {
            // No data available
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        ASSERT_GT(received, 0);
        response.append(buffer, received);
    };

    // Check the messages received by the client (the order is not guaranteed)
    ASSERT_EQ(expectedProcessedMessages.length(), response.length()) << "Response not expected";

    server.close();
    stopHandler->send();
    thread.join();
}
