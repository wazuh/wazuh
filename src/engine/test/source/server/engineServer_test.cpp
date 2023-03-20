#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

#include <server/engineServer.hpp>

class EngineServerTest : public ::testing::Test
{
protected:
    void SetUp() override { test_socket_path = "/tmp/gtest_engine_server.sock"; }

    void TearDown() override { unlink(test_socket_path.c_str()); }

    std::string test_socket_path;
};

TEST_F(EngineServerTest, TestAddEndpointAndStart)
{
    engineserver::EngineServer engine_server;

    std::atomic<bool> callback_called(false);
    std::string test_message = "Test message";

    engine_server.addEndpoint_UnixDatagram_woResponse(test_socket_path,
                                                      [&callback_called, &test_message](std::string&& received_message)
                                                      {
                                                          ASSERT_EQ(test_message, received_message);
                                                          callback_called.store(true);
                                                      });

    std::thread server_thread([&engine_server]() { engine_server.start(); });

    // Wait for the server to start
    std::this_thread::sleep_for(std::chrono::seconds(1));

    int client_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
    ASSERT_NE(client_socket, -1);

    sockaddr_un server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, test_socket_path.c_str(), sizeof(server_addr.sun_path) - 1);

    ssize_t bytes_sent = sendto(client_socket,
                                test_message.c_str(),
                                test_message.length(),
                                0,
                                reinterpret_cast<sockaddr*>(&server_addr),
                                sizeof(server_addr));
    ASSERT_EQ(bytes_sent, static_cast<ssize_t>(test_message.length()));

    // Wait for the callback to be called
    int retries = 0;
    while (!callback_called.load() && retries++ < 10)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    close(client_socket);

    ASSERT_TRUE(callback_called.load());

    // Stop the server and join the server thread
    engine_server.request_stop();
    server_thread.join();
}
