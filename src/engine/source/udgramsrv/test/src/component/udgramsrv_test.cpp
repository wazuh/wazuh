// test/src/unit/udsrv_test.cpp

#include <udgramsrv/udsrv.hpp>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <gtest/gtest.h>

namespace fs = std::filesystem;

class UdsrvServerTest : public ::testing::Test
{
protected:
    std::string socketPath;
    std::shared_ptr<udsrv::Server> server;
    std::vector<std::string> received;
    std::mutex m;
    std::condition_variable cv;

    void SetUp() override
    {
        // Compose a unique socket path under the system temp directory
        auto tmp = fs::temp_directory_path();
        // random suffix: PID + timestamp
        auto pid = getpid();
        auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();

        socketPath = (tmp / ("udsrv_test_" + std::to_string(pid) + "_" + std::to_string(now) + ".sock")).string();
        // make sure no leftover
        ::unlink(socketPath.c_str());
        received.clear();
    }

    void TearDown() override
    {
        if (server)
        {
            server->stop();
            server.reset();
        }
        ::unlink(socketPath.c_str());
    }

    // Helper: send a single datagram to the socket
    void sendDatagram(const std::string& msg)
    {
        int cli = ::socket(AF_UNIX, SOCK_DGRAM, 0);
        ASSERT_GE(cli, 0) << "client socket() failed";
        sockaddr_un addr {};
        addr.sun_family = AF_UNIX;
        std::strncpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path) - 1);
        ssize_t n = ::sendto(cli,
                             msg.data(),
                             msg.size(),
                             0,
                             reinterpret_cast<sockaddr*>(&addr),
                             offsetof(sockaddr_un, sun_path) + socketPath.size());
        ::close(cli);
        ASSERT_EQ(n, ssize_t(msg.size())) << "sendto() failed";
    }
};

// Construction + start/stop
TEST_F(UdsrvServerTest, StartStopBasic)
{
    server = std::make_shared<udsrv::Server>([&](std::string_view m) {}, socketPath);
    EXPECT_NO_THROW(server->start(1));
    EXPECT_NO_THROW(server->stop());
}

// start(0) must throw
TEST_F(UdsrvServerTest, StartZeroPoolThrows)
{
    server = std::make_shared<udsrv::Server>([&](std::string_view) {}, socketPath);
    EXPECT_THROW(server->start(0), std::runtime_error);
}

// double‐start must throw
TEST_F(UdsrvServerTest, DoubleStartThrows)
{
    server = std::make_shared<udsrv::Server>([&](std::string_view) {}, socketPath);
    server->start(2);
    EXPECT_THROW(server->start(1), std::runtime_error);
    server->stop();
}

// stop before start is no‐op
TEST_F(UdsrvServerTest, StopWithoutStart)
{
    server = std::make_shared<udsrv::Server>([&](std::string_view) {}, socketPath);
    EXPECT_NO_THROW(server->stop());
}

// dispatch a single message
TEST_F(UdsrvServerTest, SingleDatagramDispatch)
{
    std::unique_lock lk(m);
    // set up handler to capture
    server = std::make_shared<udsrv::Server>(
        [&](std::string_view msg)
        {
            std::lock_guard lk(m);
            received.emplace_back(msg);
            cv.notify_one();
        },
        socketPath);
    server->start(1);

    const std::string payload = "hello, world";
    sendDatagram(payload);

    // wait for handler
    const auto res = cv.wait_for(lk, std::chrono::milliseconds(500), [&] { return !received.empty(); });
    ASSERT_TRUE(res) << "timed out waiting for message";

    ASSERT_EQ(received.size(), 1u);
    EXPECT_EQ(received[0], payload);

    server->stop();
}

// dispatch many messages in parallel
TEST_F(UdsrvServerTest, MultipleDatagramsDispatch)
{
    server = std::make_shared<udsrv::Server>(
        [&](std::string_view msg)
        {
            std::lock_guard lk(m);
            received.emplace_back(msg);
            cv.notify_all();
        },
        socketPath);
    server->start(3);

    const int N = 128;
    for (int i = 0; i < N; ++i)
    {
        sendDatagram("msg#" + std::to_string(i));
    }

    // wait for all
    std::unique_lock lk(m);
    ASSERT_TRUE(cv.wait_for(lk, std::chrono::seconds(1), [&] { return int(received.size()) == N; }))
        << "didn't receive all messages in time";

    // check all got through (order is not guaranteed)
    for (int i = 0; i < N; ++i)
    {
        EXPECT_NE(std::find(received.begin(), received.end(), "msg#" + std::to_string(i)), received.end())
            << "missing msg#" << i;
    }
}

// destructor unlinks the socket
TEST_F(UdsrvServerTest, DestructorUnlinksSocket)
{
    {
        auto srv = std::make_shared<udsrv::Server>([&](std::string_view) {}, socketPath);
        srv->start(1);
        srv->stop();
        // destructor at end of scope
    }
    EXPECT_FALSE(fs::exists(socketPath));
}
