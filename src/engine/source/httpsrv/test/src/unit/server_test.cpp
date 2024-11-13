#include <gtest/gtest.h>

#include <csignal>

#include <base/logging.hpp>
#include <httpsrv/server.hpp>

namespace
{
std::filesystem::path uniquePath()
{
    auto pid = getpid();
    auto tid = std::this_thread::get_id();
    std::stringstream ss;
    ss << pid << "_" << tid; // Unique path per thread and process
    return std::filesystem::path("/tmp") / (ss.str());
}
} // namespace

class ServerTest : public ::testing::Test
{
protected:
    auto getSocketPath(const std::string& name) { return uniquePath() / name; }

    void SetUp() override
    {
        logging::testInit();
        std::filesystem::create_directory(uniquePath());
    }

    void TearDown() override
    {
        if (std::filesystem::exists(uniquePath()))
        {
            // Remove folder
            std::filesystem::remove_all(uniquePath());
        }
    }
};

TEST_F(ServerTest, Create)
{
    EXPECT_NO_THROW(httpsrv::Server srv("test"));
}

TEST_F(ServerTest, StartEmptySocketPath)
{
    httpsrv::Server srv("test");

    EXPECT_THROW(srv.start(std::filesystem::path("")), std::runtime_error);
}

TEST_F(ServerTest, StartInvalidSocketPath)
{
    httpsrv::Server srv("test");

    EXPECT_THROW(srv.start(getSocketPath("invalid/test.sock")), std::runtime_error);
}

TEST_F(ServerTest, StartStop)
{
    httpsrv::Server srv("test");

    EXPECT_NO_THROW(srv.start(getSocketPath("test.sock")));
    EXPECT_NO_THROW(srv.stop());
}

namespace servertest
{

} // namespace servertest

TEST_F(ServerTest, StartStopCurrentThread)
{
    auto srv = std::make_shared<httpsrv::Server>("test");
    auto job = [srv, path = getSocketPath("test.sock")]()
    {
        srv->start(path, false);
    };

    std::thread t(job);
    // Wait for the server to start
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    srv->stop();
    t.join();
}

TEST_F(ServerTest, StopNotStarted)
{
    httpsrv::Server srv("test");

    EXPECT_NO_THROW(srv.stop());
}

TEST_F(ServerTest, StartAlreadyStarted)
{
    httpsrv::Server srv("test");

    EXPECT_NO_THROW(srv.start(getSocketPath("test.sock")));
    EXPECT_THROW(srv.start(getSocketPath("test.sock")), std::runtime_error);
    srv.stop();
}

TEST_F(ServerTest, AddRoute)
{
    httpsrv::Server srv("test");
    auto fn = [&]()
    {
        srv.addRoute(httpsrv::Method::GET, "/test", [](const httplib::Request&, httplib::Response&) {});
    };
    EXPECT_NO_THROW(fn());
}

TEST_F(ServerTest, AddOverrideRoute)
{
    httpsrv::Server srv("test");
    auto fn = [&]()
    {
        srv.addRoute(httpsrv::Method::GET, "/test", [](const httplib::Request&, httplib::Response&) {});
    };

    EXPECT_NO_THROW(fn());
    EXPECT_NO_THROW(fn());
}

TEST_F(ServerTest, IsRunning)
{
    httpsrv::Server srv("test");

    EXPECT_FALSE(srv.isRunning());
    EXPECT_NO_THROW(srv.start(std::filesystem::path("/tmp/test.sock")));
    EXPECT_TRUE(srv.isRunning());
    EXPECT_NO_THROW(srv.stop());
    EXPECT_FALSE(srv.isRunning());
}
