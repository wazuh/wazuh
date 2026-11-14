// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <future>
#include <memory>
#include <string>
#include <thread>

#include <base/logging.hpp>
#include <fastmetrics/registry.hpp>
#include <httpsrv/server.hpp>

using namespace std::chrono_literals;
using httpsrv::Method;
using httpsrv::Request;
using httpsrv::Response;
using httpsrv::Server;
using httpsrv::ServerOptions;

namespace
{
// The fastmetrics manager is a process-wide singleton: register it once for this binary, at load time, so every
// suite of the binary that registers metrics finds it whatever order or filter the tests run with.
struct FastMetricsInit
{
    FastMetricsInit() { fastmetrics::registerManager(); }
};
const FastMetricsInit fastMetricsInit;

const char* const SUFFIXES[] = {"inflight.bytes",
                                "inflight.requests",
                                "sessions",
                                "queue.depth",
                                "running",
                                "shed.budget",
                                "shed.connections",
                                "shed.executor_full",
                                "shed.shutdown",
                                "handler_errors",
                                "rejected.too_large"};

std::string socketPath(const char* tag)
{
    static std::atomic<int> counter {0};
    return "/tmp/httpsrv_m_" + std::string {tag} + "_" + std::to_string(::getpid()) + "_"
           + std::to_string(counter.fetch_add(1)) + ".sock";
}

ServerOptions options(std::size_t threads, std::size_t queue)
{
    ServerOptions opts;
    opts.name = "Test";
    opts.logTag = "httpsrv-test";
    opts.executorThreads = threads;
    opts.executorQueue = queue;
    return opts;
}

std::string roundTrip(const std::string& path, const std::string& raw)
{
    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
    {
        ::close(fd);
        return {};
    }
    timeval timeout {10, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    ::send(fd, raw.data(), raw.size(), MSG_NOSIGNAL);
    std::string out;
    char buffer[4096];
    for (ssize_t n; (n = ::recv(fd, buffer, sizeof(buffer), 0)) > 0;)
    {
        out.append(buffer, static_cast<std::size_t>(n));
    }
    ::close(fd);
    return out;
}

std::string post(const std::string& target, const std::string& body)
{
    return "POST " + target + " HTTP/1.1\r\nHost: localhost\r\nContent-Length: " + std::to_string(body.size())
           + "\r\nConnection: close\r\n\r\n" + body;
}

int statusOf(const std::string& response)
{
    return response.rfind("HTTP/1.1 ", 0) == 0 ? std::stoi(response.substr(9, 3)) : 0;
}

/// fastmetrics keeps the first registration of a name, so every test (and every --gtest_repeat
/// iteration) observes its own server under a fresh instance name.
std::string uniqueInstance(const char* tag)
{
    static std::atomic<int> counter {0};
    return std::string {tag} + std::to_string(counter.fetch_add(1));
}

double metric(const std::string& instance, const char* suffix)
{
    const auto found = fastmetrics::manager().get(fastmetrics::names::server_metric(instance, suffix));
    return found ? found->value() : -1.0;
}
class ServerMetricsTest : public ::testing::Test
{
protected:
    void SetUp() override { logging::testInit(); }
};
} // namespace

TEST_F(ServerMetricsTest, RegistersEveryMetricUnderTheInstance)
{
    auto server = std::make_shared<Server>(options(1, 1));

    const auto instance = uniqueInstance("names");

    httpsrv::registerMetrics(server, instance);

    for (const auto* suffix : SUFFIXES)
    {
        EXPECT_TRUE(fastmetrics::manager().exists("server." + instance + "." + suffix)) << suffix;
    }
}

TEST_F(ServerMetricsTest, MetricsFollowTheServerStats)
{
    const auto path = socketPath("follow");
    std::promise<void> release;
    auto released = release.get_future().share();
    std::atomic<int> started {0};

    auto server = std::make_shared<Server>(options(1, 1));
    server->addRoute(Method::POST,
                     "/events",
                     [&](const Request&, Response&)
                     {
                         ++started;
                         released.wait();
                     });
    httpsrv::RouteOptions capped;
    capped.maxBodyBytes = 16;
    server->addRoute(Method::POST, "/small", [](const Request&, Response&) {}, capped);
    const auto instance = uniqueInstance("follow");
    httpsrv::registerMetrics(server, instance);
    server->start(path);

    // One request runs (blocked), one waits in the queue, the third finds the queue full.
    auto first = std::async(std::launch::async, [&] { return roundTrip(path, post("/events", "a")); });
    while (started.load() == 0)
    {
        std::this_thread::sleep_for(1ms);
    }
    auto second = std::async(std::launch::async, [&] { return roundTrip(path, post("/events", "b")); });
    while (server->stats().queueDepth == 0)
    {
        std::this_thread::sleep_for(1ms);
    }
    EXPECT_EQ(503, statusOf(roundTrip(path, post("/events", "c"))));
    EXPECT_EQ(413, statusOf(roundTrip(path, post("/small", std::string(32, 'x')))));

    EXPECT_EQ(1.0, metric(instance, "running"));
    EXPECT_EQ(1.0, metric(instance, "queue.depth"));
    EXPECT_EQ(1.0, metric(instance, "shed.executor_full"));
    EXPECT_EQ(1.0, metric(instance, "rejected.too_large"));
    EXPECT_GE(metric(instance, "sessions"), 2.0) << "the running and the queued request hold a connection";
    EXPECT_EQ(0.0, metric(instance, "shed.budget"));

    release.set_value();
    EXPECT_EQ(200, statusOf(first.get()));
    EXPECT_EQ(200, statusOf(second.get()));
    server->shutdown(1s);
}

TEST_F(ServerMetricsTest, MetricsReadZeroOnceTheServerIsGone)
{
    const auto path = socketPath("gone");
    auto server = std::make_shared<Server>(options(1, 1));
    httpsrv::RouteOptions capped;
    capped.maxBodyBytes = 16;
    server->addRoute(Method::POST, "/small", [](const Request&, Response&) {}, capped);
    const auto instance = uniqueInstance("gone");
    httpsrv::registerMetrics(server, instance);
    server->start(path);

    EXPECT_EQ(413, statusOf(roundTrip(path, post("/small", std::string(32, 'x')))));
    EXPECT_EQ(1.0, metric(instance, "rejected.too_large"));

    server->shutdown(1s);
    server.reset();

    for (const auto* suffix : SUFFIXES)
    {
        EXPECT_EQ(0.0, metric(instance, suffix)) << suffix;
    }
}
