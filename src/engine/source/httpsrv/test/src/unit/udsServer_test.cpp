// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <future>
#include <string>
#include <thread>

#include <httpsrv/udsServer.hpp>

using namespace std::chrono_literals;
using httpsrv::Method;
using httpsrv::Request;
using httpsrv::Response;
using httpsrv::UdsServer;
using httpsrv::UdsServerOptions;

namespace
{
std::string socketPath(const char* tag)
{
    static std::atomic<int> counter {0};
    return "/tmp/httpsrv_" + std::string {tag} + "_" + std::to_string(::getpid()) + "_"
           + std::to_string(counter.fetch_add(1)) + ".sock";
}

UdsServerOptions options(std::size_t threads = 2, std::size_t queue = 16)
{
    UdsServerOptions opts;
    opts.name = "Test";
    opts.logTag = "httpsrv-test";
    opts.executorThreads = threads;
    opts.executorQueue = queue;
    return opts;
}

int connectTo(const std::string& path)
{
    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
    {
        ::close(fd);
        return -1;
    }
    return fd;
}

/// Sends @p head + @p body and reads until the server closes the connection.
std::string roundTrip(const std::string& path, const std::string& raw)
{
    const int fd = connectTo(path);
    if (fd < 0)
    {
        return {};
    }
    timeval timeout {10, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    ::send(fd, raw.data(), raw.size(), MSG_NOSIGNAL);
    std::string out;
    char buffer[4096];
    for (;;)
    {
        const auto n = ::recv(fd, buffer, sizeof(buffer), 0);
        if (n <= 0)
        {
            break;
        }
        out.append(buffer, static_cast<std::size_t>(n));
    }
    ::close(fd);
    return out;
}

std::string
post(const std::string& path, const std::string& target, const std::string& body, const std::string& extra = "")
{
    return "POST " + target + " HTTP/1.1\r\nHost: localhost\r\n" + extra
           + "Content-Length: " + std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
}

int statusOf(const std::string& response)
{
    return response.rfind("HTTP/1.1 ", 0) == 0 ? std::stoi(response.substr(9, 3)) : 0;
}

std::string bodyOf(const std::string& response)
{
    const auto at = response.find("\r\n\r\n");
    return at == std::string::npos ? std::string {} : response.substr(at + 4);
}

bool hasHeader(const std::string& response, const std::string& line)
{
    return response.find("\r\n" + line + "\r\n") != std::string::npos;
}
} // namespace

TEST(UdsServerTest, RoundTripCarriesNeutralRequestAndResponse)
{
    const auto path = socketPath("rt");
    Method seenMethod {Method::GET};
    std::string seenTarget;
    std::string seenBody;
    std::string seenHeader;

    UdsServer server {options()};
    server.addRoute(Method::POST,
                    "/events",
                    [&](const Request& req, Response& res)
                    {
                        seenMethod = req.method;
                        seenTarget = req.target;
                        seenBody = std::string {req.body};
                        seenHeader = std::string {req.header("X-Custom").value_or("")};
                        res.setContent(R"({"ok":true})", "application/json");
                    });
    server.start(path);

    const auto response = roundTrip(path, post(path, "/events?q=1", "hello", "X-Custom: Value\r\n"));
    server.shutdown(1s);

    EXPECT_EQ(200, statusOf(response));
    EXPECT_EQ(R"({"ok":true})", bodyOf(response));
    EXPECT_TRUE(hasHeader(response, "Content-Type: application/json")) << response;
    EXPECT_EQ(Method::POST, seenMethod);
    EXPECT_EQ("/events?q=1", seenTarget);
    EXPECT_EQ("hello", seenBody);
    EXPECT_EQ("Value", seenHeader) << "header lookup is case-insensitive";
}

TEST(UdsServerTest, HeaderCountSeesARepeatedHeader)
{
    const auto path = socketPath("dup");
    std::size_t repeated {0};
    std::size_t single {0};

    UdsServer server {options()};
    server.addRoute(Method::POST,
                    "/events",
                    [&](const Request& req, Response&)
                    {
                        repeated = req.headerCount("X-Wazuh-Agent-Id");
                        single = req.headerCount("x-other");
                    });
    server.start(path);

    roundTrip(path, post(path, "/events", "", "X-Wazuh-Agent-Id: 001\r\nX-Wazuh-Agent-Id: 002\r\nX-Other: a\r\n"));
    server.shutdown(1s);

    EXPECT_EQ(2U, repeated);
    EXPECT_EQ(1U, single);
}

TEST(UdsServerTest, ExecutorFullAnswers503Busy)
{
    const auto path = socketPath("busy");
    std::promise<void> release;
    auto released = release.get_future().share();
    std::atomic<int> started {0};

    UdsServer server {options(1, 1)};
    server.addRoute(Method::POST,
                    "/events",
                    [&](const Request&, Response&)
                    {
                        ++started;
                        released.wait();
                    });
    server.start(path);

    // One request runs (blocked), one waits in the queue, the third finds the queue full.
    auto first = std::async(std::launch::async, [&] { return roundTrip(path, post(path, "/events", "a")); });
    while (started.load() == 0)
    {
        std::this_thread::sleep_for(1ms);
    }
    auto second = std::async(std::launch::async, [&] { return roundTrip(path, post(path, "/events", "b")); });
    while (server.stats().queueDepth == 0)
    {
        std::this_thread::sleep_for(1ms);
    }
    const auto third = roundTrip(path, post(path, "/events", "c"));

    EXPECT_EQ(503, statusOf(third));
    EXPECT_EQ(R"({"error":"Server busy","code":503})", bodyOf(third));
    EXPECT_EQ(1U, server.stats().shedExecutorFull);

    release.set_value();
    EXPECT_EQ(200, statusOf(first.get()));
    EXPECT_EQ(200, statusOf(second.get()));
    server.shutdown(1s);
}

TEST(UdsServerTest, HandlerExceptionAnswers500Text)
{
    const auto path = socketPath("throw");
    UdsServer server {options()};
    server.addRoute(Method::POST, "/events", [](const Request&, Response&) { throw std::runtime_error {"boom"}; });
    server.start(path);

    const auto response = roundTrip(path, post(path, "/events", "x"));
    const auto stats = server.stats();
    server.shutdown(1s);

    EXPECT_EQ(500, statusOf(response));
    EXPECT_EQ("Internal server error", bodyOf(response));
    EXPECT_TRUE(hasHeader(response, "Content-Type: text/plain")) << response;
    EXPECT_EQ(1U, stats.handlerErrors);
}

TEST(UdsServerTest, ShutdownDeliversARunningReplyWithinTheDeadline)
{
    const auto path = socketPath("slow");
    std::atomic<bool> started {false};
    UdsServer server {options()};
    server.addRoute(Method::POST,
                    "/events",
                    [&](const Request&, Response& res)
                    {
                        started = true;
                        std::this_thread::sleep_for(300ms);
                        res.setContent("done", "text/plain");
                    });
    server.start(path);

    auto pending = std::async(std::launch::async, [&] { return roundTrip(path, post(path, "/events", "x")); });
    while (!started)
    {
        std::this_thread::sleep_for(1ms);
    }
    const auto report = server.shutdown(2s);
    const auto response = pending.get();

    EXPECT_EQ(200, statusOf(response));
    EXPECT_EQ("done", bodyOf(response));
    EXPECT_EQ(1U, report.completed);
    EXPECT_EQ(0U, report.abandoned);
}

TEST(UdsServerTest, ShutdownAnswersUnstartedRequests503AtTheDeadline)
{
    const auto path = socketPath("unstarted");
    std::promise<void> release;
    auto released = release.get_future().share();
    std::atomic<int> started {0};

    UdsServer server {options(1, 4)};
    server.addRoute(Method::POST,
                    "/events",
                    [&](const Request&, Response&)
                    {
                        ++started;
                        released.wait();
                    });
    server.start(path);

    auto running = std::async(std::launch::async, [&] { return roundTrip(path, post(path, "/events", "a")); });
    while (started.load() == 0)
    {
        std::this_thread::sleep_for(1ms);
    }
    auto queued = std::async(std::launch::async, [&] { return roundTrip(path, post(path, "/events", "b")); });
    while (server.stats().queueDepth == 0)
    {
        std::this_thread::sleep_for(1ms);
    }

    auto stopping = std::async(std::launch::async, [&] { return server.shutdown(200ms); });
    const auto queuedResponse = queued.get();
    release.set_value(); // let the abandoned job end so the executor can be joined
    const auto report = stopping.get();
    running.get();

    EXPECT_EQ(503, statusOf(queuedResponse));
    EXPECT_EQ(R"({"error":"Server shutting down","code":503})", bodyOf(queuedResponse));
    EXPECT_EQ(1U, report.rejected);
    EXPECT_EQ(1U, report.abandoned);
}

TEST(UdsServerTest, ShutdownAllStopsAcceptingOnEveryServerFirst)
{
    const auto pathA = socketPath("allA");
    const auto pathB = socketPath("allB");
    UdsServer a {options()};
    UdsServer b {options()};
    a.addRoute(Method::POST, "/x", [](const Request&, Response&) {});
    b.addRoute(Method::POST, "/x", [](const Request&, Response&) {});
    a.start(pathA);
    b.start(pathB);

    httpsrv::shutdownAll({&a, nullptr, &b}, 1s);

    EXPECT_FALSE(a.isRunning());
    EXPECT_FALSE(b.isRunning());
    EXPECT_EQ(0, statusOf(roundTrip(pathA, post(pathA, "/x", "")))) << "no answer once stopped";
    EXPECT_EQ(0, statusOf(roundTrip(pathB, post(pathB, "/x", ""))));
}

TEST(UdsServerTest, SocketIsCreatedWithMode0660)
{
    const auto path = socketPath("mode");
    UdsServer server {options()};
    server.addRoute(Method::GET, "/status", [](const Request&, Response&) {});
    server.start(path);

    struct stat info {};
    ASSERT_EQ(0, ::stat(path.c_str(), &info));
    server.shutdown(1s);

    EXPECT_EQ(0660U, info.st_mode & 0777U);
}

// A typo in the configured path must never delete an operator's file: only a socket is replaced.
TEST(UdsServerTest, StartRefusesAPathThatIsNotASocket)
{
    const auto path = socketPath("file");
    {
        std::ofstream file {path};
        file << "operator data";
    }
    UdsServer server {options()};
    server.addRoute(Method::GET, "/status", [](const Request&, Response&) {});

    EXPECT_ANY_THROW(server.start(path));
    EXPECT_TRUE(std::filesystem::is_regular_file(path)) << "the file must survive";
    std::filesystem::remove(path);
}

TEST(UdsServerTest, ExpectContinueOptionReachesTheWire)
{
    const auto path = socketPath("expect");
    auto opts = options();
    opts.expectContinue = true;
    UdsServer server {opts};
    server.addRoute(Method::POST,
                    "/events",
                    [](const Request& req, Response& res) { res.setContent(std::string {req.body}, "text/plain"); });
    server.start(path);

    const int fd = connectTo(path);
    ASSERT_GE(fd, 0);
    timeval timeout {2, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    const std::string head {
        "POST /events HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n"};
    ::send(fd, head.data(), head.size(), MSG_NOSIGNAL);
    char buffer[256];
    const auto n = ::recv(fd, buffer, sizeof(buffer), 0);
    const std::string interim {buffer, n > 0 ? static_cast<std::size_t>(n) : 0U};
    ::send(fd, "ping", 4, MSG_NOSIGNAL);
    std::string rest;
    for (ssize_t r; (r = ::recv(fd, buffer, sizeof(buffer), 0)) > 0;)
    {
        rest.append(buffer, static_cast<std::size_t>(r));
    }
    ::close(fd);
    server.shutdown(1s);

    EXPECT_EQ("HTTP/1.1 100 Continue\r\n\r\n", interim);
    EXPECT_EQ(200, statusOf(rest));
    EXPECT_EQ("ping", bodyOf(rest));
}
