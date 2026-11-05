// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <base/logging.hpp>
#include <httpsrv/udsServer.hpp>

namespace Log
{
// The transport's log hook, defined by the engine's logging module; the tests below capture it.
extern std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
    GLOBAL_LOG_FUNCTION;
} // namespace Log

using namespace std::chrono_literals;
using httpsrv::Method;
using httpsrv::Request;
using httpsrv::Response;
using httpsrv::UdsServer;
using httpsrv::UdsServerOptions;

namespace
{
std::string uniqueSocketPath(const char* tag)
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
class UdsServerTest : public ::testing::Test
{
protected:
    void SetUp() override { logging::testInit(); }

    void TearDown() override
    {
        // A server removes its own socket on stop; this only cleans up after a test that failed early.
        for (const auto& path : m_paths)
        {
            std::error_code ignored;
            std::filesystem::remove(path, ignored);
        }
    }

    /// A socket path unique to this test run, removed after the test.
    std::string socketPath(const char* tag)
    {
        m_paths.push_back(uniqueSocketPath(tag));
        return m_paths.back();
    }

private:
    std::vector<std::string> m_paths;
};
} // namespace

TEST_F(UdsServerTest, RoundTripCarriesNeutralRequestAndResponse)
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

TEST_F(UdsServerTest, HeaderCountSeesARepeatedHeader)
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

TEST_F(UdsServerTest, ExecutorFullAnswers503Busy)
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

// Connections that never send their request fill the server-wide limit; the next one is refused at
// accept, before any route class is known, and still counts as a connection shed.
TEST_F(UdsServerTest, ConnectionCapRejectCountsAsAConnectionShed)
{
    const auto path = socketPath("cap");
    auto opts = options();
    opts.maxConnections = 2;
    UdsServer server {opts};
    server.addRoute(Method::POST, "/events", [](const Request&, Response&) {});
    server.start(path);

    const int first = connectTo(path);
    const int second = connectTo(path);
    ASSERT_GE(first, 0);
    ASSERT_GE(second, 0);
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (server.stats().sessions < 2 && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(1ms);
    }
    ASSERT_EQ(2U, server.stats().sessions);

    const auto refused = roundTrip(path, post(path, "/events", "x"));

    EXPECT_EQ(503, statusOf(refused));
    EXPECT_EQ(1U, server.stats().shedSessions);
    EXPECT_EQ(0U, server.stats().shedBudget);
    ::close(first);
    ::close(second);
    server.shutdown(1s);
}

namespace
{
/// Captures the transport's log lines for the lifetime of the object, then restores the previous hook.
class TransportLogCapture
{
public:
    TransportLogCapture()
        : m_previous {Log::GLOBAL_LOG_FUNCTION}
    {
        Log::GLOBAL_LOG_FUNCTION =
            [this](const int, const char*, const char*, const int, const char*, const char* msg, va_list args)
        {
            char line[2048];
            std::vsnprintf(line, sizeof(line), msg, args);
            std::lock_guard<std::mutex> lock {m_mutex};
            m_lines.emplace_back(line);
        };
    }

    ~TransportLogCapture() { Log::GLOBAL_LOG_FUNCTION = m_previous; }

    bool contains(const std::string& needle)
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        for (const auto& line : m_lines)
        {
            if (line.find(needle) != std::string::npos)
            {
                return true;
            }
        }
        return false;
    }

private:
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)> m_previous;
    std::mutex m_mutex;
    std::vector<std::string> m_lines;
};
} // namespace

// The connection-limit line names the setting that raises the limit, as given in the options.
TEST_F(UdsServerTest, ConnectionLimitLogNamesTheConfiguredSetting)
{
    TransportLogCapture log;
    const auto path = socketPath("caphint");
    auto opts = options();
    opts.maxConnections = 2;
    opts.connectionCapOptionHint = "test.max_connections";
    UdsServer server {opts};
    server.addRoute(Method::POST, "/events", [](const Request&, Response&) {});
    server.start(path);

    const int first = connectTo(path);
    const int second = connectTo(path);
    ASSERT_GE(first, 0);
    ASSERT_GE(second, 0);
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (server.stats().sessions < 2 && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(1ms);
    }
    ASSERT_EQ(2U, server.stats().sessions);

    EXPECT_EQ(503, statusOf(roundTrip(path, post(path, "/events", "x"))));
    ::close(first);
    ::close(second);
    server.shutdown(1s);

    EXPECT_TRUE(log.contains("raising 'test.max_connections'"));
}

// The budget-exhausted line names the setting that raises the budget, as given in the options.
TEST_F(UdsServerTest, BudgetLogNamesTheConfiguredSetting)
{
    TransportLogCapture log;
    const auto path = socketPath("budgethint");
    auto opts = options();
    opts.maxBodySize = 64 * 1024;
    // Room for one 60 KiB request and its per-request overhead, not for two.
    opts.maxInFlightBytes = 400 * 1024;
    opts.budgetOptionHint = "test.max_inflight_bytes";
    std::promise<void> release;
    auto released = release.get_future().share();
    std::atomic<int> started {0};
    UdsServer server {opts};
    httpsrv::RouteOptions data; // only Data routes are charged to the byte budget
    data.cls = httpsrv::RouteClass::Data;
    server.addRoute(
        Method::POST,
        "/events",
        [&](const Request&, Response&)
        {
            ++started;
            released.wait();
        },
        data);
    server.start(path);

    const std::string body(60 * 1024, 'x');
    auto held = std::async(std::launch::async, [&] { return roundTrip(path, post(path, "/events", body)); });
    while (started.load() == 0)
    {
        std::this_thread::sleep_for(1ms);
    }
    const auto refused = roundTrip(path, post(path, "/events", body));
    release.set_value();
    held.get();
    server.shutdown(1s);

    EXPECT_EQ(503, statusOf(refused));
    EXPECT_EQ(1U, server.stats().shedBudget);
    EXPECT_TRUE(log.contains("raising 'test.max_inflight_bytes'"));
}

TEST_F(UdsServerTest, HandlerExceptionAnswers500Text)
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

TEST_F(UdsServerTest, ShutdownDeliversARunningReplyWithinTheDeadline)
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

TEST_F(UdsServerTest, ShutdownAnswersUnstartedRequests503AtTheDeadline)
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

// A handler still running at the deadline is reported as abandoned, and the stop still waits for it: the caller
// tears down what the handler uses (the engine shuts protobuf down) as soon as shutdown() or shutdownAll() returns.
// The handler runs past the transport's own 2 s wait for outstanding replies too, so only the executor join can make
// it finish first.
constexpr auto OUTLIVING_HANDLER_TIME {2600ms};

enum class StopVia
{
    Shutdown,
    ShutdownAll
};

class UdsServerOutlivingHandlerTest
    : public UdsServerTest
    , public ::testing::WithParamInterface<StopVia>
{
};

TEST_P(UdsServerOutlivingHandlerTest, StopReturnsOnlyAfterAHandlerThatOutlivedTheDeadline)
{
    const auto slowPath = socketPath("outlived");
    const auto idlePath = socketPath("outlived_idle");
    std::atomic<bool> started {false};
    std::atomic<bool> finished {false};

    UdsServer slow {options(1, 4)};
    slow.addRoute(Method::POST,
                  "/slow",
                  [&](const Request&, Response&)
                  {
                      started = true;
                      std::this_thread::sleep_for(OUTLIVING_HANDLER_TIME);
                      finished = true;
                  });
    UdsServer idle {options()};
    idle.addRoute(Method::POST, "/x", [](const Request&, Response&) {});
    slow.start(slowPath);
    idle.start(idlePath);

    auto pending = std::async(std::launch::async, [&] { return roundTrip(slowPath, post(slowPath, "/slow", "a")); });
    while (!started)
    {
        std::this_thread::sleep_for(1ms);
    }

    if (GetParam() == StopVia::Shutdown)
    {
        const auto report = slow.shutdown(50ms);
        EXPECT_EQ(1U, report.abandoned);
        idle.shutdown(50ms);
    }
    else
    {
        httpsrv::shutdownAll({&slow, &idle}, 50ms);
    }
    EXPECT_TRUE(finished.load()) << "the stop returned while a handler still ran";
    EXPECT_EQ(0U, slow.stats().running);
    pending.get();
}

INSTANTIATE_TEST_SUITE_P(StopPaths,
                         UdsServerOutlivingHandlerTest,
                         ::testing::Values(StopVia::Shutdown, StopVia::ShutdownAll),
                         [](const ::testing::TestParamInfo<StopVia>& info)
                         { return info.param == StopVia::Shutdown ? "Shutdown" : "ShutdownAll"; });

TEST_F(UdsServerTest, ShutdownAllStopsAcceptingOnEveryServerFirst)
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

TEST_F(UdsServerTest, SocketIsCreatedWithMode0660)
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
TEST_F(UdsServerTest, StartRefusesAPathThatIsNotASocket)
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

TEST_F(UdsServerTest, ExpectContinueOptionReachesTheWire)
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
