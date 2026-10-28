// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <thread>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include <base/behaviour.hpp>
#include <base/logging.hpp>
#include <httpsrv/server.hpp>

#include "generic_request.pb.h"

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

std::string makePayload(size_t n)
{
    return std::string(n, 'a');
}
} // namespace

/*******************************************************************************
 * Server General Tests
 ******************************************************************************/
class ServerTest : public ::testing::Test
{
protected:
    std::shared_ptr<httpsrv::IServer<httpsrv::Server>> m_srv;

    auto getSocketPath(const std::string& name) { return uniquePath() / name; }

public:
    void SetUp() override
    {
        logging::testInit();
        m_srv = std::make_shared<httpsrv::Server>("test");

        std::filesystem::create_directory(uniquePath());
    }

    void TearDown() override
    {
        m_srv->stop();
        m_srv.reset();
        if (std::filesystem::exists(uniquePath()))
        {
            // Remove folder
            std::filesystem::remove_all(uniquePath());
        }
    }
};

TEST_F(ServerTest, ServerStart)
{
    m_srv->start(getSocketPath("test.sock"));
}

TEST_F(ServerTest, ServerStartTwice)
{
    m_srv->start(getSocketPath("test.sock"));
    ASSERT_THROW(m_srv->start(getSocketPath("test.sock")), std::runtime_error);
    ASSERT_THROW(m_srv->start(getSocketPath("other.sock")), std::runtime_error);
}

TEST_F(ServerTest, ServerStop)
{
    ASSERT_NO_THROW(m_srv->stop());
    m_srv->start(getSocketPath("test.sock"));
    ASSERT_NO_THROW(m_srv->stop());
}

/*******************************************************************************
 * Server Httplib route tests
 ******************************************************************************/
using CliReq = std::function<httplib::Result(httplib::Client&, const std::string&, const httplib::Headers&)>;
using RoutesT = std::tuple<httpsrv::Method, std::string, CliReq>;

class RouteTest : public ::testing::TestWithParam<RoutesT>
{
protected:
    std::shared_ptr<httpsrv::IServer<httpsrv::Server>> m_srv;

    auto getSocketPath(const std::string& name) { return uniquePath() / name; }

public:
    void SetUp() override
    {
        logging::testInit();
        m_srv = std::make_shared<httpsrv::Server>("test");

        std::filesystem::create_directory(uniquePath());
    }

    void TearDown() override
    {
        m_srv->stop();
        m_srv.reset();
        if (std::filesystem::exists(uniquePath()))
        {
            // Remove folder
            std::filesystem::remove_all(uniquePath());
        }
    }

    auto getDefHandler()
    {

        return [](const httplib::Request&, httplib::Response& res)
        {
            res.status = 200;
            res.set_content("OK", "text/plain");
        };
    }
};

class BodyRouteTest : public RouteTest
{
};

TEST_P(RouteTest, AddRouteNotStarted)
{
    auto [method, route, cliReq] = GetParam();

    auto handler = getDefHandler();

    auto fn = [srv = m_srv, method, route, handler]()
    {
        srv->template addRoute<httplib::Request, httplib::Response>(method, route, handler);
    };

    ASSERT_NO_THROW(fn());
}

TEST_P(RouteTest, AddRouteStarted)
{
    auto [method, route, cliReq] = GetParam();

    auto handler = getDefHandler();

    auto fn = [srv = m_srv, method, route, handler]()
    {
        srv->template addRoute<httplib::Request, httplib::Response>(method, route, handler);
    };

    m_srv->start(getSocketPath("test.sock"));

    ASSERT_NO_THROW(fn());
}

TEST_P(RouteTest, AddRouteTwiceNotStarted)
{
    auto [method, route, cliReq] = GetParam();

    auto handler = getDefHandler();

    auto fn = [srv = m_srv, method, route, handler]()
    {
        srv->template addRoute<httplib::Request, httplib::Response>(method, route, handler);
    };

    ASSERT_NO_THROW(fn());
    ASSERT_NO_THROW(fn());
}

TEST_P(RouteTest, AddRouteTwiceStarted)
{
    auto [method, route, cliReq] = GetParam();

    auto handler = getDefHandler();

    auto fn = [srv = m_srv, method, route, handler]()
    {
        srv->template addRoute<httplib::Request, httplib::Response>(method, route, handler);
    };

    m_srv->start(getSocketPath("test.sock"));

    ASSERT_NO_THROW(fn());
    ASSERT_NO_THROW(fn());
}

TEST_P(RouteTest, Serve)
{
    auto [method, route, cliReq] = GetParam();

    auto handler = getDefHandler();

    auto fn = [srv = m_srv, method, route, handler]()
    {
        srv->template addRoute<httplib::Request, httplib::Response>(method, route, handler);
    };

    m_srv->start(getSocketPath("test.sock"));

    ASSERT_NO_THROW(fn());

    httplib::Client cli(getSocketPath("test.sock").string(), true);
    cli.set_address_family(AF_UNIX);

    httplib::Headers headers {{"Content-Type", "text/plain"}};
    httplib::Result res;

    res = cliReq(cli, route, headers);

    ASSERT_TRUE(res);
    ASSERT_EQ(res->status, 200);
    ASSERT_EQ(res->body, "OK");
}

TEST_P(RouteTest, NotStartedNotServed)
{
    auto [method, route, cliReq] = GetParam();

    auto handler = getDefHandler();

    auto fn = [srv = m_srv, method, route, handler]()
    {
        srv->template addRoute<httplib::Request, httplib::Response>(method, route, handler);
    };

    ASSERT_NO_THROW(fn());

    httplib::Client cli(getSocketPath("test.sock").string(), true);
    cli.set_address_family(AF_UNIX);

    httplib::Headers headers {{"Content-Type", "text/plain"}};
    httplib::Result res;

    res = cliReq(cli, route, headers);

    ASSERT_FALSE(res);
}

TEST_P(RouteTest, ServeIgnoredOverride)
{
    auto [method, route, cliReq] = GetParam();

    auto handler = getDefHandler();
    auto overrideHandler = [](const httplib::Request&, httplib::Response& res)
    {
        res.status = 200;
        res.set_content("OVERRIDE", "text/plain");
    };

    auto fn = [srv = m_srv, method, route, handler]()
    {
        srv->template addRoute<httplib::Request, httplib::Response>(method, route, handler);
    };
    auto overrideFn = [srv = m_srv, method, route, overrideHandler]()
    {
        srv->template addRoute<httplib::Request, httplib::Response>(method, route, overrideHandler);
    };

    m_srv->start(getSocketPath("test.sock"));

    ASSERT_NO_THROW(fn());
    ASSERT_NO_THROW(overrideFn());

    httplib::Client cli(getSocketPath("test.sock").string(), true);
    cli.set_address_family(AF_UNIX);

    httplib::Headers headers {{"Content-Type", "text/plain"}};
    httplib::Result res;

    res = cliReq(cli, route, headers);

    ASSERT_TRUE(res);
    ASSERT_EQ(res->status, 200);
    ASSERT_EQ(res->body, "OK");
}

TEST_P(RouteTest, ServeUnhandledException)
{
    auto [method, route, cliReq] = GetParam();
    auto handler = [](const httplib::Request&, httplib::Response&)
    {
        throw std::runtime_error("Test");
    };

    auto fn = [srv = m_srv, method, route, handler]()
    {
        srv->template addRoute<httplib::Request, httplib::Response>(method, route, handler);
    };

    m_srv->start(getSocketPath("test.sock"));

    ASSERT_NO_THROW(fn());

    httplib::Client cli(getSocketPath("test.sock").string(), true);
    cli.set_address_family(AF_UNIX);

    httplib::Headers headers {{"Content-Type", "text/plain"}};
    httplib::Result res;

    res = cliReq(cli, route, headers);

    ASSERT_TRUE(res);
    ASSERT_EQ(res->status, 500);
    ASSERT_EQ(res->body, "Internal server error");
}

TEST_P(BodyRouteTest, PayloadAtLimitIsAccepted)
{
    auto [method, route, /*cliReq*/ _] = GetParam();

    if (method != httpsrv::Method::POST && method != httpsrv::Method::PUT)
    {
        GTEST_SKIP() << "No request body for this method in current parametrization.";
    }

    constexpr size_t kLimitBytes = 16;

    // Replace the default server instance with a limited one (minimal change to fixture)
    m_srv->stop();
    m_srv.reset();
    m_srv = std::make_shared<httpsrv::Server>("test", kLimitBytes);

    std::atomic<int> handlerCalls {0};
    std::atomic<size_t> receivedSize {0};

    auto handler = [&](const httplib::Request& req, httplib::Response& res)
    {
        handlerCalls++;
        receivedSize = req.body.size();
        res.status = 200;
        res.set_content("OK", "text/plain");
    };

    m_srv->template addRoute<httplib::Request, httplib::Response>(method, route, handler);
    m_srv->start(getSocketPath("test.sock"));

    httplib::Client cli(getSocketPath("test.sock").string(), true);
    cli.set_address_family(AF_UNIX);

    httplib::Headers headers {{"Content-Type", "text/plain"}};
    const auto body = makePayload(kLimitBytes);

    httplib::Result res;
    if (method == httpsrv::Method::POST)
    {
        res = cli.Post(route.c_str(), headers, body, "text/plain");
    }
    else // PUT
    {
        res = cli.Put(route.c_str(), headers, body, "text/plain");
    }

    ASSERT_TRUE(res);
    ASSERT_EQ(res->status, 200);
    ASSERT_EQ(res->body, "OK");
    ASSERT_EQ(handlerCalls.load(), 1);
    ASSERT_EQ(receivedSize.load(), kLimitBytes);
}

TEST_P(BodyRouteTest, PayloadOverLimitReturns413)
{
    auto [method, route, /*cliReq*/ _] = GetParam();

    if (method != httpsrv::Method::POST && method != httpsrv::Method::PUT)
    {
        GTEST_SKIP() << "No request body for this method in current parametrization.";
    }

    constexpr size_t kLimitBytes = 16;

    m_srv->stop();
    m_srv.reset();
    m_srv = std::make_shared<httpsrv::Server>("test", kLimitBytes);

    std::atomic<int> handlerCalls {0};

    auto handler = [&](const httplib::Request&, httplib::Response& res)
    {
        handlerCalls++;
        res.status = 200;
        res.set_content("OK", "text/plain");
    };

    m_srv->template addRoute<httplib::Request, httplib::Response>(method, route, handler);
    m_srv->start(getSocketPath("test.sock"));

    httplib::Client cli(getSocketPath("test.sock").string(), true);
    cli.set_address_family(AF_UNIX);

    httplib::Headers headers {{"Content-Type", "text/plain"}};
    const auto body = makePayload(kLimitBytes + 1);

    httplib::Result res;
    if (method == httpsrv::Method::POST)
    {
        res = cli.Post(route.c_str(), headers, body, "text/plain");
    }
    else // PUT
    {
        res = cli.Put(route.c_str(), headers, body, "text/plain");
    }

    ASSERT_TRUE(res);
    ASSERT_EQ(res->status, 413);
    ASSERT_NE(res->body.find("Payload too large"), std::string::npos);
    // Optional: ensure it mentions the configured limit (if your handler formats it)
    ASSERT_NE(res->body.find(std::to_string(kLimitBytes)), std::string::npos);

    ASSERT_EQ(handlerCalls.load(), 0);
}

TEST_P(BodyRouteTest, PayloadUnlimitedAcceptsLargePayload)
{
    auto [method, route, /*cliReq*/ _] = GetParam();

    if (method != httpsrv::Method::POST && method != httpsrv::Method::PUT)
    {
        GTEST_SKIP() << "No request body for this method in current parametrization.";
    }

    // 0 => unlimited
    constexpr size_t kUnlimited = 0;
    constexpr size_t kBigPayload = 64 * 1024;

    m_srv->stop();
    m_srv.reset();
    m_srv = std::make_shared<httpsrv::Server>("test", kUnlimited);

    std::atomic<int> handlerCalls {0};
    std::atomic<size_t> receivedSize {0};

    auto handler = [&](const httplib::Request& req, httplib::Response& res)
    {
        handlerCalls++;
        receivedSize = req.body.size();
        res.status = 200;
        res.set_content("OK", "text/plain");
    };

    m_srv->template addRoute<httplib::Request, httplib::Response>(method, route, handler);
    m_srv->start(getSocketPath("test.sock"));

    httplib::Client cli(getSocketPath("test.sock").string(), true);
    cli.set_address_family(AF_UNIX);

    httplib::Headers headers {{"Content-Type", "text/plain"}};
    const auto body = makePayload(kBigPayload);

    httplib::Result res;
    if (method == httpsrv::Method::POST)
    {
        res = cli.Post(route.c_str(), headers, body, "text/plain");
    }
    else // PUT
    {
        res = cli.Put(route.c_str(), headers, body, "text/plain");
    }

    ASSERT_TRUE(res);
    ASSERT_EQ(res->status, 200);
    ASSERT_EQ(res->body, "OK");
    ASSERT_EQ(handlerCalls.load(), 1);
    ASSERT_EQ(receivedSize.load(), kBigPayload);
}

// httplib's own 8 KiB cap on form-urlencoded bodies must not apply: only the configured payload limit does.
TEST_P(BodyRouteTest, PayloadUnlimitedAcceptsLargeFormUrlEncodedBody)
{
    auto [method, route, /*cliReq*/ _] = GetParam();

    if (method != httpsrv::Method::POST && method != httpsrv::Method::PUT)
    {
        GTEST_SKIP() << "No request body for this method in current parametrization.";
    }

    constexpr size_t kUnlimited = 0;
    constexpr size_t kBigPayload = 64 * 1024; // well over httplib's default 8 KiB form limit
    constexpr const char* kFormType = "application/x-www-form-urlencoded";

    m_srv->stop();
    m_srv.reset();
    m_srv = std::make_shared<httpsrv::Server>("test", kUnlimited);

    std::atomic<int> handlerCalls {0};
    std::atomic<size_t> receivedSize {0};

    auto handler = [&](const httplib::Request& req, httplib::Response& res)
    {
        handlerCalls++;
        receivedSize = req.body.size();
        res.status = 200;
        res.set_content("OK", "text/plain");
    };

    m_srv->template addRoute<httplib::Request, httplib::Response>(method, route, handler);
    m_srv->start(getSocketPath("test.sock"));

    httplib::Client cli(getSocketPath("test.sock").string(), true);
    cli.set_address_family(AF_UNIX);

    httplib::Headers headers {};
    const auto body = makePayload(kBigPayload);

    httplib::Result res;
    if (method == httpsrv::Method::POST)
    {
        res = cli.Post(route.c_str(), headers, body, kFormType);
    }
    else // PUT
    {
        res = cli.Put(route.c_str(), headers, body, kFormType);
    }

    ASSERT_TRUE(res);
    ASSERT_EQ(res->status, 200);
    ASSERT_EQ(handlerCalls.load(), 1);
    ASSERT_EQ(receivedSize.load(), kBigPayload);
}

TEST_P(BodyRouteTest, HandlerCustom413BodyIsPreserved)
{
    auto [method, route, /*cliReq*/ _] = GetParam();

    if (method != httpsrv::Method::POST && method != httpsrv::Method::PUT)
    {
        GTEST_SKIP() << "No request body for this method in current parametrization.";
    }

    constexpr size_t kLimitBytes = 16;
    constexpr const char* kCustomBody = R"({"status":"ERROR","error":"custom 413 from handler"})";

    m_srv->stop();
    m_srv.reset();
    m_srv = std::make_shared<httpsrv::Server>("test", kLimitBytes);

    std::atomic<int> handlerCalls {0};
    auto handler = [&](const httplib::Request&, httplib::Response& res)
    {
        handlerCalls++;
        res.status = httplib::StatusCode::PayloadTooLarge_413;
        res.set_content(kCustomBody, "application/json");
    };

    m_srv->template addRoute<httplib::Request, httplib::Response>(method, route, handler);
    m_srv->start(getSocketPath("test.sock"));

    httplib::Client cli(getSocketPath("test.sock").string(), true);
    cli.set_address_family(AF_UNIX);

    httplib::Headers headers {{"Content-Type", "text/plain"}};

    httplib::Result res;
    if (method == httpsrv::Method::POST)
    {
        res = cli.Post(route.c_str(), headers, "small", "text/plain");
    }
    else // PUT
    {
        res = cli.Put(route.c_str(), headers, "small", "text/plain");
    }

    ASSERT_TRUE(res);
    ASSERT_EQ(res->status, 413);
    ASSERT_EQ(res->body, kCustomBody);
    ASSERT_EQ(handlerCalls.load(), 1);
}

INSTANTIATE_TEST_SUITE_P(
    ServerP,
    RouteTest,
    ::testing::Values(RoutesT(httpsrv::Method::GET,
                              "/test",
                              [](httplib::Client& cli, const std::string& route, const httplib::Headers&)
                              { return cli.Get(route.c_str()); }),
                      RoutesT(httpsrv::Method::POST,
                              "/test",
                              [](httplib::Client& cli, const std::string& route, const httplib::Headers& headers)
                              { return cli.Post(route.c_str(), headers, "test", "text/plain"); }),
                      RoutesT(httpsrv::Method::PUT,
                              "/test",
                              [](httplib::Client& cli, const std::string& route, const httplib::Headers& headers)
                              { return cli.Put(route.c_str(), headers, "test", "text/plain"); }),
                      RoutesT(httpsrv::Method::DELETE,
                              "/test",
                              [](httplib::Client& cli, const std::string& route, const httplib::Headers&)
                              { return cli.Delete(route.c_str()); })));

INSTANTIATE_TEST_SUITE_P(
    ServerPayloadP,
    BodyRouteTest,
    ::testing::Values(RoutesT(httpsrv::Method::POST,
                              "/test",
                              [](httplib::Client& cli, const std::string& route, const httplib::Headers& headers)
                              { return cli.Post(route.c_str(), headers, "test", "text/plain"); }),
                      RoutesT(httpsrv::Method::PUT,
                              "/test",
                              [](httplib::Client& cli, const std::string& route, const httplib::Headers& headers)
                              { return cli.Put(route.c_str(), headers, "test", "text/plain"); })));

/*******************************************************************************
 * Requests without Content-Length
 ******************************************************************************/
namespace
{
/**
 * @brief Send a raw request over the unix socket and read the whole answer.
 *
 * The write side stays open, as a client waiting for its answer keeps it. Gives up after `timeoutSec`.
 */
std::string rawRequest(const std::filesystem::path& socketPath, const std::string& request, int timeoutSec = 3)
{
    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
    {
        return {};
    }

    sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path) - 1);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
    {
        ::close(fd);
        return {};
    }

    timeval tv {};
    tv.tv_sec = timeoutSec;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (::write(fd, request.data(), request.size()) != static_cast<ssize_t>(request.size()))
    {
        ::close(fd);
        return {};
    }

    std::string answer;
    char buf[1024];
    for (;;)
    {
        const auto n = ::read(fd, buf, sizeof(buf));
        if (n <= 0)
        {
            break;
        }
        answer.append(buf, static_cast<size_t>(n));
    }
    ::close(fd);
    return answer;
}
} // namespace

class NoContentLengthTest
    : public ServerTest
    , public ::testing::WithParamInterface<std::pair<httpsrv::Method, std::string>>
{
};

TEST_P(NoContentLengthTest, RequestWithoutLengthReachesTheHandlerWithAnEmptyBody)
{
    const auto& [method, methodName] = GetParam();
    std::atomic<int> handlerCalls {0};
    std::atomic<bool> emptyBody {false};

    m_srv->template addRoute<httplib::Request, httplib::Response>(
        method,
        "/test",
        [&handlerCalls, &emptyBody](const httplib::Request& req, httplib::Response& res)
        {
            ++handlerCalls;
            emptyBody = req.body.empty();
            res.status = 200;
            res.set_content("OK", "text/plain");
        });
    m_srv->start(getSocketPath("test.sock"));

    const auto start = std::chrono::steady_clock::now();
    const auto answer = rawRequest(getSocketPath("test.sock"),
                                   methodName + " /test HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    const auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_EQ(answer.rfind("HTTP/1.1 200", 0), 0u) << answer;
    EXPECT_NE(answer.find("OK"), std::string::npos) << answer;
    EXPECT_EQ(handlerCalls.load(), 1);
    EXPECT_TRUE(emptyBody.load());
    // Answered at once, not after the server's read timeout
    EXPECT_LT(elapsed, std::chrono::seconds(2));
}

INSTANTIATE_TEST_SUITE_P(ServerP,
                         NoContentLengthTest,
                         ::testing::Values(std::make_pair(httpsrv::Method::POST, std::string {"POST"}),
                                           std::make_pair(httpsrv::Method::PUT, std::string {"PUT"}),
                                           std::make_pair(httpsrv::Method::DELETE, std::string {"DELETE"})));

TEST_F(ServerTest, BodyWithExplicitLengthIsStillRead)
{
    std::string received;
    m_srv->template addRoute<httplib::Request, httplib::Response>(
        httpsrv::Method::POST,
        "/test",
        [&received](const httplib::Request& req, httplib::Response& res)
        {
            received = req.body;
            res.status = 200;
            res.set_content("OK", "text/plain");
        });
    m_srv->start(getSocketPath("test.sock"));

    const auto answer =
        rawRequest(getSocketPath("test.sock"),
                   "POST /test HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 4\r\n\r\nabcd");

    EXPECT_EQ(answer.rfind("HTTP/1.1 200", 0), 0u) << answer;
    EXPECT_EQ(received, "abcd");
}

TEST_F(ServerTest, WrongMethodOnExistingRouteIs405WithAllow)
{
    m_srv->template addRoute<httplib::Request, httplib::Response>(httpsrv::Method::POST,
                                                                  "/test",
                                                                  [](const httplib::Request&, httplib::Response& res)
                                                                  {
                                                                      res.status = 200;
                                                                      res.set_content("OK", "text/plain");
                                                                  });
    m_srv->start(getSocketPath("test.sock"));

    httplib::Client cli(getSocketPath("test.sock").string(), true);
    cli.set_address_family(AF_UNIX);

    auto res = cli.Get("/test");

    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 405);
    EXPECT_EQ(res->get_header_value("Allow"), "POST");
    EXPECT_EQ(res->body, "Method not allowed. Allowed: POST.");
}

TEST_F(ServerTest, UnknownRouteIs404WithReason)
{
    m_srv->template addRoute<httplib::Request, httplib::Response>(httpsrv::Method::POST,
                                                                  "/test",
                                                                  [](const httplib::Request&, httplib::Response& res)
                                                                  {
                                                                      res.status = 200;
                                                                      res.set_content("OK", "text/plain");
                                                                  });
    m_srv->start(getSocketPath("test.sock"));

    httplib::Client cli(getSocketPath("test.sock").string(), true);
    cli.set_address_family(AF_UNIX);

    auto res = cli.Post("/other", "x", "text/plain");

    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 404);
    EXPECT_EQ(res->body, "Not found: no such route.");
}

TEST_F(ServerTest, HandlerOwn404IsKept)
{
    m_srv->template addRoute<httplib::Request, httplib::Response>(
        httpsrv::Method::POST, "/test", [](const httplib::Request&, httplib::Response& res) { res.status = 404; });
    m_srv->start(getSocketPath("test.sock"));

    httplib::Client cli(getSocketPath("test.sock").string(), true);
    cli.set_address_family(AF_UNIX);

    auto res = cli.Post("/test", "x", "text/plain");

    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 404);
    EXPECT_TRUE(res->body.empty());
}
