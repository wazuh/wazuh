// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include <base/logging.hpp>
#include <fastmetrics/registry.hpp>
#include <httpsrv/apiServer.hpp>

using namespace std::chrono_literals;
using httpsrv::ApiRouteRegistrar;
using httpsrv::Method;
using httpsrv::Request;
using httpsrv::Response;
using httpsrv::RouteClass;
using httpsrv::RouteOptions;

namespace
{
std::string uniqueSocketPath(const char* tag)
{
    static std::atomic<int> counter {0};
    return "/tmp/httpsrv_api_" + std::string {tag} + "_" + std::to_string(::getpid()) + "_"
           + std::to_string(counter.fetch_add(1)) + ".sock";
}

/// Sends @p raw and reads until the server closes the connection.
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

/// A head declaring @p length body bytes, sent without them: a 413 must come from the declared length.
std::string headDeclaring(const std::string& target, std::size_t length)
{
    return "POST " + target + " HTTP/1.1\r\nHost: localhost\r\nContent-Length: " + std::to_string(length)
           + "\r\nConnection: close\r\n\r\n";
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

std::string bodyOf(const std::string& response)
{
    const auto at = response.find("\r\n\r\n");
    return at == std::string::npos ? std::string {} : response.substr(at + 4);
}

void ok(const Request&, Response& res)
{
    res.setContent("{}", "application/json");
}
class ApiServerTest : public ::testing::Test
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

TEST_F(ApiServerTest, PayloadTooLargeTextIsTheDocumentedOne)
{
    EXPECT_EQ("Payload too large. Max allowed: 1024 bytes (1 KiB).", httpsrv::payloadTooLargeText(1024));
    EXPECT_EQ("Payload too large.", httpsrv::payloadTooLargeText(0));
}

TEST_F(ApiServerTest, ControlRouteOverTheLimitGetsTheDocumentedText)
{
    const auto path = socketPath("limit");
    auto server = httpsrv::makeApiServer();
    std::atomic<int> calls {0};
    ApiRouteRegistrar routes {server, 1024};
    routes.addRoute(Method::POST,
                    "/_internal/router/table/get",
                    [&](const Request& req, Response& res)
                    {
                        ++calls;
                        ok(req, res);
                    });
    server->start(path);

    const auto rejected = roundTrip(path, headDeclaring("/_internal/router/table/get", 1025));
    const auto accepted = roundTrip(path, post("/_internal/router/table/get", std::string(1024, 'x')));
    server->shutdown(1s);

    EXPECT_EQ(413, statusOf(rejected));
    EXPECT_EQ("Payload too large. Max allowed: 1024 bytes (1 KiB).", bodyOf(rejected));
    EXPECT_NE(std::string::npos, rejected.find("\r\nContent-Type: text/plain\r\n")) << rejected;
    EXPECT_EQ(200, statusOf(accepted)) << "at the limit is fine";
    EXPECT_EQ(1, calls.load()) << "the rejected request never reached the handler";
}

TEST_F(ApiServerTest, ZeroLimitMeansUnlimited)
{
    const auto path = socketPath("unlimited");
    auto server = httpsrv::makeApiServer();
    std::atomic<std::size_t> seen {0};
    ApiRouteRegistrar routes {server, 0};
    routes.addRoute(Method::POST,
                    "/_internal/content/namespace/import",
                    [&](const Request& req, Response& res)
                    {
                        seen = req.body.size();
                        ok(req, res);
                    });
    server->start(path);

    // Well above the control class's own 64 KiB cap.
    const std::string body(2U * 1024U * 1024U, 'x');
    const auto response = roundTrip(path, post("/_internal/content/namespace/import", body));
    server->shutdown(1s);

    EXPECT_EQ(200, statusOf(response));
    EXPECT_EQ(body.size(), seen.load());
}

TEST_F(ApiServerTest, LivenessRouteIsCappedAt4KiBWithTheDocumentedText)
{
    const auto path = socketPath("liveness");
    auto server = httpsrv::makeApiServer();
    ApiRouteRegistrar routes {server, 0};
    RouteOptions liveness;
    liveness.cls = RouteClass::Liveness;
    liveness.runInline = true;
    routes.addRoute(Method::POST, "/metrics/get", ok, liveness);
    server->start(path);

    const auto rejected = roundTrip(path, headDeclaring("/metrics/get", httpsrv::API_LIVENESS_BODY_CAP + 1));
    const auto accepted = roundTrip(path, post("/metrics/get", std::string(httpsrv::API_LIVENESS_BODY_CAP, 'x')));
    server->shutdown(1s);

    EXPECT_EQ(413, statusOf(rejected));
    EXPECT_EQ("Payload too large. Max allowed: 4096 bytes (4 KiB).", bodyOf(rejected));
    EXPECT_EQ(200, statusOf(accepted));
}

TEST_F(ApiServerTest, PublishesApiMetrics)
{
    auto server = httpsrv::makeApiServer();
    for (const auto* suffix : {"inflight.bytes",
                               "inflight.requests",
                               "sessions",
                               "queue.depth",
                               "running",
                               "shed.budget",
                               "shed.connections",
                               "shed.executor_full",
                               "shed.shutdown",
                               "handler_errors",
                               "rejected.too_large"})
    {
        EXPECT_TRUE(fastmetrics::manager().exists(std::string {"server.api."} + suffix)) << suffix;
    }
}
