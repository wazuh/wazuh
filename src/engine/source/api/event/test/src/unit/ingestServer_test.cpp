// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <stdexcept>
#include <string>
#include <tuple>

#include <api/event/ingestServer.hpp>
#include <base/logging.hpp>
#include <dumper/mockDumper.hpp>
#include <fastmetrics/registry.hpp>
#include <router/mockRouter.hpp>

using api::event::IngestLimits;
using api::event::makeIngestServer;
using api::event::validateIngestLimits;
using router::mocks::MockRouterAPI;

namespace
{
constexpr std::size_t MIB {1024U * 1024U};

std::string socketPath()
{
    static std::atomic<int> counter {0};
    return "/tmp/ingest_" + std::to_string(::getpid()) + "_" + std::to_string(counter.fetch_add(1)) + ".sock";
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
    timeval timeout {10, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    return fd;
}

std::string readAll(int fd)
{
    std::string out;
    char buffer[4096];
    for (ssize_t n; (n = ::recv(fd, buffer, sizeof(buffer), 0)) > 0;)
    {
        out.append(buffer, static_cast<std::size_t>(n));
    }
    return out;
}

std::string roundTrip(const std::string& path, const std::string& raw)
{
    const int fd = connectTo(path);
    if (fd < 0)
    {
        return {};
    }
    ::send(fd, raw.data(), raw.size(), MSG_NOSIGNAL);
    auto out = readAll(fd);
    ::close(fd);
    return out;
}

std::string head(std::size_t length, const std::string& extra = "X-Wazuh-Agent-Id: 001\r\n")
{
    return "POST /events/enriched HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-ndjson\r\n" + extra
           + "Content-Length: " + std::to_string(length) + "\r\n\r\n";
}

std::string batch()
{
    return "H {\"wazuh\":{\"agent\":{\"id\":\"001\"}}}\nE 1:syslog:hello\n";
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

class IngestServerTest : public ::testing::Test
{
protected:
    std::shared_ptr<testing::NiceMock<MockRouterAPI>> router = std::make_shared<testing::NiceMock<MockRouterAPI>>();
    std::shared_ptr<httpsrv::UdsServer> server;
    std::string path = socketPath();

    /// The limits the server is built with; a derived fixture overrides them.
    virtual IngestLimits limits() const { return IngestLimits {}; }

    void SetUp() override
    {
        // The fastmetrics manager is registered once for this binary (handlers_test.cpp).
        logging::testInit();
        server = makeIngestServer(router,
                                  std::make_shared<testing::NiceMock<dumper::mocks::MockDumper>>(),
                                  std::make_shared<agentcache::AgentMetadataCache>(std::chrono::seconds {300}),
                                  validateIngestLimits(limits()));
        server->start(path);
    }

    void TearDown() override
    {
        if (server)
        {
            server->shutdown(std::chrono::seconds {1});
        }
    }
};

/// A body cap equal to the in-flight budget: the smallest budget validation accepts for that cap.
class IngestServerLimitsTest : public IngestServerTest
{
protected:
    IngestLimits limits() const override { return IngestLimits {32 * MIB, 1024, 32 * MIB}; }
};

/// Case name, limits to validate, and the internal option the error must name (empty: the limits are valid).
using LimitsCase = std::tuple<std::string, IngestLimits, std::string>;

class IngestLimitsTest : public ::testing::TestWithParam<LimitsCase>
{
};

constexpr auto MAX_BODY_KEY = "analysisd.server_enriched_events_max_body_bytes";
constexpr auto MAX_CONNECTIONS_KEY = "analysisd.server_enriched_events_max_connections";
constexpr auto MAX_INFLIGHT_KEY = "analysisd.server_enriched_events_max_inflight_bytes";
} // namespace

TEST_P(IngestLimitsTest, ValidatesEachRangeNamingTheKey)
{
    const auto& limits = std::get<1>(GetParam());
    const auto& key = std::get<2>(GetParam());
    if (key.empty())
    {
        EXPECT_NO_THROW(validateIngestLimits(limits));
        return;
    }
    try
    {
        validateIngestLimits(limits);
        ADD_FAILURE() << "accepted an out-of-range " << key;
    }
    catch (const std::invalid_argument& e)
    {
        EXPECT_NE(std::string {e.what()}.find(key), std::string::npos) << e.what();
    }
}

INSTANTIATE_TEST_SUITE_P(
    Ranges,
    IngestLimitsTest,
    ::testing::Values(
        // Valid: the defaults, every minimum, every maximum.
        LimitsCase {"Defaults", IngestLimits {}, ""},
        LimitsCase {"Minimums", IngestLimits {32 * MIB, 16, 32 * MIB}, ""},
        LimitsCase {"Maximums", IngestLimits {1024 * MIB, 65536, 8192 * MIB}, ""},
        // One value just out of its range; the error names that option.
        LimitsCase {"BodyBelowMinimum", IngestLimits {32 * MIB - 1, 1024, 256 * MIB}, MAX_BODY_KEY},
        LimitsCase {"BodyAboveMaximum", IngestLimits {1024 * MIB + 1, 1024, 2048 * MIB}, MAX_BODY_KEY},
        LimitsCase {"ConnectionsBelowMinimum", IngestLimits {64 * MIB, 15, 256 * MIB}, MAX_CONNECTIONS_KEY},
        LimitsCase {"ConnectionsAboveMaximum", IngestLimits {64 * MIB, 65537, 256 * MIB}, MAX_CONNECTIONS_KEY},
        LimitsCase {"InFlightBelowBodyCap", IngestLimits {64 * MIB, 1024, 64 * MIB - 1}, MAX_INFLIGHT_KEY},
        LimitsCase {"InFlightAboveMaximum", IngestLimits {64 * MIB, 1024, 8192 * MIB + 1}, MAX_INFLIGHT_KEY}),
    [](const ::testing::TestParamInfo<LimitsCase>& info) { return std::get<0>(info.param); });

TEST_F(IngestServerTest, AcceptsABatchOnTheSocket)
{
    EXPECT_CALL(*router, postEvent(testing::_)).Times(1);

    const auto response = roundTrip(path, head(batch().size()) + batch());

    EXPECT_EQ(200, statusOf(response)) << response;
    EXPECT_EQ("", bodyOf(response));
}

// The cap is enforced from the declared length: the producer learns it before sending the body.
TEST_F(IngestServerTest, DeclaredBodyOverTheCapIs413BeforeTheBody)
{
    EXPECT_CALL(*router, postEvent(testing::_)).Times(0);

    const auto response = roundTrip(path, head(IngestLimits {}.maxBodyBytes + 1));

    EXPECT_EQ(413, statusOf(response)) << response;
}

TEST_F(IngestServerTest, RepeatedAgentIdIs400WithTheDocumentedBody)
{
    EXPECT_CALL(*router, postEvent(testing::_)).Times(0);

    const auto response =
        roundTrip(path, head(batch().size(), "X-Wazuh-Agent-Id: 001\r\nX-Wazuh-Agent-Id: 002\r\n") + batch());

    EXPECT_EQ(400, statusOf(response));
    EXPECT_EQ(R"({"error":"NDJson parser error, Expected exactly one X-Wazuh-Agent-Id header","code":400})",
              bodyOf(response));
}

TEST_F(IngestServerTest, ExpectContinueIsAnswered)
{
    EXPECT_CALL(*router, postEvent(testing::_)).Times(1);
    const int fd = connectTo(path);
    ASSERT_GE(fd, 0);

    const auto firstHead = head(batch().size(), "X-Wazuh-Agent-Id: 001\r\nExpect: 100-continue\r\n");
    ::send(fd, firstHead.data(), firstHead.size(), MSG_NOSIGNAL);
    char buffer[128];
    const auto n = ::recv(fd, buffer, sizeof(buffer), 0);
    const std::string interim {buffer, n > 0 ? static_cast<std::size_t>(n) : 0U};
    ::send(fd, batch().data(), batch().size(), MSG_NOSIGNAL);
    const auto final = readAll(fd);
    ::close(fd);

    EXPECT_EQ("HTTP/1.1 100 Continue\r\n\r\n", interim);
    EXPECT_EQ(200, statusOf(final)) << final;
}

// The values themselves are covered by httpsrv's metric tests; fastmetrics keeps the first registration of a
// name, so in this binary they follow the first ingest server a test created.
TEST_F(IngestServerTest, PublishesItsMetricsUnderServerIngest)
{
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
        EXPECT_TRUE(fastmetrics::manager().exists(std::string {"server.ingest."} + suffix)) << suffix;
    }
}

// With the in-flight budget equal to the body cap (the smallest valid pair), a batch of exactly the cap
// is accepted: the transport's per-request overhead must not lower the limit below the configured one.
TEST_F(IngestServerLimitsTest, ABatchOfExactlyTheBodyCapIsAcceptedWhenTheBudgetEqualsIt)
{
    const auto cap = limits().maxBodyBytes;

    // One header line, then 1 KiB event lines, the last one padded so the body is exactly the cap.
    std::string body = "H {\"wazuh\":{\"agent\":{\"id\":\"001\"}}}\n";
    const std::string prefix = "E 1:syslog:";
    const std::string line = prefix + std::string(1024 - prefix.size() - 1, 'x') + "\n";
    while (body.size() + 2 * line.size() <= cap)
    {
        body += line;
    }
    body += prefix + std::string(cap - body.size() - prefix.size() - 1, 'x') + "\n";
    ASSERT_EQ(cap, body.size());

    const auto atTheCap = roundTrip(path, head(body.size()) + body);
    const auto overTheCap = roundTrip(path, head(cap + 1));

    EXPECT_EQ(200, statusOf(atTheCap)) << atTheCap.substr(0, 200);
    EXPECT_EQ(413, statusOf(overTheCap)) << overTheCap.substr(0, 200);
}
