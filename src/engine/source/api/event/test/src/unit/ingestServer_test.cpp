// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <stdexcept>
#include <string>

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

    void SetUp() override
    {
        // The fastmetrics manager is registered once for this binary (handlers_test.cpp).
        logging::testInit();
        server = makeIngestServer(router,
                                  std::make_shared<testing::NiceMock<dumper::mocks::MockDumper>>(),
                                  std::make_shared<agentcache::AgentMetadataCache>(std::chrono::seconds {300}),
                                  validateIngestLimits(IngestLimits {}));
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
} // namespace

TEST(IngestLimitsTest, RejectsEachOutOfRangeValueNamingTheKey)
{
    const auto rejects = [](IngestLimits limits, const std::string& key)
    {
        try
        {
            validateIngestLimits(limits);
            ADD_FAILURE() << "accepted an out-of-range " << key;
        }
        catch (const std::invalid_argument& e)
        {
            EXPECT_NE(std::string {e.what()}.find(key), std::string::npos) << e.what();
        }
    };

    EXPECT_NO_THROW(validateIngestLimits(IngestLimits {}));
    EXPECT_NO_THROW(validateIngestLimits(IngestLimits {32 * MIB, 16, 32 * MIB}));
    EXPECT_NO_THROW(validateIngestLimits(IngestLimits {1024 * MIB, 65536, 8192 * MIB}));

    rejects({32 * MIB - 1, 1024, 256 * MIB}, "analysisd.server_enriched_events_max_body_bytes");
    rejects({1024 * MIB + 1, 1024, 2048 * MIB}, "analysisd.server_enriched_events_max_body_bytes");
    rejects({64 * MIB, 15, 256 * MIB}, "analysisd.server_enriched_events_max_connections");
    rejects({64 * MIB, 65537, 256 * MIB}, "analysisd.server_enriched_events_max_connections");
    rejects({64 * MIB, 1024, 64 * MIB - 1}, "analysisd.server_enriched_events_max_inflight_bytes");
    rejects({64 * MIB, 1024, 8192 * MIB + 1}, "analysisd.server_enriched_events_max_inflight_bytes");
}

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
