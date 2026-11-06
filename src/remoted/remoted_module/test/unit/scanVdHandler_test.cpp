/*
 * Wazuh remoted module - ScanVdHandlerImpl unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Exercises the synchronous admission passthrough against a real VdClient and a real
 * FakeVdServer (see fakeVdServer.hpp) standing in for VD's /offset and /scan endpoints. The
 * handler holds no state and every decision happens inline in handleVdScan's callback, so the
 * assertions are immediate -- there are no background workers left to synchronize with.
 */

#include "common/vdClient.hpp"
#include "fakeVdServer.hpp"
#include "scanvd/scanVdHandler.hpp"
#include "scanvd/scanVdMetrics.hpp"
#include "vdHttpClient.hpp"

#include <wazuh_metrics/manager.hpp>

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <json.hpp>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std::chrono_literals;
using remoted::common::VdClient;
using remoted::downstream::DownstreamCallback;
using remoted::downstream::DownstreamError;
using remoted::downstream::DownstreamRequest;
using remoted::downstream::DownstreamResponse;
using remoted::downstream::IDownstreamClient;
using remoted::endpoints::scanvd::ScanVdOutcome;
using remoted::endpoints::scanvd::ScanVdResponse;
using remoted::scanvd::makeScanVdMetrics;
using remoted::scanvd::ScanVdHandlerImpl;
using remoted::scanvd::ScanVdMetrics;
using remoted::test::FakeVdServer;
using remoted::test::makeUniqueVdSocketPath;
using remoted::test::makeVdHttpClient;

namespace
{
    constexpr auto VDCLIENT_TTL = 30ms;
    constexpr auto VDCLIENT_FAILURE_RETRY = 30ms;

    ScanVdResponse callSync(ScanVdHandlerImpl& handler, uint32_t agentId, uint64_t offset)
    {
        ScanVdResponse result {};
        handler.handleVdScan(agentId, offset, [&result](const ScanVdResponse& r) { result = r; });
        return result;
    }

    /// One test's whole rig: fake VD + one client for its socket + real VdClient + metrics + the handler under
    /// test, wired as the facade wires them.
    struct Rig
    {
        explicit Rig(const std::string& tag,
                     long readTimeout = ScanVdHandlerImpl::VD_SCAN_READ_TIMEOUT_SECONDS,
                     long writeTimeout = ScanVdHandlerImpl::VD_SCAN_WRITE_TIMEOUT_SECONDS)
            : socketPath(makeUniqueVdSocketPath(tag))
            , server(socketPath)
            , httpClient(makeVdHttpClient())
            , vdClient(std::make_shared<VdClient>(httpClient, socketPath, VDCLIENT_TTL, VDCLIENT_FAILURE_RETRY))
            , metrics(makeScanVdMetrics(metricsManager))
            , handler(vdClient, httpClient, metrics, socketPath, readTimeout, writeTimeout)
        {
            server.setOffset(100);
        }

        std::string socketPath;
        FakeVdServer server;
        std::shared_ptr<IDownstreamClient> httpClient;
        std::shared_ptr<VdClient> vdClient;
        wazuh::metrics::Manager metricsManager;
        ScanVdMetrics metrics;
        ScanVdHandlerImpl handler;
    };

    /// Records the request it is handed and answers 200 at once, without touching a socket.
    class CapturingClient final : public IDownstreamClient
    {
    public:
        void sendAsync(DownstreamRequest req, std::shared_ptr<const void>, DownstreamCallback onComplete) override
        {
            body = std::string {req.body};
            request = std::move(req);
            request.body = {};
            DownstreamResponse response;
            response.status = 200;
            response.body = "{}";
            onComplete(DownstreamError::None, std::move(response));
        }

        DownstreamRequest request;
        std::string body;
    };

    /// A listener that never accepts, its accept backlog filled to the brim: the next connect is refused
    /// with EAGAIN at once instead of waiting for a slot.
    class FullBacklogListener
    {
    public:
        explicit FullBacklogListener(std::string path)
            : m_path(std::move(path))
        {
            ::unlink(m_path.c_str());
            sockaddr_un addr {};
            addr.sun_family = AF_UNIX;
            std::strncpy(addr.sun_path, m_path.c_str(), sizeof(addr.sun_path) - 1);
            m_listenFd = ::socket(AF_UNIX, SOCK_STREAM, 0);
            if (m_listenFd < 0 || ::bind(m_listenFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
                ::listen(m_listenFd, 0) != 0)
            {
                throw std::runtime_error(std::string {"listener setup failed: "} + std::strerror(errno));
            }
            for (int attempt = 0; attempt < 64; ++attempt)
            {
                const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
                if (fd < 0)
                {
                    break;
                }
                if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
                {
                    const int error = errno;
                    ::close(fd);
                    m_full = (error == EAGAIN);
                    break;
                }
                m_fillers.push_back(fd);
            }
        }

        ~FullBacklogListener()
        {
            for (const int fd : m_fillers)
            {
                ::close(fd);
            }
            if (m_listenFd >= 0)
            {
                ::close(m_listenFd);
            }
            ::unlink(m_path.c_str());
        }

        FullBacklogListener(const FullBacklogListener&) = delete;
        FullBacklogListener& operator=(const FullBacklogListener&) = delete;

        bool full() const
        {
            return m_full;
        }

    private:
        std::string m_path;
        int m_listenFd {-1};
        std::vector<int> m_fillers;
        bool m_full {false};
    };

    /// The offset gate passes against a fake VD; the scan goes to `scanSocketPath` instead.
    struct SplitRig
    {
        explicit SplitRig(const std::string& tag, std::string scanSocketPath)
            : offsetSocketPath(makeUniqueVdSocketPath(tag + "-offset"))
            , server(offsetSocketPath)
            , httpClient(makeVdHttpClient())
            , vdClient(std::make_shared<VdClient>(httpClient, offsetSocketPath, 5s, VDCLIENT_FAILURE_RETRY))
            , metrics(makeScanVdMetrics(metricsManager))
            , handler(vdClient, httpClient, metrics, std::move(scanSocketPath))
        {
            server.setOffset(100);
        }

        std::string offsetSocketPath;
        FakeVdServer server;
        std::shared_ptr<IDownstreamClient> httpClient;
        std::shared_ptr<VdClient> vdClient;
        wazuh::metrics::Manager metricsManager;
        ScanVdMetrics metrics;
        ScanVdHandlerImpl handler;
    };
} // namespace

TEST(ScanVdHandlerTest, RejectsANullHttpClient)
{
    wazuh::metrics::Manager metricsManager;
    ScanVdMetrics metrics {makeScanVdMetrics(metricsManager)};
    const auto vdClient = std::make_shared<VdClient>(makeVdHttpClient(), makeUniqueVdSocketPath("null-client"));

    EXPECT_THROW((ScanVdHandlerImpl {vdClient, nullptr, metrics}), std::invalid_argument);
}

/**
 * Both calls -- the offset query and the scan -- first have to reach VD's socket, each under its own
 * fixed connect deadline. Those are part of what a slow request can pay, so the startup check counts them.
 */
TEST(ScanVdHandlerTest, TheStartupBudgetCountsBothConnectDeadlines)
{
    EXPECT_EQ(ScanVdHandlerImpl::budgetMsFor(5, 5),
              (5 + 5 + VdClient::OFFSET_READ_TIMEOUT_SECONDS + VdClient::OFFSET_WRITE_TIMEOUT_SECONDS) * 1000 +
                  2 * VdClient::CONNECT_TIMEOUT_MS);
    EXPECT_EQ(ScanVdHandlerImpl::budgetMsFor(5, 5), 14000) << "the defaults, spelled out";
}

TEST(ScanVdHandlerTest, TheScanRequestCarriesTheConfiguredDeadlines)
{
    const auto socketPath = makeUniqueVdSocketPath("request-shape");
    FakeVdServer server {socketPath};
    server.setOffset(100);
    const auto vdClient = std::make_shared<VdClient>(makeVdHttpClient(), socketPath);

    auto capturing = std::make_shared<CapturingClient>();
    wazuh::metrics::Manager metricsManager;
    ScanVdMetrics metrics {makeScanVdMetrics(metricsManager)};
    ScanVdHandlerImpl handler {vdClient, capturing, metrics, socketPath, /*read=*/30, /*write=*/40};

    ASSERT_EQ(callSync(handler, 42, 100).outcome, ScanVdOutcome::Accepted);
    EXPECT_EQ(capturing->request.socketPath, socketPath);
    EXPECT_EQ(capturing->request.method, remoted::http::Method::Post);
    EXPECT_EQ(capturing->request.path, "/vulnerability-detector/scan");
    EXPECT_EQ(capturing->request.contentType, "application/json");
    EXPECT_EQ(capturing->request.writeTimeoutMs, 40000) << "remoted.vd_scan_write_timeout, not the client's default";
    EXPECT_EQ(capturing->request.responseTimeoutMs, 30000) << "remoted.vd_scan_read_timeout, not the client's default";
    EXPECT_EQ(nlohmann::json::parse(capturing->body).value("agent_id", std::string {}), "42");
}

TEST(ScanVdHandlerTest, AMissingScannerSocketIsAPromptVdUnreachable)
{
    SplitRig rig {"missing", makeUniqueVdSocketPath("missing-scan")};

    const auto started = std::chrono::steady_clock::now();
    const auto response = callSync(rig.handler, 7, 100);
    const auto elapsed = std::chrono::steady_clock::now() - started;

    EXPECT_EQ(response.outcome, ScanVdOutcome::VdRejected);
    EXPECT_EQ(response.errorCode, "vd_unreachable");
    EXPECT_EQ(rig.metrics.vdError->get(), 1u);
    EXPECT_LT(elapsed, 900ms) << "nothing listening is refused at once, not after the connect deadline";
}

TEST(ScanVdHandlerTest, AFullAcceptBacklogIsAPromptVdUnreachable)
{
    const auto scanSocketPath = makeUniqueVdSocketPath("backlog-scan");
    FullBacklogListener listener {scanSocketPath};
    ASSERT_TRUE(listener.full()) << "the backlog never filled; the case below would not test a full one";
    SplitRig rig {"backlog", scanSocketPath};

    const auto started = std::chrono::steady_clock::now();
    const auto response = callSync(rig.handler, 7, 100);
    const auto elapsed = std::chrono::steady_clock::now() - started;

    EXPECT_EQ(response.outcome, ScanVdOutcome::VdRejected);
    EXPECT_EQ(response.errorCode, "vd_unreachable");
    EXPECT_EQ(rig.metrics.vdError->get(), 1u);
    EXPECT_LT(elapsed, 900ms) << "a full backlog refuses a non-blocking connect at once, not after the deadline";
}

/**
 * The facade checks this budget against remoted.http_request_timeout at startup, so it has to cover
 * every deadline the request can actually pay -- including getOffset()'s, which runs synchronously
 * before the scan POST and, on a stale cache, is a round trip with its own two.
 */
TEST(ScanVdHandlerTest, TheStartupBudgetCoversTheOffsetQueryToo)
{
    EXPECT_GT(ScanVdHandlerImpl::budgetMsFor(ScanVdHandlerImpl::VD_SCAN_READ_TIMEOUT_SECONDS,
                                             ScanVdHandlerImpl::VD_SCAN_WRITE_TIMEOUT_SECONDS),
              (ScanVdHandlerImpl::VD_SCAN_READ_TIMEOUT_SECONDS + ScanVdHandlerImpl::VD_SCAN_WRITE_TIMEOUT_SECONDS) *
                  1000)
        << "the offset query's deadlines are part of the request path, not free";
}

TEST(ScanVdHandlerTest, TheBudgetFollowsTheConfiguredTimeouts)
{
    Rig configured {"configured-budget", 30, 40};
    Rig unset {"unset-budget", 0, 0};

    EXPECT_EQ(configured.handler.getBudgetMs(), ScanVdHandlerImpl::budgetMsFor(30, 40))
        << "the startup check must see remoted.vd_scan_*_timeout, not the compiled-in defaults";
    EXPECT_EQ(unset.handler.getBudgetMs(),
              ScanVdHandlerImpl::budgetMsFor(ScanVdHandlerImpl::VD_SCAN_READ_TIMEOUT_SECONDS,
                                             ScanVdHandlerImpl::VD_SCAN_WRITE_TIMEOUT_SECONDS))
        << "a <=0 timeout falls back to the default instead of disabling the deadline";
}

TEST(ScanVdHandlerTest, VersionMismatchRejectsWithoutEverTriggeringAScan)
{
    Rig rig {"mismatch"};

    const auto response = callSync(rig.handler, 42, 999);
    EXPECT_EQ(response.outcome, ScanVdOutcome::VersionMismatch);
    EXPECT_EQ(response.currentOffset, 100u);
    EXPECT_EQ(rig.server.scanRequestCount(), 0u) << "a mismatched offset must never reach VD's /scan endpoint";
    EXPECT_EQ(rig.metrics.versionMismatch->get(), 1u);
    EXPECT_EQ(rig.metrics.accepted->get(), 0u);
}

TEST(ScanVdHandlerTest, ZeroAgentIdIsRejectedAsInvalidAgent)
{
    Rig rig {"invalid"};

    const auto response = callSync(rig.handler, 0, 100);
    EXPECT_EQ(response.outcome, ScanVdOutcome::InvalidAgent);
    EXPECT_EQ(rig.server.scanRequestCount(), 0u);
    EXPECT_EQ(rig.metrics.invalidAgent->get(), 1u);
}

TEST(ScanVdHandlerTest, VdQueueingTheScanIsA200AndExactlyOnePost)
{
    Rig rig {"accepted"};
    // VD's contract after the redesign: /scan answers 200 {} at ADMISSION.
    rig.server.setScanHandler([](const httplib::Request&, httplib::Response& res)
                              { res.set_content("{}", "application/json"); });

    const auto response = callSync(rig.handler, 7, 100);
    EXPECT_EQ(response.outcome, ScanVdOutcome::Accepted);
    EXPECT_EQ(rig.server.scanRequestCount(), 1u) << "one request, one POST -- there is no retry machinery";
    EXPECT_EQ(rig.metrics.accepted->get(), 1u);

    // A second request for the same agent is ANOTHER honest passthrough (dedup, if any, is
    // VD's business): two requests, two POSTs.
    EXPECT_EQ(callSync(rig.handler, 7, 100).outcome, ScanVdOutcome::Accepted);
    EXPECT_EQ(rig.server.scanRequestCount(), 2u);
}

TEST(ScanVdHandlerTest, AVdCapacityRejectionPassesThroughAsQueueFull)
{
    Rig rig {"full"};
    rig.server.setScanHandler(
        [](const httplib::Request&, httplib::Response& res)
        {
            res.status = 503;
            res.set_content(R"({"error":"scan_queue_full","retryable":true})", "application/json");
        });

    const auto response = callSync(rig.handler, 7, 100);
    EXPECT_EQ(response.outcome, ScanVdOutcome::VdRejected);
    EXPECT_EQ(response.errorCode, "scan_queue_full") << "the agent-facing body carries VD's actual cause";
    EXPECT_EQ(rig.metrics.queueFull->get(), 1u) << "capacity rejections keep their own counter";
    EXPECT_EQ(rig.metrics.vdError->get(), 0u);
    EXPECT_EQ(rig.metrics.accepted->get(), 0u);
    EXPECT_EQ(rig.server.scanRequestCount(), 1u) << "no retry: the agent's next notify is the retry";
}

TEST(ScanVdHandlerTest, AVdIndexerOutageKeepsItsOwnCounterOffTheRelayWindow)
{
    Rig rig {"idxdown"};
    rig.server.setScanHandler(
        [](const httplib::Request&, httplib::Response& res)
        {
            res.status = 503;
            res.set_content(R"({"error":"indexer_unavailable","retryable":true})", "application/json");
        });

    const auto response = callSync(rig.handler, 7, 100);
    EXPECT_EQ(response.outcome, ScanVdOutcome::VdRejected);
    EXPECT_EQ(response.errorCode, "indexer_unavailable") << "the agent-facing body carries VD's actual cause";
    EXPECT_EQ(rig.metrics.indexerUnavailable->get(), 1u) << "VD's own reported cause keeps its own counter";
    EXPECT_EQ(rig.metrics.vdError->get(), 0u)
        << "an indexer outage must not masquerade as a remoted<->VD relay failure";
    EXPECT_EQ(rig.metrics.queueFull->get(), 0u);
}

TEST(ScanVdHandlerTest, AVdReadinessRejectionPassesItsCodeThrough)
{
    Rig rig {"notready"};
    rig.server.setScanHandler(
        [](const httplib::Request&, httplib::Response& res)
        {
            res.status = 503;
            res.set_content(R"({"error":"feed_not_ready","retryable":true})", "application/json");
        });

    const auto response = callSync(rig.handler, 7, 100);
    EXPECT_EQ(response.outcome, ScanVdOutcome::VdRejected);
    EXPECT_EQ(response.errorCode, "feed_not_ready");
    EXPECT_EQ(rig.metrics.vdError->get(), 1u) << "non-capacity rejections land on vd_error";
    EXPECT_EQ(rig.metrics.queueFull->get(), 0u);
}

TEST(ScanVdHandlerTest, AnUnreachableVdIsAnHonest503NotASilentDrop)
{
    const auto socketPath = makeUniqueVdSocketPath("unreachable");
    // A server only for /offset, torn down before the scan POST: the offset gate passes on the
    // cached value, then the POST hits a dead socket.
    auto server = std::make_unique<FakeVdServer>(socketPath);
    server->setOffset(100);

    const auto httpClient = makeVdHttpClient();
    auto vdClient = std::make_shared<VdClient>(httpClient, socketPath, 5s, VDCLIENT_FAILURE_RETRY);
    ASSERT_EQ(vdClient->getOffset(), 100u) << "prime the cache while the server is up";

    wazuh::metrics::Manager metricsManager;
    ScanVdMetrics metrics {makeScanVdMetrics(metricsManager)};
    ScanVdHandlerImpl handler(vdClient, httpClient, metrics, socketPath);

    server.reset(); // VD goes away

    ScanVdResponse response {};
    handler.handleVdScan(7, 100, [&response](const ScanVdResponse& r) { response = r; });
    EXPECT_EQ(response.outcome, ScanVdOutcome::VdRejected);
    EXPECT_EQ(response.errorCode, "vd_unreachable");
    EXPECT_EQ(metrics.vdError->get(), 1u);
}

TEST(ScanVdHandlerTest, AnUnexpectedVdStatusMapsToVdError)
{
    Rig rig {"weird"};
    rig.server.setScanHandler(
        [](const httplib::Request&, httplib::Response& res)
        {
            res.status = 500;
            res.set_content("not json at all", "text/plain");
        });

    const auto response = callSync(rig.handler, 7, 100);
    EXPECT_EQ(response.outcome, ScanVdOutcome::VdRejected);
    EXPECT_EQ(response.errorCode, "vd_error") << "an unparseable body degrades to the generic code";
    EXPECT_EQ(rig.metrics.vdError->get(), 1u);
}

TEST(ScanVdHandlerTest, TheScanPostCarriesTheAgentIdAsAString)
{
    Rig rig {"body"};
    std::string capturedBody;
    rig.server.setScanHandler(
        [&capturedBody](const httplib::Request& req, httplib::Response& res)
        {
            capturedBody = req.body;
            res.set_content("{}", "application/json");
        });

    ASSERT_EQ(callSync(rig.handler, 42, 100).outcome, ScanVdOutcome::Accepted);
    const auto json = nlohmann::json::parse(capturedBody);
    EXPECT_EQ(json.value("agent_id", std::string {}), "42")
        << "VD's route expects the id as a JSON string -- the wire shape is part of the contract";
}
