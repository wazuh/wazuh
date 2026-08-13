/*
 * Wazuh remoted module - /control + /scan/vd end-to-end integration test
 * Copyright (C) 2015, Wazuh Inc.
 * August 10, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Drives a REAL TLS RestinioHttpServer + real AuthGateway + real ControlHandler +
 * real ScanVdHandlerImpl over the wire, wired exactly as RemotedModuleFacade wires them (see
 * remotedModuleFacade.hpp) -- only the downstream backends (wazuh-db, task manager, the VD
 * module) are faked. controlEndpoint_test.cpp/scanVdEndpoint_test.cpp already cover each
 * handler's logic in isolation (no HTTP, no TLS, no auth, no real JSON-over-the-wire
 * serialization); this file exists to catch what those can't -- whether vd_feed_offset and the
 * /scan/vd 200/409 semantics actually survive the real stack end to end.
 */

#include "auth/authTypes.hpp"
#include "common/vdClient.hpp"
#include "control/agentRegistry.hpp"
#include "control/controlConfig.hpp"
#include "control/controlHandler.hpp"
#include "control/hashCache.hpp"
#include "control/metrics.hpp"
#include "control/taskClient.hpp"
#include "control/wazuhDBClient.hpp"
#include "decoding/bodyDecoder.hpp"
#include "endpoints/authGateway.hpp"
#include "endpoints/controlEndpoint.hpp"
#include "endpoints/scanVdEndpoint.hpp"
#include "fakeUdsServer.hpp"
#include "fakeVdServer.hpp"
#include "http_server/httpServerFactory.hpp"
#include "scanvd/scanVdHandler.hpp"
#include "scanvd/scanVdMetrics.hpp"
#include "testTlsServer.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <json.hpp>
#include <memory>
#include <optional>
#include <string>
#include <vector>

using namespace remoted::http;
using namespace remoted::control;
using remoted::endpoints::AuthGateway;
namespace fs = std::filesystem;

namespace
{
    // Wires the same slice of RemotedModuleFacade::start() that builds /control and /scan/vd:
    // one shared VdClient, ControlHandler, ScanVdHandlerImpl, an AuthGateway, and a real TLS
    // server -- with fake UDS backends standing in for wazuh-db, the task manager, and VD.
    struct ControlScanVdE2EFixture
    {
        fs::path base;
        std::string wdbPath;
        std::string taskPath;
        std::string vdSocketPath;
        Config cfg;
        ControlMetrics controlMetrics;
        remoted::scanvd::ScanVdMetrics scanVdMetrics;
        std::unique_ptr<remoted::test::FakeUdsServer> wdbServer;
        std::unique_ptr<remoted::test::FakeUdsServer> taskServer;
        std::unique_ptr<remoted::test::FakeVdServer> vdServer;
        std::shared_ptr<AgentRegistry> registry;
        std::shared_ptr<WazuhDBClient> wdbClient;
        std::shared_ptr<TaskClient> taskClient;
        std::shared_ptr<HashCache> hashCache;
        std::shared_ptr<remoted::common::VdClient> vdClient;
        std::unique_ptr<ControlHandler> controlHandler;
        std::unique_ptr<remoted::scanvd::ScanVdHandlerImpl> scanVdHandler;
        std::unique_ptr<IHttpServer> server;
        std::unique_ptr<AuthGateway> gateway;
        std::uint16_t port {0};

        std::optional<remoted::test::TestCertificate> cert;
        std::unique_ptr<remoted::test::ScratchFileCleanup> certCleanup;

        // Returns false (test should GTEST_SKIP) only when openssl isn't available to mint the
        // throwaway TLS certificate -- everything else here is expected to always succeed.
        bool start()
        {
            cert = remoted::test::generateTestCertificate("rmt_ctrl_scanvd_e2e");
            if (!cert)
            {
                return false;
            }
            certCleanup = std::make_unique<remoted::test::ScratchFileCleanup>(
                std::vector<std::string> {cert->certPath, cert->keyPath});

            base = fs::temp_directory_path() / ("wazuh_ctrl_scanvd_e2e_" + std::to_string(::getpid()) + "_" +
                                                std::to_string(reinterpret_cast<uintptr_t>(this)));
            fs::create_directories(base / "shared");
            fs::create_directories(base / "multi");

            wdbPath = remoted::test::makeUniqueSocketPath("e2e_wdb");
            taskPath = remoted::test::makeUniqueSocketPath("e2e_task");
            vdSocketPath = remoted::test::makeUniqueVdSocketPath("e2e");

            cfg.sharedGroupsRoot = (base / "shared").string();
            cfg.multiGroupsRoot = (base / "multi").string();
            cfg.wdbSocketPath = wdbPath;
            cfg.taskSocketPath = taskPath;
            cfg.clusterName = "wazuh";
            cfg.managerVersion = "5.0.0";
            cfg.limits = nlohmann::json::object();
            cfg.wdbRequestConnections = 1;
            cfg.wdbRoundtripDeadlineMs = 2000;
            cfg.wdbMaxQueueSize = 100;
            cfg.tmConcurrency = 1;
            cfg.tmDeadlineMs = 2000;
            cfg.tmMaxQueueSize = 100;

            wdbServer =
                std::make_unique<remoted::test::FakeUdsServer>(wdbPath,
                                                               [](const std::string& req) -> std::string
                                                               {
                                                                   if (req.find("global select-agent-group") == 0)
                                                                   {
                                                                       return "ok {\"group\":\"default\"}";
                                                                   }
                                                                   return "ok";
                                                               });
            taskServer = std::make_unique<remoted::test::FakeUdsServer>(
                taskPath, [](const std::string&) -> std::string { return "{\"status\":\"ok\",\"tasks\":[]}"; });

            vdServer = std::make_unique<remoted::test::FakeVdServer>(vdSocketPath);
            vdServer->setOffset(12345);
            vdServer->setScanHandler([](const httplib::Request&, httplib::Response& res)
                                     { res.set_content("{}", "application/json"); });

            registry = std::make_shared<AgentRegistry>();
            wdbClient = std::make_shared<WazuhDBClient>(cfg.wdbSocketPath,
                                                        cfg.wdbRequestConnections,
                                                        cfg.wdbRoundtripDeadlineMs,
                                                        cfg.wdbMaxQueueSize,
                                                        controlMetrics);
            taskClient = std::make_shared<TaskClient>(
                cfg.taskSocketPath, cfg.tmConcurrency, cfg.tmDeadlineMs, cfg.tmMaxQueueSize, controlMetrics);
            hashCache = std::make_shared<HashCache>(cfg);
            // Short TTL: ScanVdMismatchedOffsetReturns409OverRealHttp relies on a fresh query
            // rather than the real 30s default cache window.
            vdClient = std::make_shared<remoted::common::VdClient>(
                vdSocketPath, std::chrono::milliseconds {30}, std::chrono::milliseconds {30});

            controlHandler = std::make_unique<ControlHandler>(
                registry, wdbClient, taskClient, hashCache, vdClient, controlMetrics, cfg);
            // Same vdClient as ControlHandler, same as production (see remotedModuleFacade.hpp).
            scanVdHandler = std::make_unique<remoted::scanvd::ScanVdHandlerImpl>(vdClient, scanVdMetrics, vdSocketPath);

            server = makeHttpServer();
            gateway = std::make_unique<AuthGateway>(
                remoted::auth::AuthConfig {},
                std::make_shared<remoted::test::FakeKeystore>(),
                std::make_shared<const remoted::decoding::BodyDecoder>(*server, /*enabled=*/true));

            gateway->addAuthenticatedRoute(
                *server, Method::Post, "/control", remoted::endpoints::control::makeHandler(*controlHandler));
            gateway->addAuthenticatedRoute(
                *server, Method::Post, "/scan/vd", remoted::endpoints::scanvd::makeHandler(*scanVdHandler));

            HttpServerConfig httpConfig;
            port = static_cast<std::uint16_t>(28000 + (::getpid() % 5000));
            httpConfig.port = port;
            httpConfig.certificatePath = cert->certPath;
            httpConfig.privateKeyPath = cert->keyPath;
            server->start(httpConfig);
            return true;
        }

        ~ControlScanVdE2EFixture()
        {
            if (server)
            {
                server->stopAccepting();
                server->stop();
            }
            std::error_code ec;
            fs::remove_all(base, ec);
        }
    };
} // namespace

TEST(ControlScanVdE2ETest, NotifyResponseCarriesVdFeedOffsetOverRealHttp)
{
    ControlScanVdE2EFixture f;
    if (!f.start())
    {
        GTEST_SKIP() << "openssl not available to generate a test certificate";
    }

    const std::string body =
        R"({"type":"notify","agent":{"version":"5.0.0"},"host":{"hostname":"h1","ip":"127.0.0.1",)"
        R"("architecture":"x86_64","os":{"name":"Ubuntu","version":"24.04","platform":"ubuntu","type":"Linux"}}})";
    const auto raw = remoted::test::sendSignedRequest(f.port, remoted::test::testAgentKey(), "/control", body);
    const auto [head, respBody] = remoted::test::splitResponse(raw);

    ASSERT_NE(head.find("200"), std::string::npos) << "raw response head: " << head;
    const auto json = nlohmann::json::parse(respBody);
    ASSERT_TRUE(json.contains("vd_feed_offset")) << respBody;
    EXPECT_EQ(json.at("vd_feed_offset").get<uint64_t>(), 12345u);

    // Sanity: the rest of the notify contract (unrelated to this feature) is intact too.
    ASSERT_TRUE(json.contains("agent"));
    EXPECT_TRUE(json.at("agent").contains("groups"));
}

TEST(ControlScanVdE2ETest, ScanVdMatchingOffsetReturns200OverRealHttp)
{
    ControlScanVdE2EFixture f;
    if (!f.start())
    {
        GTEST_SKIP() << "openssl not available to generate a test certificate";
    }

    const std::string body = R"({"type":"feed_update","feed_offset":12345})";
    const auto raw = remoted::test::sendSignedRequest(f.port, remoted::test::testAgentKey(), "/scan/vd", body);
    const auto [head, respBody] = remoted::test::splitResponse(raw);

    ASSERT_NE(head.find("200"), std::string::npos) << "raw response head: " << head;
    EXPECT_EQ(respBody, "{}");
    EXPECT_EQ(f.scanVdMetrics.acceptedCount.load(), 1u);
}

TEST(ControlScanVdE2ETest, ScanVdMismatchedOffsetReturns409OverRealHttp)
{
    ControlScanVdE2EFixture f;
    if (!f.start())
    {
        GTEST_SKIP() << "openssl not available to generate a test certificate";
    }

    const std::string body = R"({"type":"feed_update","feed_offset":999})"; // server reports 12345
    const auto raw = remoted::test::sendSignedRequest(f.port, remoted::test::testAgentKey(), "/scan/vd", body);
    const auto [head, respBody] = remoted::test::splitResponse(raw);

    ASSERT_NE(head.find("409"), std::string::npos) << "raw response head: " << head;
    const auto json = nlohmann::json::parse(respBody);
    EXPECT_EQ(json.at("error").get<std::string>(), "version_mismatch");
    EXPECT_EQ(json.at("current_version").get<uint64_t>(), 12345u);
    EXPECT_EQ(f.scanVdMetrics.versionMismatchCount.load(), 1u);
}
