/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 3, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "testDoubles.hpp"
#include "upgradeDoubles.hpp"

#include "upgrade/upgradeApi.hpp"
#include "upgrade/upgradeService.hpp"

#include <gtest/gtest.h>

#include <json.hpp>

#include <memory>
#include <vector>

using namespace task_manager;
using namespace task_manager::upgrade;
using task_manager::test::FakeHostOps;
using task_manager::test::FakeResponder;
using task_manager::test::FakeWpkRepository;
using task_manager::test::TempDir;

namespace
{
    constexpr Timestamp NOW {1756800000};

    /// @brief Read the per-agent codes out of an envelope, which is what the Server API does.
    std::vector<int> agentErrors(const std::string& body)
    {
        // The parsed document is bound to a named local first. Iterating
        // `json::parse(body).at("data")` directly binds the loop to a reference INTO a temporary
        // that dies at the end of the full-expression -- the range-for lifetime trap, which reads
        // as an empty result rather than a crash.
        const auto parsed = nlohmann::json::parse(body);

        std::vector<int> codes;
        for (const auto& entry : parsed.at("data"))
        {
            codes.push_back(entry.at("error").get<int>());
        }
        return codes;
    }

    class ServiceTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            m_store = task_manager::test::makeMemoryStore();

            WpkCache::Options wpkOptions;
            wpkOptions.upgradeDir = m_dir.path();
            wpkOptions.downloadAttempts = 1;
            wpkOptions.retryBackoff = std::chrono::milliseconds {1};
            m_wpkCache = std::make_unique<WpkCache>(m_repository, wpkOptions);
            m_versionsCache = std::make_unique<VersionsCache>(m_repository, std::chrono::seconds {60});

            UpgradeOrchestrator::Options options;
            options.managerVersion = "v5.0.0";
            options.upgradeDir = m_dir.path();
            m_orchestrator = std::make_unique<UpgradeOrchestrator>(
                m_hostOps, *m_store, m_pendingCache, *m_wpkCache, *m_versionsCache, options);
        }

        void TearDown() override
        {
            if (m_service)
            {
                m_service->stop();
            }
        }

        void startService(const int workers = 1, const std::size_t queueDepth = 8)
        {
            UpgradeService::Options options;
            options.workers = workers;
            options.queueDepth = queueDepth;
            m_service = std::make_unique<UpgradeService>(
                *m_orchestrator, [] { return RemotedSettings {true, true, RemotedSettings::VERIFY_NONE}; },
                options);
            m_service->start();
        }

        static UpgradeRequest requestFor(std::vector<int> agentIds)
        {
            UpgradeRequest request;
            request.agentIds = std::move(agentIds);
            request.requestTime = NOW;
            return request;
        }

        TempDir m_dir;
        FakeHostOps m_hostOps;
        FakeWpkRepository m_repository;
        cache::PendingCache m_pendingCache;
        std::unique_ptr<storage::SqliteTaskStore> m_store;
        std::unique_ptr<WpkCache> m_wpkCache;
        std::unique_ptr<VersionsCache> m_versionsCache;
        std::unique_ptr<UpgradeOrchestrator> m_orchestrator;
        std::unique_ptr<UpgradeService> m_service;
    };
} // namespace

TEST_F(ServiceTest, RunsABatchAndAnswersThroughTheParkedResponder)
{
    startService();

    auto responder {std::make_shared<FakeResponder>()};
    EXPECT_TRUE(m_service->submit(requestFor({1, 2}), responder));

    ASSERT_TRUE(responder->waitForAnswer(std::chrono::seconds {5}));
    EXPECT_EQ(responder->status(), 200);
    // No agent rows were scripted, so both are "not in the database" -- what matters here is that
    // an answer arrived at all, from a thread that is not the one that submitted.
    EXPECT_EQ(agentErrors(responder->body()),
              (std::vector<int> {errorValue(UpgradeError::GlobalDbFailure),
                                 errorValue(UpgradeError::GlobalDbFailure)}));
}

TEST_F(ServiceTest, ShedsOnceTheQueueIsFull)
{
    // One worker, depth one. The worker takes the first job; the second fills the queue; the third
    // has nowhere to go.
    startService(1, 1);

    // A slow download keeps the worker busy so the queue actually backs up.
    m_hostOps.agentRows[1] = nlohmann::json {
        {"os_platform", "ubuntu"}, {"os_major", "22"}, {"os_minor", "04"}, {"os_arch", "x86_64"},
        {"version", "v4.14.0"}};
    m_repository.scriptVersions("https://packages.wazuh.com/5.x/wpk/linux/deb/amd64/versions",
                                {true, "v5.0.0 bdac63d27983c405531b56e2cd0eafa54b2f1d42\n", 200, 0});
    m_repository.scriptDownload(
        "https://packages.wazuh.com/5.x/wpk/linux/deb/amd64/wazuh_agent_v5.0.0_linux_amd64.deb.wpk",
        {true, "WPK-CONTENT-A", 200, 0, std::chrono::milliseconds {400}, false});

    auto running {std::make_shared<FakeResponder>()};
    auto queued {std::make_shared<FakeResponder>()};
    auto shed {std::make_shared<FakeResponder>()};

    EXPECT_TRUE(m_service->submit(requestFor({1}), running));
    // Give the worker a moment to pick the first job up, so the second one queues rather than
    // racing it into the same slot.
    std::this_thread::sleep_for(std::chrono::milliseconds {100});

    EXPECT_TRUE(m_service->submit(requestFor({1}), queued));
    EXPECT_FALSE(m_service->submit(requestFor({1}), shed));

    EXPECT_EQ(m_service->shedCount(), 1U);
    // The REFUSED responder was never taken, so the caller still owns it and answers itself. That
    // is what keeps a shed request from becoming a transport 503.
    EXPECT_FALSE(shed->answered());
}

TEST_F(ServiceTest, ShutdownAnswersEveryParkedRequestAndDropsNone)
{
    // THE GUARANTEE. A dropped responder becomes a transport 503, and the Server API raises on a
    // 503 rather than halving the chunk and retrying -- so a shutdown mid-fleet-upgrade would kill
    // a whole chunk of 500 agents instead of having it retried.
    startService(1, 16);

    std::vector<std::shared_ptr<FakeResponder>> responders;
    for (int index = 0; index < 8; ++index)
    {
        responders.push_back(std::make_shared<FakeResponder>());
        EXPECT_TRUE(m_service->submit(requestFor({1, 2, 3}), responders.back()));
    }

    m_service->stop();

    for (const auto& responder : responders)
    {
        EXPECT_TRUE(responder->answered());
        EXPECT_EQ(responder->status(), 200);
        EXPECT_EQ(responder->extraSends(), 0);

        // One entry per agent, so the caller can reconcile against what it sent.
        const auto codes {agentErrors(responder->body())};
        EXPECT_EQ(codes.size(), 3U);
        for (const auto code : codes)
        {
            // Only two codes are legitimate here, and the distinction is timing, not behaviour:
            // a batch shutdown caught -- queued or mid-flight -- reports 4, the code the Server API
            // answers by halving the chunk and retrying; a batch that had already finished reports
            // whatever it actually found, which for these unscripted agents is 6. Anything else,
            // and in particular 17, would mean an interrupted batch is telling the caller the
            // upgrade "could not start" rather than "try again".
            EXPECT_TRUE(code == errorValue(UpgradeError::TaskManagerCommunication) ||
                        code == errorValue(UpgradeError::GlobalDbFailure))
                << "unexpected code " << code;
        }
    }
}

TEST_F(ServiceTest, RefusesNewWorkOnceStopping)
{
    startService();
    m_service->stop();

    auto responder {std::make_shared<FakeResponder>()};
    EXPECT_FALSE(m_service->submit(requestFor({1}), responder));
    EXPECT_FALSE(responder->answered());
}

TEST_F(ServiceTest, StopIsIdempotent)
{
    startService();
    m_service->stop();
    m_service->stop(); // Also reached via the destructor in TearDown.
}

// ---- the routes ----------------------------------------------------------------------------------

namespace
{
    class UpgradeApiTest : public ServiceTest
    {
    protected:
        void buildApi(const bool enabled = true)
        {
            startService();
            m_api = std::make_unique<UpgradeApi>(*m_service, [] { return NOW; }, enabled);
        }

        static std::shared_ptr<const wazuh::uds_http::HttpRequest> bodyOf(const std::string& text)
        {
            auto request {std::make_shared<wazuh::uds_http::HttpRequest>()};
            request->method = wazuh::uds_http::Method::Post;
            request->target = UPGRADE_ROUTE;
            request->body = text;
            return request;
        }

        std::unique_ptr<UpgradeApi> m_api;
    };
} // namespace

TEST_F(UpgradeApiTest, AnUnparseableBodyIsAnsweredWithTheEnvelopeNotA400)
{
    // The Server API's HTTP client raises WazuhError(2019) on ANY non-2xx, which would replace a
    // precise per-agent message with a generic transport error. The framed socket these routes
    // replace had no status code at all; the envelope carried everything, and still does.
    buildApi();

    auto responder {std::make_shared<FakeResponder>()};
    m_api->handleUpgrade(bodyOf("{not json"), responder);

    ASSERT_TRUE(responder->answered());
    EXPECT_EQ(responder->status(), 200);
    EXPECT_EQ(agentErrors(responder->body()), (std::vector<int> {errorValue(UpgradeError::ParsingError)}));
}

TEST_F(UpgradeApiTest, AParseFailureCarriesItsSpecificMessage)
{
    buildApi();

    auto responder {std::make_shared<FakeResponder>()};
    m_api->handleUpgrade(bodyOf(R"({"agents":[1],"request_time":1756800000,"version":7})"), responder);

    ASSERT_TRUE(responder->answered());
    const auto parsed = nlohmann::json::parse(responder->body());
    EXPECT_EQ(parsed.at("error"), errorValue(UpgradeError::TaskConfigurations));
    EXPECT_EQ(parsed.at("data")[0].at("message"), "Parameter \"version\" should be a string");
    // The envelope keeps the code's generic text while the entry carries the specific complaint.
    EXPECT_EQ(parsed.at("message"), "JSON parameter not recognized");
}

TEST_F(UpgradeApiTest, AMissingAgentListIsARequiredParameterFailure)
{
    buildApi();

    auto responder {std::make_shared<FakeResponder>()};
    m_api->handleUpgrade(bodyOf(R"({"request_time":1756800000})"), responder);

    ASSERT_TRUE(responder->answered());
    EXPECT_EQ(agentErrors(responder->body()),
              (std::vector<int> {errorValue(UpgradeError::ParsingRequiredParameter)}));
}

TEST_F(UpgradeApiTest, AValidRequestIsAcceptedAndAnsweredLater)
{
    buildApi();

    auto responder {std::make_shared<FakeResponder>()};
    m_api->handleUpgrade(bodyOf(R"({"agents":[1,2],"request_time":1756800000})"), responder);

    // Handed to the pool, so the answer arrives from a worker rather than inline.
    ASSERT_TRUE(responder->waitForAnswer(std::chrono::seconds {5}));
    EXPECT_EQ(responder->status(), 200);
    EXPECT_EQ(agentErrors(responder->body()).size(), 2U);
}

TEST_F(UpgradeApiTest, ADisabledModuleRefusesEveryAgentExplicitly)
{
    // The retired module expressed "disabled" by never binding its socket, which the Server API saw
    // as a connection failure. With the socket shared there is nothing to leave unbound, so the
    // refusal has to be said out loud -- once per agent, so the caller can reconcile.
    buildApi(false);

    auto responder {std::make_shared<FakeResponder>()};
    m_api->handleUpgrade(bodyOf(R"({"agents":[1,2,3],"request_time":1756800000})"), responder);

    ASSERT_TRUE(responder->answered());
    EXPECT_EQ(responder->status(), 200);
    EXPECT_EQ(agentErrors(responder->body()),
              (std::vector<int> {errorValue(UpgradeError::UnknownError),
                                 errorValue(UpgradeError::UnknownError),
                                 errorValue(UpgradeError::UnknownError)}));
}

TEST_F(UpgradeApiTest, ADisabledModuleStillValidatesTheBodyFirst)
{
    // So a caller with a malformed request learns that, rather than being told the module is off.
    buildApi(false);

    auto responder {std::make_shared<FakeResponder>()};
    m_api->handleUpgrade(bodyOf(R"({"agents":[]})"), responder);

    ASSERT_TRUE(responder->answered());
    EXPECT_EQ(agentErrors(responder->body()),
              (std::vector<int> {errorValue(UpgradeError::ParsingRequiredParameter)}));
}

TEST_F(UpgradeApiTest, ANullRequestIsAnsweredRatherThanDropped)
{
    buildApi();

    auto responder {std::make_shared<FakeResponder>()};
    m_api->handleUpgrade(nullptr, responder);

    ASSERT_TRUE(responder->answered());
    EXPECT_EQ(responder->status(), 200);
}

TEST_F(UpgradeApiTest, TheCustomRouteUsesTheCustomParser)
{
    buildApi();

    // `file_path` is a custom-route key; on the repository route it would be ignored as unknown.
    auto responder {std::make_shared<FakeResponder>()};
    m_api->handleUpgradeCustom(
        bodyOf(R"({"agents":[1],"request_time":1756800000,"file_path":7})"), responder);

    ASSERT_TRUE(responder->answered());
    EXPECT_EQ(nlohmann::json::parse(responder->body()).at("data")[0].at("message"),
              "Parameter \"file_path\" should be a string");
}
