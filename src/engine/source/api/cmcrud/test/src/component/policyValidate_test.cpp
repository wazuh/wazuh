// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <atomic>
#include <filesystem>
#include <future>
#include <mutex>
#include <set>
#include <thread>
#include <vector>

#include <fmt/format.h>
#include <fmt/ranges.h>

#include <base/logging.hpp>
#include <base/utils/generator.hpp>
#include <base/utils/singletonLocator.hpp>
#include <base/utils/singletonLocatorStrategies.hpp>
#include <bk/mockController.hpp>
#include <builder/mockBuilder.hpp>
#include <builder/mockPolicy.hpp>
#include <builder/mockValidator.hpp>
#include <cmcrud/cmcrudservice.hpp>
#include <cmstore/cmstore.hpp>
#include <fastmetrics/mockCounter.hpp>
#include <fastmetrics/mockManager.hpp>
#include <queue/mockQueue.hpp>
#include <rawevtindexer/mockraweventindexer.hpp>
#include <router/orchestrator.hpp>
#include <store/mockStore.hpp>

#include <api/adapter/adapter.hpp>
#include <api/cmcrud/handlers.hpp>
#include <api/tester/handlers.hpp>

/**
 * Real CMStore (on a temp dir), real CrudService and real Orchestrator (mocked builder) driving the
 * policyValidate and logtestDelete handlers from several threads at once.
 */

namespace
{
constexpr auto kSpace = "racetest";
constexpr auto kDecoderUuid = "a1f330f4-8012-48ab-9949-c5d76edaf9b1";
constexpr auto kIntegUuid = "a1f330f4-8012-48ab-9949-c5d76edaf9b2";

class TempDir
{
public:
    explicit TempDir(std::string_view prefix)
        : m_path(std::filesystem::temp_directory_path()
                 / std::filesystem::path(fmt::format("{}_{}", prefix, base::utils::generators::generateUUIDv4())))
    {
        std::filesystem::create_directories(m_path);
    }
    ~TempDir() { std::filesystem::remove_all(m_path); }
    const std::filesystem::path& path() const { return m_path; }

private:
    std::filesystem::path m_path;
};

std::string promoteBody()
{
    constexpr auto kTemplate = R"j({{
  "load_in_tester": true,
  "space": "{space}",
  "full_policy": {{
    "policy": {{
      "metadata": {{"title": "race"}}, "enabled": true, "root_decoder": "{dec}", "integrations": ["{integ}"],
      "filters": [], "enrichments": [], "index_unclassified_events": false, "index_discarded_events": false,
      "outputs": []
    }},
    "resources": {{
      "kvdbs": [],
      "decoders": [{{"id": "{dec}", "name": "decoder/root/0", "enabled": true,
                    "normalize": [{{"map": [{{"@timestamp": "get_date()"}}]}}]}}],
      "integrations": [{{"id": "{integ}", "metadata": {{"title": "race"}}, "enabled": true, "category": "security",
                        "decoders": ["{dec}"], "kvdbs": []}}],
      "filters": [],
      "outputs": []
    }}
  }}
}})j";
    return fmt::format(
        kTemplate, fmt::arg("space", kSpace), fmt::arg("dec", kDecoderUuid), fmt::arg("integ", kIntegUuid));
}

httplib::Request jsonRequest(const std::string& body)
{
    httplib::Request req;
    req.body = body;
    req.set_header("Content-Type", "plain/text");
    return req;
}

class PolicyValidateConcurrencyTest : public ::testing::Test
{
protected:
    std::unique_ptr<TempDir> m_rulesetDir;
    std::unique_ptr<TempDir> m_outputsDir;
    std::shared_ptr<cm::store::CMStore> m_store;
    std::shared_ptr<builder::mocks::MockValidator> m_validator;
    std::shared_ptr<cm::crud::CrudService> m_crud;

    std::shared_ptr<builder::mocks::MockBuilder> m_mockBuilder;
    std::shared_ptr<builder::mocks::MockPolicy> m_mockPolicy;
    std::shared_ptr<fastmetrics::MockCounter> m_mockCounter;
    std::shared_ptr<store::mocks::MockStore> m_mockStore;
    std::shared_ptr<bk::mocks::MockMakerController> m_mockControllerMaker;
    std::shared_ptr<bk::mocks::MockController> m_mockController;
    std::shared_ptr<fastqueue::mocks::MockQueue<router::IngestEvent>> m_mockQueueRouter;
    std::shared_ptr<fastqueue::mocks::MockQueue<router::test::EventTest>> m_mockQueueTester;
    std::shared_ptr<raweventindexer::mocks::MockRawEventIndexer> m_mockRawIndexer;
    std::shared_ptr<router::Orchestrator> m_orchestrator;

    api::adapter::RouteHandler m_promote;
    api::adapter::RouteHandler m_cleanup;

    void SetUp() override
    {
        logging::testInit();

        m_rulesetDir = std::make_unique<TempDir>("api_cmcrud_ctest_ruleset");
        m_outputsDir = std::make_unique<TempDir>("api_cmcrud_ctest_outputs");
        m_store = std::make_shared<cm::store::CMStore>(m_rulesetDir->path().string(), m_outputsDir->path().string());

        m_validator = std::make_shared<testing::NiceMock<builder::mocks::MockValidator>>();
        ON_CALL(*m_validator, softIntegrationValidate(testing::_, testing::_))
            .WillByDefault(testing::Return(builder::mocks::validateOk()));
        ON_CALL(*m_validator, validateAsset(testing::_, testing::_))
            .WillByDefault(testing::Return(builder::mocks::validateOk()));
        ON_CALL(*m_validator, validateAssetShallow(testing::_))
            .WillByDefault(testing::Return(builder::mocks::validateOk()));
        ON_CALL(*m_validator, softPolicyValidate(testing::_, testing::_))
            .WillByDefault(testing::Return(builder::mocks::validateOk()));
        m_crud = std::make_shared<cm::crud::CrudService>(m_store, m_validator);

        SingletonLocator::registerManager<fastmetrics::IManager,
                                          base::PtrSingleton<fastmetrics::IManager, fastmetrics::MockManager>>();
        auto& manager = SingletonLocator::instance<fastmetrics::IManager>();
        auto mockMetricsManager = dynamic_cast<fastmetrics::MockManager*>(&manager);
        ASSERT_NE(mockMetricsManager, nullptr);

        m_mockCounter = std::make_shared<fastmetrics::MockCounter>();
        static const std::string kCounterName = "test.counter";
        ON_CALL(*m_mockCounter, value()).WillByDefault(testing::Return(0.0));
        ON_CALL(*m_mockCounter, get()).WillByDefault(testing::Return(0));
        ON_CALL(*m_mockCounter, name()).WillByDefault(testing::ReturnRef(kCounterName));
        EXPECT_CALL(*mockMetricsManager, getOrCreateCounter(testing::_, testing::_, testing::_))
            .Times(testing::AnyNumber())
            .WillRepeatedly(testing::Return(m_mockCounter));
        ON_CALL(*mockMetricsManager, registerPullMetric(testing::_, testing::_, testing::_, testing::_))
            .WillByDefault(
                [](const std::string&, std::function<uint64_t()>, const std::string&, const std::string&) {});
        ON_CALL(*mockMetricsManager, registerPullMetricDouble(testing::_, testing::_, testing::_, testing::_))
            .WillByDefault([](const std::string&, std::function<double()>, const std::string&, const std::string&) {});

        m_mockStore = std::make_shared<store::mocks::MockStore>();
        m_mockBuilder = std::make_shared<builder::mocks::MockBuilder>();
        m_mockPolicy = std::make_shared<builder::mocks::MockPolicy>();
        m_mockControllerMaker = std::make_shared<bk::mocks::MockMakerController>();
        m_mockController = std::make_shared<bk::mocks::MockController>();
        m_mockQueueRouter = std::make_shared<fastqueue::mocks::MockQueue<router::IngestEvent>>();
        m_mockQueueTester = std::make_shared<fastqueue::mocks::MockQueue<router::test::EventTest>>();
        m_mockRawIndexer = std::make_shared<raweventindexer::mocks::MockRawEventIndexer>();

        EXPECT_CALL(*m_mockStore, readDoc(testing::_))
            .WillRepeatedly(testing::Invoke(
                [](const base::Name& name)
                {
                    if (name == "router/router/0" || name == "router/tester/0")
                    {
                        return json::Json {"[]"};
                    }
                    if (name == "router/eps/0")
                    {
                        return json::Json {R"({"eps": 1, "refreshInterval": 1, "active": false})"};
                    }
                    return json::Json {};
                }));
        EXPECT_CALL(*m_mockStore, upsertDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));
        EXPECT_CALL(*m_mockControllerMaker, create(testing::_, testing::_, testing::_))
            .WillRepeatedly(testing::Return(m_mockController));
        EXPECT_CALL(*m_mockController, stop()).Times(testing::AnyNumber());

        EXPECT_CALL(*m_mockBuilder, buildPolicy(testing::_, testing::_)).WillRepeatedly(testing::Return(m_mockPolicy));
        static const std::unordered_set<base::Name> kAssets {"asset/test/0"};
        static const base::Expression kExpression {};
        static const std::string kHash {"hash"};
        EXPECT_CALL(*m_mockPolicy, assets()).WillRepeatedly(testing::ReturnRef(kAssets));
        EXPECT_CALL(*m_mockPolicy, expression()).WillRepeatedly(testing::ReturnRef(kExpression));
        EXPECT_CALL(*m_mockPolicy, hash()).WillRepeatedly(testing::ReturnRef(kHash));

        router::Orchestrator::Options config {.m_numThreads = 1,
                                              .m_wStore = m_mockStore,
                                              .m_builder = m_mockBuilder,
                                              .m_controllerMaker = m_mockControllerMaker,
                                              .m_prodQueue = m_mockQueueRouter,
                                              .m_testQueue = m_mockQueueTester,
                                              .m_rawIndexer = m_mockRawIndexer,
                                              .m_testTimeout = 100000};
        m_orchestrator = std::make_shared<router::Orchestrator>(config);
        EXPECT_CALL(*m_mockQueueTester, waitPop(testing::_, testing::_)).WillRepeatedly(testing::Return(false));
        EXPECT_CALL(*m_mockQueueRouter, waitPop(testing::_, testing::_)).WillRepeatedly(testing::Return(false));
        m_orchestrator->start();

        m_promote = api::cmcrud::handlers::policyValidate(m_crud, m_orchestrator);
        m_cleanup = api::tester::handlers::logtestDelete(m_orchestrator, m_store);
    }

    void TearDown() override
    {
        m_orchestrator->stop();
        SingletonLocator::unregisterManager<fastmetrics::IManager>();
    }

    std::vector<std::string> tempNamespaces() const
    {
        std::vector<std::string> out;
        for (const auto& ns : m_store->getNamespaces())
        {
            if (ns.toStr().rfind("logtest_", 0) == 0)
            {
                out.push_back(ns.toStr());
            }
        }
        return out;
    }

    std::vector<std::string> tempDirsOnDisk() const
    {
        std::vector<std::string> out;
        for (const auto& entry : std::filesystem::directory_iterator(m_rulesetDir->path()))
        {
            const auto name = entry.path().filename().string();
            if (name.rfind("logtest_", 0) == 0)
            {
                out.push_back(name);
            }
        }
        return out;
    }

    // Runs `handlers[i]` in one thread each, released together; returns the failures as "index: status body".
    std::vector<std::string>
    runConcurrently(const std::vector<std::pair<api::adapter::RouteHandler, std::string>>& calls)
    {
        std::promise<void> go;
        std::shared_future<void> start = go.get_future().share();
        std::vector<std::thread> threads;
        std::vector<httplib::Response> responses(calls.size());

        for (std::size_t i = 0; i < calls.size(); ++i)
        {
            threads.emplace_back(
                [&, i]()
                {
                    auto req = jsonRequest(calls[i].second);
                    start.wait();
                    calls[i].first(req, responses[i]);
                });
        }
        go.set_value();
        for (auto& t : threads)
        {
            t.join();
        }

        std::vector<std::string> failures;
        for (std::size_t i = 0; i < responses.size(); ++i)
        {
            if (responses[i].status != 200 || responses[i].body.find(R"("status":"OK")") == std::string::npos)
            {
                failures.push_back(fmt::format("{}: {} {}", i, responses[i].status, responses[i].body));
            }
        }
        return failures;
    }

    std::string cleanupBody() const { return fmt::format(R"({{"space":"{}"}})", kSpace); }
};
} // namespace

TEST_F(PolicyValidateConcurrencyTest, SinglePromoteCreatesSessionOnOneTempNamespace)
{
    auto failures = runConcurrently({{m_promote, promoteBody()}});
    EXPECT_TRUE(failures.empty()) << fmt::format("{}", fmt::join(failures, "\n"));

    auto entry = m_orchestrator->getTestEntry(kSpace);
    ASSERT_FALSE(base::isError(entry));
    const auto temps = tempNamespaces();
    ASSERT_EQ(temps.size(), 1u);
    EXPECT_EQ(temps.front(), base::getResponse(entry).namespaceId().toStr());
    EXPECT_EQ(tempDirsOnDisk(), temps);
}

TEST_F(PolicyValidateConcurrencyTest, ConcurrentPromotesAllSucceedAndLeaveOneTempNamespace)
{
    constexpr std::size_t kThreads = 8;
    constexpr std::size_t kRounds = 20;

    for (std::size_t round = 0; round < kRounds; ++round)
    {
        std::vector<std::pair<api::adapter::RouteHandler, std::string>> calls(kThreads, {m_promote, promoteBody()});
        auto failures = runConcurrently(calls);
        ASSERT_TRUE(failures.empty()) << fmt::format("round {}:\n{}", round, fmt::join(failures, "\n"));

        auto entry = m_orchestrator->getTestEntry(kSpace);
        ASSERT_FALSE(base::isError(entry)) << fmt::format("round {}", round);
        const auto temps = tempNamespaces();
        ASSERT_EQ(temps.size(), 1u) << fmt::format("round {}: {}", round, fmt::join(temps, ","));
        EXPECT_EQ(temps.front(), base::getResponse(entry).namespaceId().toStr());
        EXPECT_EQ(tempDirsOnDisk(), temps);
    }
}

TEST_F(PolicyValidateConcurrencyTest, ConcurrentCleanupsAreIdempotentAndLeaveNothing)
{
    constexpr std::size_t kThreads = 8;

    ASSERT_TRUE(runConcurrently({{m_promote, promoteBody()}}).empty());
    ASSERT_EQ(tempNamespaces().size(), 1u);

    std::vector<std::pair<api::adapter::RouteHandler, std::string>> calls(kThreads, {m_cleanup, cleanupBody()});
    auto failures = runConcurrently(calls);
    EXPECT_TRUE(failures.empty()) << fmt::format("{}", fmt::join(failures, "\n"));

    EXPECT_TRUE(base::isError(m_orchestrator->getTestEntry(kSpace)));
    EXPECT_TRUE(tempNamespaces().empty());
    EXPECT_TRUE(tempDirsOnDisk().empty());
}

TEST_F(PolicyValidateConcurrencyTest, PromotesOverlappingCleanupsNeverFailAndEndConsistent)
{
    constexpr std::size_t kPairs = 4;
    constexpr std::size_t kRounds = 20;

    for (std::size_t round = 0; round < kRounds; ++round)
    {
        std::vector<std::pair<api::adapter::RouteHandler, std::string>> calls;
        for (std::size_t i = 0; i < kPairs; ++i)
        {
            calls.emplace_back(m_promote, promoteBody());
            calls.emplace_back(m_cleanup, cleanupBody());
        }
        auto failures = runConcurrently(calls);
        ASSERT_TRUE(failures.empty()) << fmt::format("round {}:\n{}", round, fmt::join(failures, "\n"));

        const auto temps = tempNamespaces();
        auto entry = m_orchestrator->getTestEntry(kSpace);
        if (base::isError(entry))
        {
            EXPECT_TRUE(temps.empty()) << fmt::format("round {}: orphans {}", round, fmt::join(temps, ","));
        }
        else
        {
            ASSERT_EQ(temps.size(), 1u) << fmt::format("round {}: {}", round, fmt::join(temps, ","));
            EXPECT_EQ(temps.front(), base::getResponse(entry).namespaceId().toStr());
        }
        EXPECT_EQ(tempDirsOnDisk(), temps);
    }

    ASSERT_TRUE(runConcurrently({{m_cleanup, cleanupBody()}}).empty());
    EXPECT_TRUE(tempNamespaces().empty());
}
