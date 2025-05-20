#include <gtest/gtest.h>

#include <bk/mockController.hpp>
#include <builder/mockBuilder.hpp>
#include <builder/mockPolicy.hpp>
#include <queue/mockQueue.hpp>
#include <store/mockStore.hpp>

#include <router/orchestrator.hpp>

#include "fakeStore.hpp"

constexpr auto SERVER_API_TIMEOUT {100000};
constexpr auto NUM_THREADS {1};

class OrchestratorTesterTest : public ::testing::Test
{
protected:
    std::shared_ptr<builder::mocks::MockBuilder> m_mockbuilder;
    std::shared_ptr<builder::mocks::MockPolicy> m_mockPolicy;
    std::shared_ptr<store::mocks::MockStore> m_mockStore;
    std::shared_ptr<bk::mocks::MockMakerController> m_mockControllerMaker;
    std::shared_ptr<bk::mocks::MockController> m_mockController;
    std::shared_ptr<queue::mocks::MockQueue<base::Event>> m_mockQueueRouter;
    std::shared_ptr<queue::mocks::MockQueue<router::test::QueueType>> m_mockQueueTester;

    std::shared_ptr<router::Orchestrator> m_orchestrator;

public:
    void SetUp() override
    {
        logging::testInit();

        m_mockStore = std::make_shared<store::mocks::MockStore>();
        m_mockbuilder = std::make_shared<builder::mocks::MockBuilder>();
        m_mockPolicy = std::make_shared<builder::mocks::MockPolicy>();
        m_mockControllerMaker = std::make_shared<bk::mocks::MockMakerController>();
        m_mockController = std::make_shared<bk::mocks::MockController>();
        m_mockQueueRouter = std::make_shared<queue::mocks::MockQueue<base::Event>>();
        m_mockQueueTester = std::make_shared<queue::mocks::MockQueue<router::test::QueueType>>();

        router::Orchestrator::Options config {.m_numThreads = NUM_THREADS,
                                              .m_wStore = m_mockStore,
                                              .m_builder = m_mockbuilder,
                                              .m_controllerMaker = m_mockControllerMaker,
                                              .m_prodQueue = m_mockQueueRouter,
                                              .m_testQueue = m_mockQueueTester,
                                              .m_testTimeout = SERVER_API_TIMEOUT};

        EXPECT_CALL(*m_mockStore, readInternalDoc(testing::_))
            .WillRepeatedly(testing::Invoke(
                [&](const base::Name& name)
                {
                    if (name == "router/router/0")
                    {
                        return json::Json {ROUTER_JSON};
                    }
                    if (name == "router/tester/0")
                    {
                        return json::Json {TESTER_JSON};
                    }
                    if (name == "policy/wazuh/0")
                    {
                        // Handle other cases or return a default value
                        return json::Json {POLICY_JSON};
                    }
                    if (name == "router/eps/0")
                    {
                        return json::Json {EPS_JSON};
                    }
                    return json::Json {};
                }));

        EXPECT_CALL(*m_mockStore, readDoc(testing::_))
            .WillRepeatedly(testing::Invoke(
                [&](const base::Name& name)
                {
                    if (name == "integration/wazuh-core-fake/0")
                    {
                        return json::Json {INTEGRATION_JSON};
                    }
                    else if (name == "decoder/fake/0")
                    {
                        return json::Json {DECODER_JSON};
                    }
                    else if (name == "filter/allow-all/0")
                    {
                        // Handle other cases or return a default value
                        return json::Json {FILTER_JSON};
                    }
                    else
                    {
                        return json::Json {};
                    }
                }));

        EXPECT_CALL(*m_mockControllerMaker, create(testing::_, testing::_, testing::_))
            .WillRepeatedly(testing::Return(m_mockController));

        m_orchestrator = std::make_shared<router::Orchestrator>(config);

        EXPECT_CALL(*m_mockQueueTester, tryPop(testing::_)).WillRepeatedly(testing::Return(false));
        EXPECT_CALL(*m_mockQueueRouter, waitPop(testing::_, testing::_)).WillRepeatedly(testing::Return(true));
        m_orchestrator->start();
    }
};

namespace
{
void expectBuildPolicyOk(std::shared_ptr<builder::mocks::MockBuilder> mockbuilder,
                         std::shared_ptr<builder::mocks::MockPolicy> mockPolicy)
{
    // Build policy controller
    EXPECT_CALL(*mockbuilder, buildPolicy(testing::_, testing::_, testing::_)).WillOnce(testing::Return(mockPolicy));
    auto emptyNames = std::unordered_set<base::Name> {"asset/test/0"};
    EXPECT_CALL(*mockPolicy, assets()).WillRepeatedly(testing::ReturnRefOfCopy(emptyNames));
    auto emptyExpression = base::Expression {};
    EXPECT_CALL(*mockPolicy, expression()).WillOnce(::testing::ReturnRefOfCopy(emptyExpression));
    EXPECT_CALL(*mockPolicy, hash()).WillOnce(::testing::ReturnRefOfCopy(std::string {"hash"}));
}
} // namespace
TEST_F(OrchestratorTesterTest, AddTestEntry)
{
    router::test::EntryPost entry("test", "policy/wazuh/0", 0);

    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    // Build Valid policy
    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_FALSE(m_orchestrator->postTestEntry(entry).has_value());

    EXPECT_CALL(*m_mockController, stop()).Times(1);
    m_orchestrator->stop();
}

TEST_F(OrchestratorTesterTest, AddMultipleTestEntry)
{
    router::test::EntryPost entry("test", "policy/wazuh/0", 0);
    router::test::EntryPost entryTwo("testTwo", "policy/wazuh/0", 0);

    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_FALSE(m_orchestrator->postTestEntry(entry).has_value());

    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_FALSE(m_orchestrator->postTestEntry(entryTwo).has_value());

    EXPECT_CALL(*m_mockController, stop()).Times(2);
    m_orchestrator->stop();
}

TEST_F(OrchestratorTesterTest, AddEqualTestEntry)
{
    router::test::EntryPost entry("test", "policy/wazuh/0", 0);

    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_FALSE(m_orchestrator->postTestEntry(entry).has_value());
    EXPECT_CALL(*m_mockController, stop()).Times(1);

    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_TRUE(m_orchestrator->postTestEntry(entry).has_value());

    EXPECT_CALL(*m_mockController, stop()).Times(1);
    m_orchestrator->stop();
}

TEST_F(OrchestratorTesterTest, DeleteTestEntryWithoutName)
{
    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_TRUE(m_orchestrator->deleteEntry("").has_value());

    m_orchestrator->stop();
}

TEST_F(OrchestratorTesterTest, DeleteTestEntry)
{
    router::test::EntryPost entry("test", "policy/wazuh/0", 0);

    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_FALSE(m_orchestrator->postTestEntry(entry).has_value());
    EXPECT_CALL(*m_mockController, stop()).Times(1);

    EXPECT_FALSE(m_orchestrator->deleteTestEntry("test").has_value());

    m_orchestrator->stop();
}

TEST_F(OrchestratorTesterTest, DeleteTheEqualTestEntryTwoTimes)
{
    router::test::EntryPost entry("test", "policy/wazuh/0", 0);

    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_FALSE(m_orchestrator->postTestEntry(entry).has_value());
    EXPECT_CALL(*m_mockController, stop()).Times(1);

    EXPECT_FALSE(m_orchestrator->deleteTestEntry("test").has_value());

    EXPECT_TRUE(m_orchestrator->deleteTestEntry("test").has_value());

    m_orchestrator->stop();
}

TEST_F(OrchestratorTesterTest, GetTestEntryWithoutName)
{
    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_TRUE(base::isError(m_orchestrator->getEntry("")));

    m_orchestrator->stop();
}

TEST_F(OrchestratorTesterTest, GetTestEntry)
{
    router::test::EntryPost entry("test", "policy/wazuh/0", 0);
    router::test::EntryPost entryTwo("testTwo", "policy/wazuh/0", 0);

    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_FALSE(m_orchestrator->postTestEntry(entry).has_value());
    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_FALSE(m_orchestrator->postTestEntry(entryTwo).has_value());

    EXPECT_CALL(*m_mockController, stop()).Times(2);

    EXPECT_STREQ(base::getResponse(m_orchestrator->getTestEntry("test")).name().c_str(), entry.name().c_str());
    EXPECT_STREQ(base::getResponse(m_orchestrator->getTestEntry("testTwo")).name().c_str(), entryTwo.name().c_str());

    m_orchestrator->stop();
}

TEST_F(OrchestratorTesterTest, ReloadTestEntryWithoutName)
{
    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_TRUE(base::isError(m_orchestrator->reloadTestEntry("")));

    m_orchestrator->stop();
}

TEST_F(OrchestratorTesterTest, ReloadTestEntry)
{
    router::test::EntryPost entry("test", "policy/wazuh/0", 0);

    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_FALSE(m_orchestrator->postTestEntry(entry).has_value());
    EXPECT_CALL(*m_mockController, stop()).Times(1);

    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_FALSE(m_orchestrator->reloadTestEntry("test").has_value());

    m_orchestrator->stop();
}

TEST_F(OrchestratorTesterTest, GetAssetsTestEntryError)
{
    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_TRUE(base::isError(m_orchestrator->getAssets("test")));

    m_orchestrator->stop();
}

TEST_F(OrchestratorTesterTest, GetAssetsTestEntry)
{
    router::test::EntryPost entry("test", "policy/wazuh/0", 0);

    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_FALSE(m_orchestrator->postTestEntry(entry).has_value());
    EXPECT_CALL(*m_mockController, stop()).Times(1);

    auto mockAsset = std::unordered_set<std::string> {"decoder/fake/0"};
    EXPECT_CALL(*m_mockController, getTraceables()).WillOnce(::testing::ReturnRef(mockAsset));
    auto assets = m_orchestrator->getAssets("test");
    EXPECT_FALSE(base::isError(assets));

    auto asset = base::getResponse(assets);
    EXPECT_FALSE(asset.empty());
    EXPECT_TRUE(asset.find("decoder/fake/0") != asset.end());

    m_orchestrator->stop();
}

TEST_F(OrchestratorTesterTest, IngestTest)
{
    router::test::EntryPost entry("test", "policy/wazuh/0", 0);

    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_FALSE(m_orchestrator->postTestEntry(entry).has_value());
    EXPECT_CALL(*m_mockController, stop()).Times(1);

    std::unordered_set<std::string> fakeAssetsString {};
    fakeAssetsString.insert("decoder/fake/0");
    router::test::Options opt(router::test::Options::TraceLevel::ASSET_ONLY, fakeAssetsString, "test");

    EXPECT_CALL(*m_mockQueueTester, tryPush(testing::_)).WillOnce(testing::Return(true));
    EXPECT_CALL(*m_mockQueueRouter, empty()).WillOnce(testing::Return(true));
    EXPECT_CALL(*m_mockQueueRouter, push(testing::_)).Times(1);

    auto event = std::make_shared<json::Json>(R"({"message":"test"})");

    auto resultFuture = m_orchestrator->ingestTest(std::move(event), opt);

    m_orchestrator->stop();
}
