#include <gtest/gtest.h>

#include <bk/mockController.hpp>
#include <builder/mockBuilder.hpp>
#include <builder/mockPolicy.hpp>
#include <queue/mockQueue.hpp>
#include <rawevtindexer/mockraweventindexer.hpp>
#include <store/mockStore.hpp>

#include <router/orchestrator.hpp>

#include "fakeStore.hpp"

constexpr auto SERVER_API_TIMEOUT {100000};
constexpr auto NUM_THREADS {1};

namespace
{
router::prod::EntryPost makeProdEntry(const std::string& name, const std::string& ns, const std::string& filter, size_t priority)
{
    return router::prod::EntryPost {name, cm::store::NamespaceId {ns}, base::Name {filter}, priority};
}
}

class OrchestratorRouterTest : public ::testing::Test
{
protected:
    std::shared_ptr<builder::mocks::MockBuilder> m_mockbuilder;
    std::shared_ptr<builder::mocks::MockPolicy> m_mockPolicy;
    std::shared_ptr<store::mocks::MockStore> m_mockStore;
    std::shared_ptr<bk::mocks::MockMakerController> m_mockControllerMaker;
    std::shared_ptr<bk::mocks::MockController> m_mockController;
    std::shared_ptr<fastqueue::mocks::MockQueue<router::IngestEvent>> m_mockQueueRouter;
    std::shared_ptr<fastqueue::mocks::MockQueue<router::test::EventTest>> m_mockQueueTester;
    std::shared_ptr<raweventindexer::mocks::MockRawEventIndexer> m_mockRawIndexer;

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
        m_mockQueueRouter = std::make_shared<fastqueue::mocks::MockQueue<router::IngestEvent>>();
        m_mockQueueTester = std::make_shared<fastqueue::mocks::MockQueue<router::test::EventTest>>();
        m_mockRawIndexer = std::make_shared<raweventindexer::mocks::MockRawEventIndexer>();

        router::Orchestrator::Options config {.m_numThreads = NUM_THREADS,
                                              .m_wStore = m_mockStore,
                                              .m_builder = m_mockbuilder,
                                              .m_controllerMaker = m_mockControllerMaker,
                                              .m_prodQueue = m_mockQueueRouter,
                                              .m_testQueue = m_mockQueueTester,
                                              .m_rawIndexer = m_mockRawIndexer,
                                              .m_testTimeout = SERVER_API_TIMEOUT};

        EXPECT_CALL(*m_mockStore, readDoc(testing::_))
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
                        return json::Json {POLICY_JSON};
                    }
                    if (name == "router/eps/0")
                    {
                        return json::Json {EPS_JSON};
                    }
                    if (name == "integration/wazuh-core-fake/0")
                    {
                        return json::Json {INTEGRATION_JSON};
                    }
                    if (name == "decoder/fake/0")
                    {
                        return json::Json {DECODER_JSON};
                    }
                    if (name == "filter/allow-all/0")
                    {
                        return json::Json {FILTER_JSON};
                    }
                    return json::Json {};
                }));

        EXPECT_CALL(*m_mockControllerMaker, create(testing::_, testing::_, testing::_))
            .WillRepeatedly(testing::Return(m_mockController));

        m_orchestrator = std::make_shared<router::Orchestrator>(config);

        EXPECT_CALL(*m_mockQueueTester, waitPop(testing::_, testing::_)).WillRepeatedly(testing::Return(false));
        EXPECT_CALL(*m_mockQueueRouter, waitPop(testing::_, testing::_)).WillRepeatedly(testing::Return(false));
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

    // Build filter
    EXPECT_CALL(*mockbuilder, buildAsset(testing::_, testing::_)).WillOnce(::testing::Return(emptyExpression));
}
} // namespace
TEST_F(OrchestratorRouterTest, AddRoute)
{
    auto entry = makeProdEntry("route", "wazuh", "filter/allow-all/0", 10);

    // Build Valid policy
    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);

    // DumpRouters()
    EXPECT_CALL(*m_mockStore, upsertDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_FALSE(m_orchestrator->postEntry(entry).has_value());

    EXPECT_CALL(*m_mockController, stop()).Times(1);
    m_orchestrator->stop();
}

TEST_F(OrchestratorRouterTest, AddMultipleRoutes)
{
    auto entry = makeProdEntry("route", "wazuh", "filter/allow-all/0", 10);
    auto entryTwo = makeProdEntry("routeTwo", "wazuh", "filter/allow-all/0", 11);

    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_CALL(*m_mockStore, upsertDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));
    EXPECT_FALSE(m_orchestrator->postEntry(entry).has_value());

    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_CALL(*m_mockStore, upsertDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));
    EXPECT_FALSE(m_orchestrator->postEntry(entryTwo).has_value());

    EXPECT_CALL(*m_mockController, stop()).Times(2);
    m_orchestrator->stop();
}

TEST_F(OrchestratorRouterTest, AddEqualRoute)
{
    auto entry = makeProdEntry("route", "wazuh", "filter/allow-all/0", 10);

    // Add ok
    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_CALL(*m_mockStore, upsertDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));
    EXPECT_FALSE(m_orchestrator->postEntry(entry).has_value());

    // Add equal (Fail to insert)
    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_CALL(*m_mockController, stop()).Times(1);
    EXPECT_TRUE(m_orchestrator->postEntry(entry).has_value());

    EXPECT_CALL(*m_mockController, stop()).Times(1);
    m_orchestrator->stop();
}

TEST_F(OrchestratorRouterTest, DeleteRouteWithoutName)
{
    EXPECT_CALL(*m_mockStore, upsertDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_TRUE(m_orchestrator->deleteEntry("").has_value());

    m_orchestrator->stop();
}

TEST_F(OrchestratorRouterTest, DeleteRoute)
{
    auto entry = makeProdEntry("route", "wazuh", "filter/allow-all/0", 10);

    // Insert route after delete
    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_CALL(*m_mockStore, upsertDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_FALSE(m_orchestrator->postEntry(entry).has_value());
    EXPECT_CALL(*m_mockController, stop()).Times(1);

    EXPECT_FALSE(m_orchestrator->deleteEntry("route").has_value());

    m_orchestrator->stop();
}

TEST_F(OrchestratorRouterTest, DeleteTheEqualRouteTwoTimes)
{
    auto entry = makeProdEntry("route", "wazuh", "filter/allow-all/0", 10);

    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_CALL(*m_mockStore, upsertDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    // Insert route after delete
    EXPECT_FALSE(m_orchestrator->postEntry(entry).has_value());
    EXPECT_CALL(*m_mockController, stop()).Times(1);

    // Delete ok
    EXPECT_FALSE(m_orchestrator->deleteEntry("route").has_value());
    // Delete equal (Fail to delete)
    EXPECT_TRUE(m_orchestrator->deleteEntry("route").has_value());

    m_orchestrator->stop();
}

TEST_F(OrchestratorRouterTest, GetEntryWithoutName)
{
    EXPECT_CALL(*m_mockStore, upsertDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_TRUE(base::isError(m_orchestrator->getEntry("")));

    m_orchestrator->stop();
}

TEST_F(OrchestratorRouterTest, GetEntry)
{
    auto entry = makeProdEntry("route", "wazuh", "filter/allow-all/0", 10);
    auto entryTwo = makeProdEntry("routeTwo", "wazuh", "filter/allow-all/0", 11);

    EXPECT_CALL(*m_mockStore, upsertDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    // Add two routes
    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_FALSE(m_orchestrator->postEntry(entry).has_value());
    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_FALSE(m_orchestrator->postEntry(entryTwo).has_value());

    EXPECT_CALL(*m_mockController, stop()).Times(2);

    // Get routes
    EXPECT_STREQ(base::getResponse(m_orchestrator->getEntry("route")).name().c_str(), entry.name().c_str());
    EXPECT_STREQ(base::getResponse(m_orchestrator->getEntry("routeTwo")).name().c_str(), entryTwo.name().c_str());

    m_orchestrator->stop();
}

TEST_F(OrchestratorRouterTest, ReloadEntryWithoutName)
{
    EXPECT_CALL(*m_mockStore, upsertDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_TRUE(base::isError(m_orchestrator->reloadEntry("")));

    m_orchestrator->stop();
}

TEST_F(OrchestratorRouterTest, ReloadEntry)
{
    auto entry = makeProdEntry("route", "wazuh", "filter/allow-all/0", 10);

    EXPECT_CALL(*m_mockStore, upsertDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_FALSE(m_orchestrator->postEntry(entry).has_value());

    EXPECT_CALL(*m_mockController, stop()).Times(1);

    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_FALSE(m_orchestrator->reloadEntry("route").has_value());

    EXPECT_CALL(*m_mockController, stop()).Times(1);
    m_orchestrator->stop();
}

TEST_F(OrchestratorRouterTest, ChangePriority)
{
    auto entry = makeProdEntry("route", "wazuh", "filter/allow-all/0", 10);

    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_CALL(*m_mockStore, upsertDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_FALSE(m_orchestrator->postEntry(entry).has_value());
    EXPECT_CALL(*m_mockController, stop()).Times(1);

    EXPECT_FALSE(m_orchestrator->changeEntryPriority("route", 90).has_value());
    EXPECT_EQ(base::getResponse(m_orchestrator->getEntry("route")).priority(), 90);

    m_orchestrator->stop();
}

TEST_F(OrchestratorRouterTest, ChangePriorityBusy)
{
    auto entry = makeProdEntry("route", "wazuh", "filter/allow-all/0", 10);
    auto entryTwo = makeProdEntry("routeTwo", "wazuh", "filter/allow-all/0", 11);

    EXPECT_CALL(*m_mockStore, upsertDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));
    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    m_orchestrator->postEntry(entry);

    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    m_orchestrator->postEntry(entryTwo);

    EXPECT_CALL(*m_mockController, stop()).Times(2);

    EXPECT_TRUE(m_orchestrator->changeEntryPriority("route", 11).has_value());
    EXPECT_EQ(base::getResponse(m_orchestrator->getEntry("route")).priority(), 10);

    m_orchestrator->stop();
}
