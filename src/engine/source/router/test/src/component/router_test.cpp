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

class OrchestratorRouterTest : public ::testing::Test
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
    EXPECT_CALL(*mockbuilder, buildPolicy(testing::_)).WillOnce(testing::Return(mockPolicy));
    auto emptyNames = std::unordered_set<base::Name> {"asset/test/0"};
    EXPECT_CALL(*mockPolicy, assets()).WillRepeatedly(testing::ReturnRefOfCopy(emptyNames));
    auto emptyExpression = base::Expression {};
    EXPECT_CALL(*mockPolicy, expression()).WillOnce(::testing::ReturnRefOfCopy(emptyExpression));
    EXPECT_CALL(*mockPolicy, hash()).WillOnce(::testing::ReturnRefOfCopy(std::string {"hash"}));

    // Build filter
    EXPECT_CALL(*mockbuilder, buildAsset(testing::_)).WillOnce(::testing::Return(emptyExpression));
}
} // namespace
TEST_F(OrchestratorRouterTest, AddRoute)
{
    router::prod::EntryPost entry("route", "policy/wazuh/0", "filter/allow-all/0", 10);

    // Build Valid policy
    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);

    // DumpRouters()
    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_FALSE(m_orchestrator->postEntry(entry).has_value());

    EXPECT_CALL(*m_mockController, stop()).Times(1);
    m_orchestrator->stop();
}

TEST_F(OrchestratorRouterTest, AddMultipleRoutes)
{
    router::prod::EntryPost entry("route", "policy/wazuh/0", "filter/allow-all/0", 10);
    router::prod::EntryPost entryTwo("routeTwo", "policy/wazuh/0", "filter/allow-all/0", 11);

    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));
    EXPECT_FALSE(m_orchestrator->postEntry(entry).has_value());

    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));
    EXPECT_FALSE(m_orchestrator->postEntry(entryTwo).has_value());

    EXPECT_CALL(*m_mockController, stop()).Times(2);
    m_orchestrator->stop();
}

TEST_F(OrchestratorRouterTest, AddEqualRoute)
{
    router::prod::EntryPost entry("route", "policy/wazuh/0", "filter/allow-all/0", 10);

    // Add ok
    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));
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
    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_TRUE(m_orchestrator->deleteEntry("").has_value());

    m_orchestrator->stop();
}

TEST_F(OrchestratorRouterTest, DeleteRoute)
{
    router::prod::EntryPost entry("route", "policy/wazuh/0", "filter/allow-all/0", 10);

    // Insert route after delete
    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_FALSE(m_orchestrator->postEntry(entry).has_value());
    EXPECT_CALL(*m_mockController, stop()).Times(1);

    EXPECT_FALSE(m_orchestrator->deleteEntry("route").has_value());

    m_orchestrator->stop();
}

TEST_F(OrchestratorRouterTest, DeleteTheEqualRouteTwoTimes)
{
    router::prod::EntryPost entry("route", "policy/wazuh/0", "filter/allow-all/0", 10);

    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

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
    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_TRUE(base::isError(m_orchestrator->getEntry("")));

    m_orchestrator->stop();
}

TEST_F(OrchestratorRouterTest, GetEntry)
{
    router::prod::EntryPost entry("route", "policy/wazuh/0", "filter/allow-all/0", 10);
    router::prod::EntryPost entryTwo("routeTwo", "policy/wazuh/0", "filter/allow-all/0", 11);

    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

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
    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_TRUE(base::isError(m_orchestrator->reloadEntry("")));

    m_orchestrator->stop();
}

TEST_F(OrchestratorRouterTest, ReloadEntry)
{
    router::prod::EntryPost entry("route", "policy/wazuh/0", "filter/allow-all/0", 10);

    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

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
    router::prod::EntryPost entry("route", "policy/wazuh/0", "filter/allow-all/0", 10);

    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_FALSE(m_orchestrator->postEntry(entry).has_value());
    EXPECT_CALL(*m_mockController, stop()).Times(1);

    EXPECT_FALSE(m_orchestrator->changeEntryPriority("route", 90).has_value());
    EXPECT_EQ(base::getResponse(m_orchestrator->getEntry("route")).priority(), 90);

    m_orchestrator->stop();
}

TEST_F(OrchestratorRouterTest, ChangePriorityBusy)
{
    router::prod::EntryPost entry("route", "policy/wazuh/0", "filter/allow-all/0", 10);
    router::prod::EntryPost entryTwo("routeTwo", "policy/wazuh/0", "filter/allow-all/0", 11);

    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));
    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    m_orchestrator->postEntry(entry);

    expectBuildPolicyOk(m_mockbuilder, m_mockPolicy);
    m_orchestrator->postEntry(entryTwo);

    EXPECT_CALL(*m_mockController, stop()).Times(2);

    EXPECT_TRUE(m_orchestrator->changeEntryPriority("route", 11).has_value());
    EXPECT_EQ(base::getResponse(m_orchestrator->getEntry("route")).priority(), 10);

    m_orchestrator->stop();
}

TEST_F(OrchestratorRouterTest, GetEPS)
{
    auto res = m_orchestrator->getEpsSettings();
    ASSERT_FALSE(base::isError(res));
    auto [eps, interval, active] = base::getResponse(res);
    EXPECT_EQ(eps, 1);
    EXPECT_EQ(interval, 1);
    EXPECT_FALSE(active);
}

TEST_F(OrchestratorRouterTest, ChangeEPS)
{
    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillOnce(testing::Return(std::nullopt));
    auto res = m_orchestrator->changeEpsSettings(2, 2);
    ASSERT_FALSE(base::isError(res));
    auto [eps, interval, active] = base::getResponse(m_orchestrator->getEpsSettings());
    EXPECT_EQ(eps, 2);
    EXPECT_EQ(interval, 2);
}

TEST_F(OrchestratorRouterTest, ChangeEPSError)
{
    auto res = m_orchestrator->changeEpsSettings(0, 1);
    ASSERT_TRUE(base::isError(res));
    res = m_orchestrator->changeEpsSettings(1, 0);
    ASSERT_TRUE(base::isError(res));
    res = m_orchestrator->changeEpsSettings(0, 0);
    ASSERT_TRUE(base::isError(res));
}

TEST_F(OrchestratorRouterTest, ActivateEPS)
{
    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_))
        .Times(2)
        .WillRepeatedly(testing::Return(std::nullopt));

    auto res = m_orchestrator->activateEpsCounter(true);
    ASSERT_FALSE(base::isError(res));
    auto [eps, interval, active] = base::getResponse(m_orchestrator->getEpsSettings());
    EXPECT_TRUE(active);

    res = m_orchestrator->activateEpsCounter(true);
    ASSERT_TRUE(base::isError(res));

    res = m_orchestrator->activateEpsCounter(false);
    ASSERT_FALSE(base::isError(res));
    std::tie(eps, interval, active) = base::getResponse(m_orchestrator->getEpsSettings());
    EXPECT_FALSE(active);

    res = m_orchestrator->activateEpsCounter(false);
    ASSERT_TRUE(base::isError(res));
}
