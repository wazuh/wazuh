#include <gtest/gtest.h>

#include <chrono>

#include <base/logging.hpp>
#include <queue/mockQueue.hpp>
#include <store/mockStore.hpp>

#include <router/orchestrator.hpp>

#include "mockRouter.hpp"
#include "mockTester.hpp"
#include "mockWorker.hpp"

using namespace router;

namespace
{
const cm::store::NamespaceId G_NAMESPACE_ID {"policy_test_0"};
const cm::store::NamespaceId G_NAMESPACE_ALT {"policy"};
const std::string G_NDJ_AGENT_HEADER {
    R"({"agent":{"id":"2887e1cf-9bf2-431a-b066-a46860080f56","name":"javier","type":"endpoint","version":"5.0.0","groups":["group1","group2"],"host":{"hostname":"myhost","os":{"name":"Amazon Linux 2","platform":"Linux"},"ip":["192.168.1.2"],"architecture":"x86_64"}}})"};
const std::string G_NDJ_MODULE_SUBHEADER_1 {R"({"module": "logcollector", "collector": "file"})"};
const std::string G_NDJ_EVENT_1 {
    R"({"log": {"file": {"path": "/var/log/apache2/access.log"}}, "base": {"tags": ["production-server"]}, "event": {"original": "::1 - - [26/Jun/2020:16:16:29 +0200] \"GET /favicon.ico HTTP/1.1\" 404 209", "ingested": "2023-12-26T09:22:14.000Z"}})"};
const std::string G_NDJ_EVENT_2 {
    R"({"log": {"file": {"path": "/var/log/apache2/error.log"}}, "base": {"tags": ["testing-server"]}, "event": {"original": "::1 - - [26/Jun/2020:16:16:29 +0200] \"GET /favicon.ico HTTP/1.1\" 404 209", "ingested": "2023-12-26T09:22:14.000Z"}})"};
const std::string G_NDJ_EVENT_3 {
    R"({"log": {"file": {"path": "/tmp/syslog.log"}}, "event": {"original": "SYSLOG EXAMPLE", "ingested": "2023-12-26T09:22:14.000Z"}})"};

// Avoid string comparison issues with json
MATCHER_P(isEqualsEvent, expectedJson, "is not equal to expected JSON")
{
    const auto recv = json::Json(*arg);
    const auto expected = *(static_cast<std::shared_ptr<json::Json>>(expectedJson));

    return recv == expected;
}

} // namespace
/// @brief Orchestrator to test, helper class
class OrchestratorToTest : public router::Orchestrator
{
public:
    std::shared_ptr<store::mocks::MockStore> m_mockstore;
    std::shared_ptr<fastqueue::mocks::MockQueue<IngestEvent>> m_mockEventQueue;
    std::shared_ptr<fastqueue::mocks::MockQueue<test::EventTest>> m_mockTestQueue;
    std::list<std::shared_ptr<MockRouterWorker>> m_routerMocks;
    std::shared_ptr<MockTesterWorker> m_testerWorkerMock;

    OrchestratorToTest()
        : router::Orchestrator()
    {
        m_testTimeout = 1000;
        m_mockstore = std::make_shared<store::mocks::MockStore>();
        m_wStore = m_mockstore;
        m_mockEventQueue = std::make_shared<fastqueue::mocks::MockQueue<IngestEvent>>();
        m_mockTestQueue = std::make_shared<fastqueue::mocks::MockQueue<test::EventTest>>();
        m_eventQueue = m_mockEventQueue;
        m_testQueue = m_mockTestQueue;

        m_testerWorkerMock = std::make_shared<MockTesterWorker>();
        m_testerWorker = m_testerWorkerMock;
    };

    auto forEachWorkerMock(std::function<void(std::shared_ptr<MockRouterWorker>)> func)
    {
        for (auto& mock : m_routerMocks)
        {
            func(mock);
        }
    }

    auto addMockWorker() -> std::shared_ptr<MockRouterWorker>
    {
        auto workerMock = std::make_shared<MockRouterWorker>();

        m_routerWorkers.emplace_back(workerMock);
        m_routerMocks.emplace_back(workerMock);

        return workerMock;
    }

    void setContentionState(bool contended, int64_t startUsec, int64_t lastWarningUsec, uint64_t dropped)
    {
        m_eventQueueContended.store(contended, std::memory_order_relaxed);
        m_contentionStartUsec.store(startUsec, std::memory_order_relaxed);
        m_lastContentionWarningUsec.store(lastWarningUsec, std::memory_order_relaxed);
        m_droppedEventsInContention.store(dropped, std::memory_order_relaxed);
    }

    bool isQueueContended() const { return m_eventQueueContended.load(std::memory_order_relaxed); }
    int64_t contentionStartUsec() const { return m_contentionStartUsec.load(std::memory_order_relaxed); }
    int64_t lastContentionWarningUsec() const { return m_lastContentionWarningUsec.load(std::memory_order_relaxed); }
    uint64_t droppedEventsInContention() const { return m_droppedEventsInContention.load(std::memory_order_relaxed); }

    /**************************************************************************
     * TESTER EXPECTS CALL
     *************************************************************************/

    void expectDumpTester()
    {
        if (!m_testerWorkerMock)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        EXPECT_CALL(*m_testerWorkerMock, get()).WillOnce(testing::Return(itesterMock));

        EXPECT_CALL(*testerMock, getEntries()).WillOnce(testing::Return(std::list<test::Entry> {}));

        EXPECT_CALL(*(m_mockstore), upsertDoc(testing::_, testing::_))
            .WillRepeatedly(::testing::Return(store::mocks::storeOk()));
    }

    void expectPostEntryAddEntryFailure()
    {
        if (!m_testerWorkerMock)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        EXPECT_CALL(*m_testerWorkerMock, get()).WillOnce(testing::Return(itesterMock));
        EXPECT_CALL(*testerMock, addEntry(testing::_, testing::_)).WillOnce(testing::Return(base::Error {"error"}));
    }

    void expectPostEntryEnableEntryFailure()
    {
        if (!m_testerWorkerMock)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        EXPECT_CALL(*m_testerWorkerMock, get()).WillRepeatedly(testing::Return(itesterMock));
        EXPECT_CALL(*testerMock, addEntry(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

        EXPECT_CALL(*testerMock, enableEntry(testing::_)).WillOnce(testing::Return(base::Error {"error"}));
    }

    void expectPostEntrySuccess()
    {
        if (!m_testerWorkerMock)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        EXPECT_CALL(*m_testerWorkerMock, get()).WillRepeatedly(testing::Return(itesterMock));
        EXPECT_CALL(*testerMock, addEntry(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));
        EXPECT_CALL(*testerMock, enableEntry(testing::_)).WillRepeatedly(testing::Return(std::nullopt));
        EXPECT_CALL(*testerMock, getEntries()).WillRepeatedly(testing::Return(std::list<test::Entry> {}));

        EXPECT_CALL(*(m_mockstore), upsertDoc(testing::_, testing::_))
            .WillOnce(::testing::Return(store::mocks::storeOk()));
    }

    void expectDeleteEntryRemoveEntryFailure()
    {
        if (!m_testerWorkerMock)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        EXPECT_CALL(*m_testerWorkerMock, get()).WillOnce(testing::Return(itesterMock));
        EXPECT_CALL(*testerMock, removeEntry(testing::_)).WillOnce(testing::Return(base::Error {"error"}));
    }

    void expectDeleteEntrySuccess()
    {
        if (!m_testerWorkerMock)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        EXPECT_CALL(*m_testerWorkerMock, get()).WillRepeatedly(testing::Return(itesterMock));
        EXPECT_CALL(*testerMock, removeEntry(testing::_)).WillRepeatedly(testing::Return(std::nullopt));
        EXPECT_CALL(*testerMock, getEntries()).WillRepeatedly(testing::Return(std::list<test::Entry> {}));

        EXPECT_CALL(*(m_mockstore), upsertDoc(testing::_, testing::_))
            .WillOnce(::testing::Return(store::mocks::storeOk()));
    }

    void expectGetEntryGetEntryFailure()
    {
        if (!m_testerWorkerMock)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        EXPECT_CALL(*m_testerWorkerMock, get()).WillOnce(testing::Return(itesterMock));
        EXPECT_CALL(*testerMock, getEntry(testing::_)).WillOnce(testing::Return(base::Error {"error"}));
    }

    void expectGetEntrySuccess()
    {
        if (!m_testerWorkerMock)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        EXPECT_CALL(*m_testerWorkerMock, get()).WillRepeatedly(testing::Return(itesterMock));
        EXPECT_CALL(*testerMock, getEntry(testing::_))
            .WillRepeatedly(testing::Return(test::EntryPost {"test", G_NAMESPACE_ALT, 0}));
    }

    void expectReloadEntryRebuildEntryFailure()
    {
        if (!m_testerWorkerMock)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        EXPECT_CALL(*m_testerWorkerMock, get()).WillOnce(testing::Return(itesterMock));
        EXPECT_CALL(*testerMock, rebuildEntry(testing::_)).WillOnce(testing::Return(base::Error {"error"}));
    }

    void expectReloadEntryEnableEntryFailure()
    {
        if (!m_testerWorkerMock)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        EXPECT_CALL(*m_testerWorkerMock, get()).WillRepeatedly(testing::Return(itesterMock));
        EXPECT_CALL(*testerMock, rebuildEntry(testing::_)).WillRepeatedly(testing::Return(std::nullopt));

        EXPECT_CALL(*testerMock, enableEntry(testing::_)).WillOnce(testing::Return(base::Error {"error"}));
    }

    void expectReloadSuccess()
    {
        if (!m_testerWorkerMock)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        EXPECT_CALL(*m_testerWorkerMock, get()).WillRepeatedly(testing::Return(itesterMock));
        EXPECT_CALL(*testerMock, rebuildEntry(testing::_)).WillRepeatedly(testing::Return(std::nullopt));

        EXPECT_CALL(*testerMock, enableEntry(testing::_)).WillRepeatedly(testing::Return(std::nullopt));
    }

    void expectGetGetEntriesEmpty()
    {
        if (!m_testerWorkerMock)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        EXPECT_CALL(*m_testerWorkerMock, get()).WillOnce(testing::Return(itesterMock));
        EXPECT_CALL(*testerMock, getEntries()).WillOnce(testing::Return(std::list<test::Entry> {}));
    }

    void expectGetEntriesSuccess()
    {
        if (!m_testerWorkerMock)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        EXPECT_CALL(*m_testerWorkerMock, get()).WillRepeatedly(testing::Return(itesterMock));

        EXPECT_CALL(*testerMock, getEntries())
            .WillRepeatedly(testing::Return(std::list<test::Entry> {test::EntryPost {"test", G_NAMESPACE_ALT, 0}}));
    }

    void expectGetAssetsEmpty()
    {
        if (!m_testerWorkerMock)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        EXPECT_CALL(*m_testerWorkerMock, get()).WillOnce(testing::Return(itesterMock));
        EXPECT_CALL(*testerMock, getAssets(testing::_)).WillOnce(testing::Return(base::Error {"error"}));
    }

    void expectGetAssetsSuccess()
    {
        if (!m_testerWorkerMock)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        EXPECT_CALL(*m_testerWorkerMock, get()).WillRepeatedly(testing::Return(itesterMock));
        EXPECT_CALL(*testerMock, getAssets(testing::_))
            .WillRepeatedly(testing::Return(std::unordered_set<std::string> {"decoder"}));
    }

    /**************************************************************************
     * ROUTER EXPECTS CALL
     *************************************************************************/

    void expectPostEntryAddEntryFailureRouter()
    {
        if (m_routerMocks.empty() || m_routerMocks.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto routerMock = std::make_shared<MockRouter>();
        auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

        EXPECT_CALL(*m_routerMocks.front(), get()).WillOnce(testing::Return(irouterMock));
        EXPECT_CALL(*routerMock, addEntry(testing::_, testing::_)).WillOnce(testing::Return(base::Error {"error"}));
    }

    void expectPostEntryEnableEntryFailureRouter()
    {
        if (m_routerMocks.empty() || m_routerMocks.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto routerMock = std::make_shared<MockRouter>();
        auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

        for (auto mock : m_routerMocks)
        {
            EXPECT_CALL(*mock, get()).WillRepeatedly(testing::Return(irouterMock));
            EXPECT_CALL(*routerMock, addEntry(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));
        }

        EXPECT_CALL(*routerMock, enableEntry(testing::_)).WillOnce(testing::Return(base::Error {"error"}));
    }

    void expectPostEntrySuccessRouter()
    {
        if (m_routerMocks.empty() || m_routerMocks.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto routerMock = std::make_shared<MockRouter>();
        auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

        for (auto mock : m_routerMocks)
        {
            EXPECT_CALL(*mock, get()).WillRepeatedly(testing::Return(irouterMock));
            EXPECT_CALL(*routerMock, addEntry(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));
            EXPECT_CALL(*routerMock, enableEntry(testing::_)).WillRepeatedly(testing::Return(std::nullopt));
            EXPECT_CALL(*routerMock, getEntries()).WillRepeatedly(testing::Return(std::list<prod::Entry> {}));
        }

        EXPECT_CALL(*(m_mockstore), upsertDoc(testing::_, testing::_))
            .WillOnce(::testing::Return(store::mocks::storeOk()));
    }

    void expectDeleteEntryRemoveEntryFailureRouter()
    {
        if (m_routerMocks.empty() || m_routerMocks.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto routerMock = std::make_shared<MockRouter>();
        auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

        EXPECT_CALL(*m_routerMocks.front(), get()).WillOnce(testing::Return(irouterMock));
        EXPECT_CALL(*routerMock, removeEntry(testing::_)).WillOnce(testing::Return(base::Error {"error"}));
    }

    void expectDeleteEntrySuccessRouter()
    {
        if (m_routerMocks.empty() || m_routerMocks.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto routerMock = std::make_shared<MockRouter>();
        auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

        for (auto mock : m_routerMocks)
        {
            EXPECT_CALL(*mock, get()).WillRepeatedly(testing::Return(irouterMock));
            EXPECT_CALL(*routerMock, removeEntry(testing::_)).WillRepeatedly(testing::Return(std::nullopt));
            EXPECT_CALL(*routerMock, getEntries()).WillRepeatedly(testing::Return(std::list<prod::Entry> {}));
        }

        EXPECT_CALL(*(m_mockstore), upsertDoc(testing::_, testing::_))
            .WillOnce(::testing::Return(store::mocks::storeOk()));
    }

    void expectGetEntryGetEntryFailureRouter()
    {
        if (m_routerMocks.empty() || m_routerMocks.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto routerMock = std::make_shared<MockRouter>();
        auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

        EXPECT_CALL(*m_routerMocks.front(), get()).WillOnce(testing::Return(irouterMock));
        EXPECT_CALL(*routerMock, getEntry(testing::_)).WillOnce(testing::Return(base::Error {"error"}));
    }

    void expectGetEntrySuccessRouter()
    {
        if (m_routerMocks.empty() || m_routerMocks.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto routerMock = std::make_shared<MockRouter>();
        auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

        for (auto mock : m_routerMocks)
        {
            EXPECT_CALL(*mock, get()).WillRepeatedly(testing::Return(irouterMock));
            EXPECT_CALL(*routerMock, getEntry(testing::_))
                .WillRepeatedly(testing::Return(prod::EntryPost {"test", G_NAMESPACE_ALT, 10}));
        }
    }

    void expectReloadEntryRebuildEntryFailureRouter()
    {
        if (m_routerMocks.empty() || m_routerMocks.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto routerMock = std::make_shared<MockRouter>();
        auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

        EXPECT_CALL(*m_routerMocks.front(), get()).WillOnce(testing::Return(irouterMock));
        EXPECT_CALL(*routerMock, rebuildEntry(testing::_)).WillOnce(testing::Return(base::Error {"error"}));
    }

    void expectReloadEntryEnableEntryFailureRouter()
    {
        if (m_routerMocks.empty() || m_routerMocks.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto routerMock = std::make_shared<MockRouter>();
        auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

        for (auto mock : m_routerMocks)
        {
            EXPECT_CALL(*mock, get()).WillRepeatedly(testing::Return(irouterMock));
            EXPECT_CALL(*routerMock, rebuildEntry(testing::_)).WillRepeatedly(testing::Return(std::nullopt));
        }

        EXPECT_CALL(*routerMock, enableEntry(testing::_)).WillOnce(testing::Return(base::Error {"error"}));
    }

    void expectReloadSuccessRouter()
    {
        if (m_routerMocks.empty() || m_routerMocks.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto routerMock = std::make_shared<MockRouter>();
        auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

        for (auto mock : m_routerMocks)
        {
            EXPECT_CALL(*mock, get()).WillRepeatedly(testing::Return(irouterMock));
            EXPECT_CALL(*routerMock, rebuildEntry(testing::_)).WillRepeatedly(testing::Return(std::nullopt));
        }

        EXPECT_CALL(*routerMock, enableEntry(testing::_)).WillRepeatedly(testing::Return(std::nullopt));
    }

    void expectChangePriorityFailure()
    {
        if (m_routerMocks.empty() || m_routerMocks.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto routerMock = std::make_shared<MockRouter>();
        auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

        EXPECT_CALL(*m_routerMocks.front(), get()).WillOnce(testing::Return(irouterMock));
        EXPECT_CALL(*routerMock, changePriority(testing::_, testing::_))
            .WillOnce(testing::Return(base::Error {"error"}));
    }

    void expectChangePrioritySuccess()
    {
        if (m_routerMocks.empty() || m_routerMocks.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto routerMock = std::make_shared<MockRouter>();
        auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

        for (auto mock : m_routerMocks)
        {
            EXPECT_CALL(*mock, get()).WillRepeatedly(testing::Return(irouterMock));
            EXPECT_CALL(*routerMock, changePriority(testing::_, testing::_))
                .WillRepeatedly(testing::Return(std::nullopt));
            EXPECT_CALL(*routerMock, getEntries()).WillRepeatedly(testing::Return(std::list<prod::Entry> {}));
        }

        EXPECT_CALL(*(m_mockstore), upsertDoc(testing::_, testing::_))
            .WillOnce(::testing::Return(store::mocks::storeOk()));
    }

    void expectGetGetEntriesEmptyRouter()
    {
        if (m_routerMocks.empty() || m_routerMocks.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto routerMock = std::make_shared<MockRouter>();
        auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

        EXPECT_CALL(*m_routerMocks.front(), get()).WillOnce(testing::Return(irouterMock));
        EXPECT_CALL(*routerMock, getEntries()).WillOnce(testing::Return(std::list<prod::Entry> {}));
    }

    void expectGetEntriesSuccessRouter()
    {
        if (m_routerMocks.empty() || m_routerMocks.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto routerMock = std::make_shared<MockRouter>();
        auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

        for (auto mock : m_routerMocks)
        {
            EXPECT_CALL(*mock, get()).WillRepeatedly(testing::Return(irouterMock));
        }

        EXPECT_CALL(*routerMock, getEntries())
            .WillRepeatedly(testing::Return(std::list<prod::Entry> {prod::EntryPost {"test", G_NAMESPACE_ALT, 10}}));
    }
};

class OrchestratorTest : public ::testing::Test
{
protected:
    std::shared_ptr<OrchestratorToTest> m_orchestrator;
    std::size_t m_workersSize = 5;

    void SetUp() override
    {
        m_orchestrator = std::make_shared<OrchestratorToTest>();

        // Add 5 mock workers
        for (int i = 0; i < m_workersSize; i++)
        {
            m_orchestrator->addMockWorker();
        }

        logging::testInit();
    }

    void TearDown() override
    {
        // Test if any call is pending
        testing::Mock::VerifyAndClearExpectations(m_orchestrator->m_mockstore.get());
        testing::Mock::VerifyAndClearExpectations(m_orchestrator->m_mockEventQueue.get());

        // Reset orchestrator
        m_orchestrator.reset();
    }
};

/**************************************************************************
 * TESTER EXPECTS CALL
 *************************************************************************/

TEST_F(OrchestratorTest, start)
{

    m_orchestrator->forEachWorkerMock([](auto mockWorker) { EXPECT_CALL(*mockWorker, start()).Times(1); });
    EXPECT_CALL(*m_orchestrator->m_testerWorkerMock, start()).Times(1);

    ASSERT_NO_THROW(m_orchestrator->start());
}

TEST_F(OrchestratorTest, stop)
{

    m_orchestrator->expectDumpTester();
    m_orchestrator->forEachWorkerMock([](auto mockWorker) { EXPECT_CALL(*mockWorker, stop()).Times(1); });
    EXPECT_CALL(*m_orchestrator->m_testerWorkerMock, stop()).Times(1);

    ASSERT_NO_THROW(m_orchestrator->stop());
}

TEST_F(OrchestratorTest, entryPostPolicyNameEmptyFailure)
{
    EXPECT_THROW((test::EntryPost {"test", cm::store::NamespaceId {""}, 0}), std::runtime_error);
}

TEST_F(OrchestratorTest, entryPostNameEmptyFailure)
{
    EXPECT_TRUE(m_orchestrator->postTestEntry(test::EntryPost {"", G_NAMESPACE_ID, 0}).has_value());
}

TEST_F(OrchestratorTest, entryPostAddEntryFailure)
{
    m_orchestrator->expectPostEntryAddEntryFailure();
    EXPECT_TRUE(m_orchestrator->postTestEntry(test::EntryPost {"test", G_NAMESPACE_ID, 0}).has_value());
}

TEST_F(OrchestratorTest, PostEntryEnableEntryFailure)
{
    m_orchestrator->expectPostEntryEnableEntryFailure();
    EXPECT_TRUE(m_orchestrator->postTestEntry(test::EntryPost {"test", G_NAMESPACE_ID, 0}).has_value());
}

TEST_F(OrchestratorTest, entryPostSuccess)
{
    m_orchestrator->expectPostEntrySuccess();
    EXPECT_FALSE(m_orchestrator->postTestEntry(test::EntryPost {"test", G_NAMESPACE_ID, 0}).has_value());
}

TEST_F(OrchestratorTest, entryDeleteNameEmptyFailure)
{
    EXPECT_TRUE(m_orchestrator->deleteTestEntry("").has_value());
}

TEST_F(OrchestratorTest, entryDeleteRemoveEntryFailure)
{
    m_orchestrator->expectDeleteEntryRemoveEntryFailure();
    EXPECT_TRUE(m_orchestrator->deleteTestEntry("test").has_value());
}

TEST_F(OrchestratorTest, entryDeleteSuccess)
{
    m_orchestrator->expectDeleteEntrySuccess();
    EXPECT_FALSE(m_orchestrator->deleteTestEntry("test").has_value());
}

TEST_F(OrchestratorTest, entryGetNameEmptyFailure)
{
    EXPECT_TRUE(base::isError(m_orchestrator->getTestEntry("")));
}

TEST_F(OrchestratorTest, entryGetGetEntryFailure)
{
    m_orchestrator->expectGetEntryGetEntryFailure();
    EXPECT_TRUE(base::isError(m_orchestrator->getTestEntry("test")));
}

TEST_F(OrchestratorTest, entryGetSuccess)
{
    m_orchestrator->expectGetEntrySuccess();
    EXPECT_FALSE(base::isError(m_orchestrator->getTestEntry("test")));
}

TEST_F(OrchestratorTest, entryReloadNameEmptyFailure)
{
    EXPECT_TRUE(base::isError(m_orchestrator->reloadTestEntry("")));
}

TEST_F(OrchestratorTest, entryReloadRebuildEntryFailure)
{
    m_orchestrator->expectReloadEntryRebuildEntryFailure();
    EXPECT_TRUE(base::isError(m_orchestrator->reloadTestEntry("test")));
}

TEST_F(OrchestratorTest, entryReloadEnableEntryFailure)
{
    m_orchestrator->expectReloadEntryEnableEntryFailure();
    EXPECT_TRUE(base::isError(m_orchestrator->reloadTestEntry("test")));
}

TEST_F(OrchestratorTest, entryReloadSuccess)
{
    m_orchestrator->expectReloadSuccess();
    EXPECT_FALSE(base::isError(m_orchestrator->reloadTestEntry("test")));
}

TEST_F(OrchestratorTest, entriesGetGetEntriesFailure)
{
    m_orchestrator->expectGetGetEntriesEmpty();
    EXPECT_TRUE(m_orchestrator->getTestEntries().empty());
}

TEST_F(OrchestratorTest, entriesGetSuccess)
{
    m_orchestrator->expectGetEntriesSuccess();
    EXPECT_FALSE(m_orchestrator->getTestEntries().empty());
}

TEST_F(OrchestratorTest, getAssetsNameEmptyFailure)
{
    EXPECT_TRUE(base::isError(m_orchestrator->getAssets("")));
}

TEST_F(OrchestratorTest, getAssetsEmpty)
{
    m_orchestrator->expectGetAssetsEmpty();
    EXPECT_TRUE(base::isError(m_orchestrator->getAssets("test")));
}

TEST_F(OrchestratorTest, getAssetsSuccess)
{
    m_orchestrator->expectGetAssetsSuccess();
    EXPECT_FALSE(base::isError(m_orchestrator->getAssets("test")));
}

TEST_F(OrchestratorTest, ingestTraceLevelNoneAssetNotEmptyFailure)
{
    m_orchestrator->expectGetAssetsSuccess();
    test::Options opt(test::Options::TraceLevel::NONE, std::unordered_set<std::string> {"anyAsset"}, "test");

    auto event = std::make_shared<json::Json>(R"({"message":"test"})");

    auto resultFuture = m_orchestrator->ingestTest(std::move(event), opt);
    resultFuture.wait();
    auto result = resultFuture.get();

    EXPECT_TRUE(base::isError(result));
}

TEST_F(OrchestratorTest, ingestNameEmptyFailure)
{
    m_orchestrator->expectGetAssetsSuccess();
    test::Options opt(test::Options::TraceLevel::NONE, std::unordered_set<std::string> {}, "");

    auto event = std::make_shared<json::Json>(R"({"message":"test"})");
    auto resultFuture = m_orchestrator->ingestTest(std::move(event), opt);
    resultFuture.wait();
    auto result = resultFuture.get();

    EXPECT_TRUE(base::isError(result));
}

/**************************************************************************
 * ROUTER EXPECTS CALL
 *************************************************************************/

TEST_F(OrchestratorTest, entryPostPolicyNameEmptyFailureRouter)
{
    EXPECT_THROW((prod::EntryPost {"test", cm::store::NamespaceId {""}, 10}), std::runtime_error);
}

TEST_F(OrchestratorTest, entryPostNameEmptyFailureRouter)
{
    EXPECT_TRUE(m_orchestrator->postEntry(prod::EntryPost {"", G_NAMESPACE_ID, 10}).has_value());
}

TEST_F(OrchestratorTest, entryPostPriorityEqualZeroFailureRouter)
{
    EXPECT_TRUE(m_orchestrator->postEntry(prod::EntryPost {"test", G_NAMESPACE_ID, 0}).has_value());
}

TEST_F(OrchestratorTest, entryPostAddEntryFailureRouter)
{
    m_orchestrator->expectPostEntryAddEntryFailureRouter();
    EXPECT_TRUE(m_orchestrator->postEntry(prod::EntryPost {"test", G_NAMESPACE_ID, 10}).has_value());
}

TEST_F(OrchestratorTest, PostEntryEnableEntryFailureRouter)
{
    m_orchestrator->expectPostEntryEnableEntryFailureRouter();
    EXPECT_TRUE(m_orchestrator->postEntry(prod::EntryPost {"test", G_NAMESPACE_ID, 10}).has_value());
}

TEST_F(OrchestratorTest, entryPostSuccessRouter)
{
    m_orchestrator->expectPostEntrySuccessRouter();
    EXPECT_FALSE(m_orchestrator->postEntry(prod::EntryPost {"test", G_NAMESPACE_ID, 10}).has_value());
}

TEST_F(OrchestratorTest, entryDeleteNameEmptyFailureRouter)
{
    EXPECT_TRUE(m_orchestrator->deleteEntry("").has_value());
}

TEST_F(OrchestratorTest, entryDeleteRemoveEntryFailureRouter)
{
    m_orchestrator->expectDeleteEntryRemoveEntryFailureRouter();
    EXPECT_TRUE(m_orchestrator->deleteEntry("test").has_value());
}

TEST_F(OrchestratorTest, entryDeleteSuccessRouter)
{
    m_orchestrator->expectDeleteEntrySuccessRouter();
    EXPECT_FALSE(m_orchestrator->deleteEntry("test").has_value());
}

TEST_F(OrchestratorTest, entryGetNameEmptyFailureRouter)
{
    EXPECT_TRUE(base::isError(m_orchestrator->getEntry("")));
}

TEST_F(OrchestratorTest, entryGetGetEntryFailureRouter)
{
    m_orchestrator->expectGetEntryGetEntryFailureRouter();
    EXPECT_TRUE(base::isError(m_orchestrator->getEntry("test")));
}

TEST_F(OrchestratorTest, entryGetSuccessRouter)
{
    m_orchestrator->expectGetEntrySuccessRouter();
    EXPECT_FALSE(base::isError(m_orchestrator->getEntry("test")));
}

TEST_F(OrchestratorTest, entryReloadNameEmptyFailureRouter)
{
    EXPECT_TRUE(base::isError(m_orchestrator->reloadEntry("")));
}

TEST_F(OrchestratorTest, changeEntryPriorityNameNotFound)
{
    EXPECT_TRUE(base::isError(m_orchestrator->changeEntryPriority("", 10)));
}

TEST_F(OrchestratorTest, changeEntryPriorityFailure)
{
    m_orchestrator->expectChangePriorityFailure();
    EXPECT_TRUE(base::isError(m_orchestrator->changeEntryPriority("test", 10)));
}

TEST_F(OrchestratorTest, changeEntryPrioritySuccess)
{
    m_orchestrator->expectChangePrioritySuccess();
    EXPECT_FALSE(base::isError(m_orchestrator->changeEntryPriority("test", 10)));
}

TEST_F(OrchestratorTest, entriesGetGetEntriesFailureRouter)
{
    m_orchestrator->expectGetGetEntriesEmptyRouter();
    EXPECT_TRUE(m_orchestrator->getEntries().empty());
}

TEST_F(OrchestratorTest, entriesGetSuccessRouter)
{
    m_orchestrator->expectGetEntriesSuccessRouter();
    EXPECT_FALSE(m_orchestrator->getEntries().empty());
}

TEST_F(OrchestratorTest, postEventHighLoadStartsContentionEvenIfPushSucceeds)
{
    IngestEvent event {std::make_shared<json::Json>(R"({"k":"v"})"), "raw-event"};

    EXPECT_CALL(*m_orchestrator->m_mockEventQueue, push(testing::_)).WillOnce(testing::Return(true));
    EXPECT_CALL(*m_orchestrator->m_mockEventQueue, size()).WillOnce(testing::Return(90));
    EXPECT_CALL(*m_orchestrator->m_mockEventQueue, aproxFreeSlots()).WillOnce(testing::Return(10));

    m_orchestrator->postEvent(std::move(event));

    EXPECT_TRUE(m_orchestrator->isQueueContended());
    EXPECT_GT(m_orchestrator->contentionStartUsec(), 0);
    EXPECT_GT(m_orchestrator->lastContentionWarningUsec(), 0);
    EXPECT_EQ(m_orchestrator->droppedEventsInContention(), 0U);
}

TEST_F(OrchestratorTest, postEventPushFailureIncrementsDroppedDuringHighLoadContention)
{
    auto nowUsec =
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch())
            .count();

    m_orchestrator->setContentionState(true, nowUsec, nowUsec, 3);

    IngestEvent event {std::make_shared<json::Json>(R"({"k":"v"})"), "raw-event"};
    EXPECT_CALL(*m_orchestrator->m_mockEventQueue, push(testing::_)).WillOnce(testing::Return(false));
    EXPECT_CALL(*m_orchestrator->m_mockEventQueue, size()).WillOnce(testing::Return(95));
    EXPECT_CALL(*m_orchestrator->m_mockEventQueue, aproxFreeSlots()).WillOnce(testing::Return(5));

    m_orchestrator->postEvent(std::move(event));

    EXPECT_TRUE(m_orchestrator->isQueueContended());
    EXPECT_EQ(m_orchestrator->droppedEventsInContention(), 4U);
}

TEST_F(OrchestratorTest, postEventPushSuccessKeepsContentionIfLoadStillHigh)
{
    const auto nowUsec =
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch())
            .count();
    const int64_t startUsec = nowUsec;
    const int64_t lastWarnUsec = nowUsec;
    const uint64_t droppedCount = 10U;
    m_orchestrator->setContentionState(true, startUsec, lastWarnUsec, droppedCount);

    IngestEvent event {std::make_shared<json::Json>(R"({"k":"v"})"), "raw-event"};
    EXPECT_CALL(*m_orchestrator->m_mockEventQueue, push(testing::_)).WillOnce(testing::Return(true));
    EXPECT_CALL(*m_orchestrator->m_mockEventQueue, size()).WillOnce(testing::Return(92));
    EXPECT_CALL(*m_orchestrator->m_mockEventQueue, aproxFreeSlots()).WillOnce(testing::Return(8));

    m_orchestrator->postEvent(std::move(event));

    EXPECT_TRUE(m_orchestrator->isQueueContended());
    EXPECT_EQ(m_orchestrator->contentionStartUsec(), startUsec);
    EXPECT_EQ(m_orchestrator->lastContentionWarningUsec(), lastWarnUsec);
    EXPECT_EQ(m_orchestrator->droppedEventsInContention(), droppedCount);
}

TEST_F(OrchestratorTest, postEventLowLoadResetsContentionState)
{
    m_orchestrator->setContentionState(true, 123, 456, 10);

    IngestEvent event {std::make_shared<json::Json>(R"({"k":"v"})"), "raw-event"};
    EXPECT_CALL(*m_orchestrator->m_mockEventQueue, push(testing::_)).WillOnce(testing::Return(true));
    EXPECT_CALL(*m_orchestrator->m_mockEventQueue, size()).WillOnce(testing::Return(50));
    EXPECT_CALL(*m_orchestrator->m_mockEventQueue, aproxFreeSlots()).WillOnce(testing::Return(50));

    m_orchestrator->postEvent(std::move(event));

    EXPECT_FALSE(m_orchestrator->isQueueContended());
    EXPECT_EQ(m_orchestrator->contentionStartUsec(), 0);
    EXPECT_EQ(m_orchestrator->lastContentionWarningUsec(), 0);
    EXPECT_EQ(m_orchestrator->droppedEventsInContention(), 0U);
}
