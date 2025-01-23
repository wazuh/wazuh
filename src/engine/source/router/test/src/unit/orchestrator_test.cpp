#include <gtest/gtest.h>

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
const std::string G_NDJ_AGENT_HEADER {
    R"({"agent":{"id":"2887e1cf-9bf2-431a-b066-a46860080f56","name":"javier","type":"endpoint","version":"5.0.0","groups":["group1","group2"],"host":{"hostname":"myhost","os":{"name":"Amazon Linux 2","platform":"Linux"},"ip":["192.168.1.2"],"architecture":"x86_64"}}})"};
const std::string G_NDJ_MODULE_SUBHEADER_1 {R"({"module": "logcollector", "collector": "file"})"};
const std::string G_NDJ_EVENT_1 {
    R"({"log": {"file": {"path": "/var/log/apache2/access.log"}}, "base": {"tags": ["production-server"]}, "event": {"original": "::1 - - [26/Jun/2020:16:16:29 +0200] \"GET /favicon.ico HTTP/1.1\" 404 209", "ingested": "2023-12-26T09:22:14.000Z", "module": "apache-access", "provider": "file"}})"};
const std::string G_NDJ_EVENT_2 {
    R"({"log": {"file": {"path": "/var/log/apache2/error.log"}}, "base": {"tags": ["testing-server"]}, "event": {"original": "::1 - - [26/Jun/2020:16:16:29 +0200] \"GET /favicon.ico HTTP/1.1\" 404 209", "ingested": "2023-12-26T09:22:14.000Z", "module": "apache-error", "provider": "file"}})"};
const std::string G_NDJ_EVENT_3 {
    R"({"log": {"file": {"path": "/tmp/syslog.log"}}, "event": {"original": "SYSLOG EXAMPLE", "ingested": "2023-12-26T09:22:14.000Z", "module": "custom-syslog-app", "provider": "file"}})"};

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
    std::shared_ptr<queue::mocks::MockQueue<base::Event>> m_mockEventQueue;
    std::list<std::shared_ptr<MockWorker>> m_mocks;

    OrchestratorToTest()
        : router::Orchestrator()
    {
        m_testTimeout = 1000;
        m_mockstore = std::make_shared<store::mocks::MockStore>();
        m_wStore = m_mockstore;
        m_mockEventQueue = std::make_shared<queue::mocks::MockQueue<base::Event>>();
        m_eventQueue = m_mockEventQueue;
    };

    auto forEachWorkerMock(std::function<void(std::shared_ptr<MockWorker>)> func)
    {
        for (auto& mock : m_mocks)
        {
            func(mock);
        }
    }

    auto addMockWorker() -> std::shared_ptr<MockWorker>
    {
        auto workerMock = std::make_shared<MockWorker>();

        m_workers.emplace_back(workerMock);
        m_mocks.emplace_back(workerMock);

        return workerMock;
    }

    /**************************************************************************
     * TESTER EXPECTS CALL
     *************************************************************************/

    void expectDumpTester()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        auto& firstWorkerMock = m_mocks.front();
        EXPECT_CALL(*firstWorkerMock, getTester()).WillOnce(testing::ReturnRefOfCopy(itesterMock));

        EXPECT_CALL(*testerMock, getEntries()).WillOnce(testing::Return(std::list<test::Entry> {}));

        EXPECT_CALL(*(m_mockstore), upsertInternalDoc(testing::_, testing::_))
            .WillOnce(::testing::Return(store::mocks::storeOk()));
    }

    void expectPostEntryAddEntryFailture()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        EXPECT_CALL(*m_mocks.front(), getTester()).WillOnce(testing::ReturnRefOfCopy(itesterMock));
        EXPECT_CALL(*testerMock, addEntry(testing::_, testing::_)).WillOnce(testing::Return(base::Error {"error"}));
    }

    void expectPostEntryEnableEntryFailture()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        for (auto mock : m_mocks)
        {
            EXPECT_CALL(*mock, getTester()).WillRepeatedly(testing::ReturnRefOfCopy(itesterMock));
            EXPECT_CALL(*testerMock, addEntry(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));
        }

        EXPECT_CALL(*testerMock, enableEntry(testing::_)).WillOnce(testing::Return(base::Error {"error"}));
    }

    void expectPostEntrySuccess()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        for (auto mock : m_mocks)
        {
            EXPECT_CALL(*mock, getTester()).WillRepeatedly(testing::ReturnRefOfCopy(itesterMock));
            EXPECT_CALL(*testerMock, addEntry(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));
            EXPECT_CALL(*testerMock, enableEntry(testing::_)).WillRepeatedly(testing::Return(std::nullopt));
            EXPECT_CALL(*testerMock, getEntries()).WillRepeatedly(testing::Return(std::list<test::Entry> {}));
        }

        EXPECT_CALL(*(m_mockstore), upsertInternalDoc(testing::_, testing::_))
            .WillOnce(::testing::Return(store::mocks::storeOk()));
    }

    void expectDeleteEntryRemoveEntryFailture()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        EXPECT_CALL(*m_mocks.front(), getTester()).WillOnce(testing::ReturnRefOfCopy(itesterMock));
        EXPECT_CALL(*testerMock, removeEntry(testing::_)).WillOnce(testing::Return(base::Error {"error"}));
    }

    void expectDeleteEntrySuccess()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        for (auto mock : m_mocks)
        {
            EXPECT_CALL(*mock, getTester()).WillRepeatedly(testing::ReturnRefOfCopy(itesterMock));
            EXPECT_CALL(*testerMock, removeEntry(testing::_)).WillRepeatedly(testing::Return(std::nullopt));
            EXPECT_CALL(*testerMock, getEntries()).WillRepeatedly(testing::Return(std::list<test::Entry> {}));
        }

        EXPECT_CALL(*(m_mockstore), upsertInternalDoc(testing::_, testing::_))
            .WillOnce(::testing::Return(store::mocks::storeOk()));
    }

    void expectGetEntryGetEntryFailture()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        EXPECT_CALL(*m_mocks.front(), getTester()).WillOnce(testing::ReturnRefOfCopy(itesterMock));
        EXPECT_CALL(*testerMock, getEntry(testing::_)).WillOnce(testing::Return(base::Error {"error"}));
    }

    void expectGetEntrySuccess()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        for (auto mock : m_mocks)
        {
            EXPECT_CALL(*mock, getTester()).WillRepeatedly(testing::ReturnRefOfCopy(itesterMock));
            EXPECT_CALL(*testerMock, getEntry(testing::_))
                .WillRepeatedly(testing::Return(test::EntryPost {"test", "policy", 0}));
        }
    }

    void expectReloadEntryRebuildEntryFailture()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        EXPECT_CALL(*m_mocks.front(), getTester()).WillOnce(testing::ReturnRefOfCopy(itesterMock));
        EXPECT_CALL(*testerMock, rebuildEntry(testing::_)).WillOnce(testing::Return(base::Error {"error"}));
    }

    void expectReloadEntryEnableEntryFailture()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        for (auto mock : m_mocks)
        {
            EXPECT_CALL(*mock, getTester()).WillRepeatedly(testing::ReturnRefOfCopy(itesterMock));
            EXPECT_CALL(*testerMock, rebuildEntry(testing::_)).WillRepeatedly(testing::Return(std::nullopt));
        }

        EXPECT_CALL(*testerMock, enableEntry(testing::_)).WillOnce(testing::Return(base::Error {"error"}));
    }

    void expectReloadSuccess()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        for (auto mock : m_mocks)
        {
            EXPECT_CALL(*mock, getTester()).WillRepeatedly(testing::ReturnRefOfCopy(itesterMock));
            EXPECT_CALL(*testerMock, rebuildEntry(testing::_)).WillRepeatedly(testing::Return(std::nullopt));
        }

        EXPECT_CALL(*testerMock, enableEntry(testing::_)).WillRepeatedly(testing::Return(std::nullopt));
    }

    void expectGetGetEntriesEmpty()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        EXPECT_CALL(*m_mocks.front(), getTester()).WillOnce(testing::ReturnRefOfCopy(itesterMock));
        EXPECT_CALL(*testerMock, getEntries()).WillOnce(testing::Return(std::list<test::Entry> {}));
    }

    void expectGetEntriesSuccess()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        for (auto mock : m_mocks)
        {
            EXPECT_CALL(*mock, getTester()).WillRepeatedly(testing::ReturnRefOfCopy(itesterMock));
        }

        EXPECT_CALL(*testerMock, getEntries())
            .WillRepeatedly(testing::Return(std::list<test::Entry> {test::EntryPost {"test", "policy", 0}}));
    }

    void expectGetAssetsEmpty()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        EXPECT_CALL(*m_mocks.front(), getTester()).WillOnce(testing::ReturnRefOfCopy(itesterMock));
        EXPECT_CALL(*testerMock, getAssets(testing::_)).WillOnce(testing::Return(base::Error {"error"}));
    }

    void expectGetAssetsSuccess()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto testerMock = std::make_shared<MockTester>();
        auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

        for (auto mock : m_mocks)
        {
            EXPECT_CALL(*mock, getTester()).WillRepeatedly(testing::ReturnRefOfCopy(itesterMock));
            EXPECT_CALL(*testerMock, getAssets(testing::_))
                .WillRepeatedly(testing::Return(std::unordered_set<std::string> {"decoder", "filter"}));
        }
    }

    /**************************************************************************
     * ROUTER EXPECTS CALL
     *************************************************************************/

    void expectPostEntryAddEntryFailtureRouter()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto routerMock = std::make_shared<MockRouter>();
        auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

        EXPECT_CALL(*m_mocks.front(), getRouter()).WillOnce(testing::ReturnRefOfCopy(irouterMock));
        EXPECT_CALL(*routerMock, addEntry(testing::_, testing::_)).WillOnce(testing::Return(base::Error {"error"}));
    }

    void expectPostEntryEnableEntryFailtureRouter()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto routerMock = std::make_shared<MockRouter>();
        auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

        for (auto mock : m_mocks)
        {
            EXPECT_CALL(*mock, getRouter()).WillRepeatedly(testing::ReturnRefOfCopy(irouterMock));
            EXPECT_CALL(*routerMock, addEntry(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));
        }

        EXPECT_CALL(*routerMock, enableEntry(testing::_)).WillOnce(testing::Return(base::Error {"error"}));
    }

    void expectPostEntrySuccessRouter()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto routerMock = std::make_shared<MockRouter>();
        auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

        for (auto mock : m_mocks)
        {
            EXPECT_CALL(*mock, getRouter()).WillRepeatedly(testing::ReturnRefOfCopy(irouterMock));
            EXPECT_CALL(*routerMock, addEntry(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));
            EXPECT_CALL(*routerMock, enableEntry(testing::_)).WillRepeatedly(testing::Return(std::nullopt));
            EXPECT_CALL(*routerMock, getEntries()).WillRepeatedly(testing::Return(std::list<prod::Entry> {}));
        }

        EXPECT_CALL(*(m_mockstore), upsertInternalDoc(testing::_, testing::_))
            .WillOnce(::testing::Return(store::mocks::storeOk()));
    }

    void expectDeleteEntryRemoveEntryFailtureRouter()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto routerMock = std::make_shared<MockRouter>();
        auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

        EXPECT_CALL(*m_mocks.front(), getRouter()).WillOnce(testing::ReturnRefOfCopy(irouterMock));
        EXPECT_CALL(*routerMock, removeEntry(testing::_)).WillOnce(testing::Return(base::Error {"error"}));
    }

    void expectDeleteEntrySuccessRouter()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto routerMock = std::make_shared<MockRouter>();
        auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

        for (auto mock : m_mocks)
        {
            EXPECT_CALL(*mock, getRouter()).WillRepeatedly(testing::ReturnRefOfCopy(irouterMock));
            EXPECT_CALL(*routerMock, removeEntry(testing::_)).WillRepeatedly(testing::Return(std::nullopt));
            EXPECT_CALL(*routerMock, getEntries()).WillRepeatedly(testing::Return(std::list<prod::Entry> {}));
        }

        EXPECT_CALL(*(m_mockstore), upsertInternalDoc(testing::_, testing::_))
            .WillOnce(::testing::Return(store::mocks::storeOk()));
    }

    void expectGetEntryGetEntryFailtureRouter()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto routerMock = std::make_shared<MockRouter>();
        auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

        EXPECT_CALL(*m_mocks.front(), getRouter()).WillOnce(testing::ReturnRefOfCopy(irouterMock));
        EXPECT_CALL(*routerMock, getEntry(testing::_)).WillOnce(testing::Return(base::Error {"error"}));
    }

    void expectGetEntrySuccessRouter()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto routerMock = std::make_shared<MockRouter>();
        auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

        for (auto mock : m_mocks)
        {
            EXPECT_CALL(*mock, getRouter()).WillRepeatedly(testing::ReturnRefOfCopy(irouterMock));
            EXPECT_CALL(*routerMock, getEntry(testing::_))
                .WillRepeatedly(testing::Return(prod::EntryPost {"test", "policy", "filter", 10}));
        }
    }

    void expectReloadEntryRebuildEntryFailtureRouter()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto routerMock = std::make_shared<MockRouter>();
        auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

        EXPECT_CALL(*m_mocks.front(), getRouter()).WillOnce(testing::ReturnRefOfCopy(irouterMock));
        EXPECT_CALL(*routerMock, rebuildEntry(testing::_)).WillOnce(testing::Return(base::Error {"error"}));
    }

    void expectReloadEntryEnableEntryFailtureRouter()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto routerMock = std::make_shared<MockRouter>();
        auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

        for (auto mock : m_mocks)
        {
            EXPECT_CALL(*mock, getRouter()).WillRepeatedly(testing::ReturnRefOfCopy(irouterMock));
            EXPECT_CALL(*routerMock, rebuildEntry(testing::_)).WillRepeatedly(testing::Return(std::nullopt));
        }

        EXPECT_CALL(*routerMock, enableEntry(testing::_)).WillOnce(testing::Return(base::Error {"error"}));
    }

    void expectReloadSuccessRouter()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto routerMock = std::make_shared<MockRouter>();
        auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

        for (auto mock : m_mocks)
        {
            EXPECT_CALL(*mock, getRouter()).WillRepeatedly(testing::ReturnRefOfCopy(irouterMock));
            EXPECT_CALL(*routerMock, rebuildEntry(testing::_)).WillRepeatedly(testing::Return(std::nullopt));
        }

        EXPECT_CALL(*routerMock, enableEntry(testing::_)).WillRepeatedly(testing::Return(std::nullopt));
    }

    void expectChangePriorityFailture()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto routerMock = std::make_shared<MockRouter>();
        auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

        EXPECT_CALL(*m_mocks.front(), getRouter()).WillOnce(testing::ReturnRefOfCopy(irouterMock));
        EXPECT_CALL(*routerMock, changePriority(testing::_, testing::_))
            .WillOnce(testing::Return(base::Error {"error"}));
    }

    void expectChangePrioritySuccess()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto routerMock = std::make_shared<MockRouter>();
        auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

        for (auto mock : m_mocks)
        {
            EXPECT_CALL(*mock, getRouter()).WillRepeatedly(testing::ReturnRefOfCopy(irouterMock));
            EXPECT_CALL(*routerMock, changePriority(testing::_, testing::_))
                .WillRepeatedly(testing::Return(std::nullopt));
            EXPECT_CALL(*routerMock, getEntries()).WillRepeatedly(testing::Return(std::list<prod::Entry> {}));
        }

        EXPECT_CALL(*(m_mockstore), upsertInternalDoc(testing::_, testing::_))
            .WillOnce(::testing::Return(store::mocks::storeOk()));
    }

    void expectGetGetEntriesEmptyRouter()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto routerMock = std::make_shared<MockRouter>();
        auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

        EXPECT_CALL(*m_mocks.front(), getRouter()).WillOnce(testing::ReturnRefOfCopy(irouterMock));
        EXPECT_CALL(*routerMock, getEntries()).WillOnce(testing::Return(std::list<prod::Entry> {}));
    }

    void expectGetEntriesSuccessRouter()
    {
        if (m_mocks.empty() || m_mocks.front() == nullptr || m_workers.empty() || m_workers.front() == nullptr)
        {
            FAIL() << "No mock worker";
        }

        auto routerMock = std::make_shared<MockRouter>();
        auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

        for (auto mock : m_mocks)
        {
            EXPECT_CALL(*mock, getRouter()).WillRepeatedly(testing::ReturnRefOfCopy(irouterMock));
        }

        EXPECT_CALL(*routerMock, getEntries())
            .WillRepeatedly(testing::Return(std::list<prod::Entry> {prod::EntryPost {"test", "policy", "filter", 10}}));
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

    m_orchestrator->forEachWorkerMock([](auto mockWorker) { EXPECT_CALL(*mockWorker, start(testing::_)).Times(1); });

    ASSERT_NO_THROW(m_orchestrator->start());
}

TEST_F(OrchestratorTest, stop)
{

    m_orchestrator->expectDumpTester();
    m_orchestrator->forEachWorkerMock([](auto mockWorker) { EXPECT_CALL(*mockWorker, stop()).Times(1); });

    ASSERT_NO_THROW(m_orchestrator->stop());
}

TEST_F(OrchestratorTest, entryPostPolicyNameEmptyFailture)
{
    EXPECT_TRUE(m_orchestrator->postTestEntry(test::EntryPost {"test", base::Name {}, 0}).has_value());
}

TEST_F(OrchestratorTest, entryPostNameEmptyFailture)
{
    EXPECT_TRUE(m_orchestrator->postTestEntry(test::EntryPost {"", "policy/test/0", 0}).has_value());
}

TEST_F(OrchestratorTest, entryPostAddEntryFailture)
{
    m_orchestrator->expectPostEntryAddEntryFailture();
    EXPECT_TRUE(m_orchestrator->postTestEntry(test::EntryPost {"test", "policy/test/0", 0}).has_value());
}

TEST_F(OrchestratorTest, PostEntryEnableEntryFailture)
{
    m_orchestrator->expectPostEntryEnableEntryFailture();
    EXPECT_TRUE(m_orchestrator->postTestEntry(test::EntryPost {"test", "policy/test/0", 0}).has_value());
}

TEST_F(OrchestratorTest, entryPostSuccess)
{
    m_orchestrator->expectPostEntrySuccess();
    EXPECT_FALSE(m_orchestrator->postTestEntry(test::EntryPost {"test", "policy/test/0", 0}).has_value());
}

TEST_F(OrchestratorTest, entryDeleteNameEmptyFailture)
{
    EXPECT_TRUE(m_orchestrator->deleteTestEntry("").has_value());
}

TEST_F(OrchestratorTest, entryDeleteRemoveEntryFailture)
{
    m_orchestrator->expectDeleteEntryRemoveEntryFailture();
    EXPECT_TRUE(m_orchestrator->deleteTestEntry("test").has_value());
}

TEST_F(OrchestratorTest, entryDeleteSuccess)
{
    m_orchestrator->expectDeleteEntrySuccess();
    EXPECT_FALSE(m_orchestrator->deleteTestEntry("test").has_value());
}

TEST_F(OrchestratorTest, entryGetNameEmptyFailture)
{
    EXPECT_TRUE(base::isError(m_orchestrator->getTestEntry("")));
}

TEST_F(OrchestratorTest, entryGetGetEntryFailture)
{
    m_orchestrator->expectGetEntryGetEntryFailture();
    EXPECT_TRUE(base::isError(m_orchestrator->getTestEntry("test")));
}

TEST_F(OrchestratorTest, entryGetSuccess)
{
    m_orchestrator->expectGetEntrySuccess();
    EXPECT_FALSE(base::isError(m_orchestrator->getTestEntry("test")));
}

TEST_F(OrchestratorTest, entryReloadNameEmptyFailture)
{
    EXPECT_TRUE(base::isError(m_orchestrator->reloadTestEntry("")));
}

TEST_F(OrchestratorTest, entryReloadRebuildEntryFailture)
{
    m_orchestrator->expectReloadEntryRebuildEntryFailture();
    EXPECT_TRUE(base::isError(m_orchestrator->reloadTestEntry("test")));
}

TEST_F(OrchestratorTest, entryReloadEnableEntryFailture)
{
    m_orchestrator->expectReloadEntryEnableEntryFailture();
    EXPECT_TRUE(base::isError(m_orchestrator->reloadTestEntry("test")));
}

TEST_F(OrchestratorTest, entryReloadSuccess)
{
    m_orchestrator->expectReloadSuccess();
    EXPECT_FALSE(base::isError(m_orchestrator->reloadTestEntry("test")));
}

TEST_F(OrchestratorTest, entriesGetGetEntriesFailture)
{
    m_orchestrator->expectGetGetEntriesEmpty();
    EXPECT_TRUE(m_orchestrator->getTestEntries().empty());
}

TEST_F(OrchestratorTest, entriesGetSuccess)
{
    m_orchestrator->expectGetEntriesSuccess();
    EXPECT_FALSE(m_orchestrator->getTestEntries().empty());
}

TEST_F(OrchestratorTest, getAssetsNameEmptyFailture)
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

TEST_F(OrchestratorTest, ingestTraceLevelNoneAssetNotEmptyFailture)
{
    m_orchestrator->expectGetAssetsSuccess();
    test::Options opt(test::Options::TraceLevel::NONE, std::unordered_set<std::string> {"anyAsset"}, "test");

    auto event = std::make_shared<json::Json>(R"({"message":"test"})");

    auto resultFuture = m_orchestrator->ingestTest(std::move(event), opt);
    resultFuture.wait();
    auto result = resultFuture.get();

    EXPECT_TRUE(base::isError(result));
}

TEST_F(OrchestratorTest, ingestNameEmptyFailture)
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

TEST_F(OrchestratorTest, entryPostPolicyNameEmptyFailtureRouter)
{
    EXPECT_TRUE(m_orchestrator->postEntry(prod::EntryPost {"test", base::Name {}, "filter/test/0", 10}).has_value());
}

TEST_F(OrchestratorTest, entryPostFilterNameEmptyFailtureRouter)
{
    EXPECT_TRUE(m_orchestrator->postEntry(prod::EntryPost {"test", "policy/test/0", base::Name {}, 10}).has_value());
}

TEST_F(OrchestratorTest, entryPostNameEmptyFailtureRouter)
{
    EXPECT_TRUE(m_orchestrator->postEntry(prod::EntryPost {"", "policy/test/0", "filter/test/0", 10}).has_value());
}

TEST_F(OrchestratorTest, entryPostPriorityEqualZeroFailtureRouter)
{
    EXPECT_TRUE(m_orchestrator->postEntry(prod::EntryPost {"test", "policy/test/0", "filter/test/0", 0}).has_value());
}

TEST_F(OrchestratorTest, entryPostAddEntryFailtureRouter)
{
    m_orchestrator->expectPostEntryAddEntryFailtureRouter();
    EXPECT_TRUE(m_orchestrator->postEntry(prod::EntryPost {"test", "policy/test/0", "filter/test/0", 10}).has_value());
}

TEST_F(OrchestratorTest, PostEntryEnableEntryFailtureRouter)
{
    m_orchestrator->expectPostEntryEnableEntryFailtureRouter();
    EXPECT_TRUE(m_orchestrator->postEntry(prod::EntryPost {"test", "policy/test/0", "filter/test/0", 10}).has_value());
}

TEST_F(OrchestratorTest, entryPostSuccessRouter)
{
    m_orchestrator->expectPostEntrySuccessRouter();
    EXPECT_FALSE(m_orchestrator->postEntry(prod::EntryPost {"test", "policy/test/0", "filter/test/0", 10}).has_value());
}

TEST_F(OrchestratorTest, entryDeleteNameEmptyFailtureRouter)
{
    EXPECT_TRUE(m_orchestrator->deleteEntry("").has_value());
}

TEST_F(OrchestratorTest, entryDeleteRemoveEntryFailtureRouter)
{
    m_orchestrator->expectDeleteEntryRemoveEntryFailtureRouter();
    EXPECT_TRUE(m_orchestrator->deleteEntry("test").has_value());
}

TEST_F(OrchestratorTest, entryDeleteSuccessRouter)
{
    m_orchestrator->expectDeleteEntrySuccessRouter();
    EXPECT_FALSE(m_orchestrator->deleteEntry("test").has_value());
}

TEST_F(OrchestratorTest, entryGetNameEmptyFailtureRouter)
{
    EXPECT_TRUE(base::isError(m_orchestrator->getEntry("")));
}

TEST_F(OrchestratorTest, entryGetGetEntryFailtureRouter)
{
    m_orchestrator->expectGetEntryGetEntryFailtureRouter();
    EXPECT_TRUE(base::isError(m_orchestrator->getEntry("test")));
}

TEST_F(OrchestratorTest, entryGetSuccessRouter)
{
    m_orchestrator->expectGetEntrySuccessRouter();
    EXPECT_FALSE(base::isError(m_orchestrator->getEntry("test")));
}

TEST_F(OrchestratorTest, entryReloadNameEmptyFailtureRouter)
{
    EXPECT_TRUE(base::isError(m_orchestrator->reloadEntry("")));
}

TEST_F(OrchestratorTest, changeEntryPriorityNameNotFound)
{
    EXPECT_TRUE(base::isError(m_orchestrator->changeEntryPriority("", 10)));
}

TEST_F(OrchestratorTest, changeEntryPriorityFailture)
{
    m_orchestrator->expectChangePriorityFailture();
    EXPECT_TRUE(base::isError(m_orchestrator->changeEntryPriority("test", 10)));
}

TEST_F(OrchestratorTest, changeEntryPrioritySuccess)
{
    m_orchestrator->expectChangePrioritySuccess();
    EXPECT_FALSE(base::isError(m_orchestrator->changeEntryPriority("test", 10)));
}

TEST_F(OrchestratorTest, entriesGetGetEntriesFailtureRouter)
{
    m_orchestrator->expectGetGetEntriesEmptyRouter();
    EXPECT_TRUE(m_orchestrator->getEntries().empty());
}

TEST_F(OrchestratorTest, entriesGetSuccessRouter)
{
    m_orchestrator->expectGetEntriesSuccessRouter();
    EXPECT_FALSE(m_orchestrator->getEntries().empty());
}

TEST_F(OrchestratorTest, postRawNdjsonsmallNDJsonsFailture)
{
    std::list<std::string> ndjsons = {"", "{}", "{}\n{}", "{}\n{}\n", "{}\n\n\n\n{}\n\n\n"};

    for (const auto& ndjson : ndjsons)
    {
        EXPECT_THROW(m_orchestrator->postRawNdjson(std::string(ndjson)), std::runtime_error)
            << "Failed for: " << ndjson;
    }
}

TEST_F(OrchestratorTest, postRawNdjsonNoCapacityFailture)
{

    auto ndjson = G_NDJ_AGENT_HEADER + "\n" + G_NDJ_MODULE_SUBHEADER_1 + "\n" + G_NDJ_EVENT_1;
    const auto event = std::make_shared<json::Json>(G_NDJ_EVENT_1.c_str());
    auto finalEvent = std::make_shared<json::Json>(G_NDJ_AGENT_HEADER.c_str());
    finalEvent->merge(true, *event);

    // no free slots
    EXPECT_CALL(*(m_orchestrator->m_mockEventQueue), aproxFreeSlots()).Times(1).WillOnce(testing::Return(0));

    EXPECT_NO_THROW(m_orchestrator->postRawNdjson(std::move(ndjson)));
}

TEST_F(OrchestratorTest, postRawNdjsonSuccess_oneEvent)
{
    auto ndjson = G_NDJ_AGENT_HEADER + "\n" + G_NDJ_MODULE_SUBHEADER_1 + "\n" + G_NDJ_EVENT_1;
    const auto event = std::make_shared<json::Json>(G_NDJ_EVENT_1.c_str());
    const auto subheader = std::make_shared<json::Json>(G_NDJ_MODULE_SUBHEADER_1.c_str());
    auto finalEvent = std::make_shared<json::Json>(G_NDJ_AGENT_HEADER.c_str());
    finalEvent->merge(true, *event);
    finalEvent->set("/event.module", subheader->getJson("/module").value());
    finalEvent->set("/event.collector", subheader->getJson("/collector").value());
    // 1 event 1 free slot
    EXPECT_CALL(*(m_orchestrator->m_mockEventQueue), aproxFreeSlots()).Times(1).WillOnce(testing::Return(1));
    EXPECT_CALL(*(m_orchestrator->m_mockEventQueue), tryPush(isEqualsEvent(finalEvent)))
        .WillOnce(testing::Return(true));
    EXPECT_NO_THROW(m_orchestrator->postRawNdjson(std::move(ndjson)));
}

TEST_F(OrchestratorTest, postRawNdjsonSuccess_multiEvent)
{
    auto ndjson = G_NDJ_AGENT_HEADER + "\n" + G_NDJ_MODULE_SUBHEADER_1 + "\n";
    ndjson += G_NDJ_EVENT_1 + "\n";
    ndjson += G_NDJ_EVENT_2 + "\n\n";
    ndjson += G_NDJ_EVENT_3;
    auto subheader = std::make_shared<json::Json>(G_NDJ_MODULE_SUBHEADER_1.c_str());

    std::vector<base::Event> events {};
    events.push_back(std::make_shared<json::Json>(G_NDJ_AGENT_HEADER.c_str()));
    events.push_back(std::make_shared<json::Json>(G_NDJ_AGENT_HEADER.c_str()));
    events.push_back(std::make_shared<json::Json>(G_NDJ_AGENT_HEADER.c_str()));
    {
        const auto event1 = std::make_shared<json::Json>(G_NDJ_EVENT_1.c_str());
        const auto event2 = std::make_shared<json::Json>(G_NDJ_EVENT_2.c_str());
        const auto event3 = std::make_shared<json::Json>(G_NDJ_EVENT_3.c_str());
        events[0]->set("/event.module", subheader->getJson("/module").value());
        events[0]->set("/event.collector", subheader->getJson("/collector").value());
        events[0]->merge(true, *event1);
        events[1]->set("/event.module", subheader->getJson("/module").value());
        events[1]->set("/event.collector", subheader->getJson("/collector").value());
        events[1]->merge(true, *event2);
        events[2]->set("/event.module", subheader->getJson("/module").value());
        events[2]->set("/event.collector", subheader->getJson("/collector").value());
        events[2]->merge(true, *event3);
    }

    // 3 event 3 free slot, in order
    testing::Sequence seq;
    EXPECT_CALL(*(m_orchestrator->m_mockEventQueue), aproxFreeSlots()).WillOnce(testing::Return(3));

    EXPECT_CALL(*(m_orchestrator->m_mockEventQueue), tryPush(isEqualsEvent(events[0])))
        .InSequence(seq)
        .WillOnce(testing::Return(true));
    EXPECT_CALL(*(m_orchestrator->m_mockEventQueue), tryPush(isEqualsEvent(events[1])))
        .InSequence(seq)
        .WillOnce(testing::Return(true));
    EXPECT_CALL(*(m_orchestrator->m_mockEventQueue), tryPush(isEqualsEvent(events[2])))
        .InSequence(seq)
        .WillOnce(testing::Return(true));

    EXPECT_NO_THROW(m_orchestrator->postRawNdjson(std::move(ndjson)));
}

TEST_F(OrchestratorTest, postRawNdjsonSuccess_multiEvent_freeSlot)
{
    auto ndjson = G_NDJ_AGENT_HEADER + "\n" + G_NDJ_MODULE_SUBHEADER_1 + "\n";
    ndjson += G_NDJ_EVENT_1 + "\n";
    ndjson += G_NDJ_EVENT_2 + "\n\n";
    ndjson += G_NDJ_EVENT_3;
    auto subheader = std::make_shared<json::Json>(G_NDJ_MODULE_SUBHEADER_1.c_str());

    std::vector<base::Event> events {};
    events.push_back(std::make_shared<json::Json>(G_NDJ_AGENT_HEADER.c_str()));
    events.push_back(std::make_shared<json::Json>(G_NDJ_AGENT_HEADER.c_str()));
    events.push_back(std::make_shared<json::Json>(G_NDJ_AGENT_HEADER.c_str()));
    {
        const auto event1 = std::make_shared<json::Json>(G_NDJ_EVENT_1.c_str());
        const auto event2 = std::make_shared<json::Json>(G_NDJ_EVENT_2.c_str());
        const auto event3 = std::make_shared<json::Json>(G_NDJ_EVENT_3.c_str());
        events[0]->set("/event.module", subheader->getJson("/module").value());
        events[0]->set("/event.collector", subheader->getJson("/collector").value());
        events[0]->merge(true, *event1);
        events[1]->set("/event.module", subheader->getJson("/module").value());
        events[1]->set("/event.collector", subheader->getJson("/collector").value());
        events[1]->merge(true, *event2);
        events[2]->set("/event.module", subheader->getJson("/module").value());
        events[2]->set("/event.collector", subheader->getJson("/collector").value());
        events[2]->merge(true, *event3);
    }

    // 3 event 3 free slot, in order
    testing::Sequence seq;
    EXPECT_CALL(*(m_orchestrator->m_mockEventQueue), aproxFreeSlots()).WillOnce(testing::Return(30));

    EXPECT_CALL(*(m_orchestrator->m_mockEventQueue), tryPush(isEqualsEvent(events[0])))
        .InSequence(seq)
        .WillOnce(testing::Return(true));
    EXPECT_CALL(*(m_orchestrator->m_mockEventQueue), tryPush(isEqualsEvent(events[1])))
        .InSequence(seq)
        .WillOnce(testing::Return(true));
    EXPECT_CALL(*(m_orchestrator->m_mockEventQueue), tryPush(isEqualsEvent(events[2])))
        .InSequence(seq)
        .WillOnce(testing::Return(true));

    EXPECT_NO_THROW(m_orchestrator->postRawNdjson(std::move(ndjson)));
}

TEST_F(OrchestratorTest, postRawNdjsonSuccess_3Events_2freeSlot)
{
    auto ndjson = G_NDJ_AGENT_HEADER + "\n" + G_NDJ_MODULE_SUBHEADER_1 + "\n";
    ndjson += G_NDJ_EVENT_1 + "\n";
    ndjson += G_NDJ_EVENT_2 + "\n\n";
    ndjson += G_NDJ_EVENT_3;
    auto subheader = std::make_shared<json::Json>(G_NDJ_MODULE_SUBHEADER_1.c_str());

    std::vector<base::Event> events {};
    events.push_back(std::make_shared<json::Json>(G_NDJ_AGENT_HEADER.c_str()));
    events.push_back(std::make_shared<json::Json>(G_NDJ_AGENT_HEADER.c_str()));
    events.push_back(std::make_shared<json::Json>(G_NDJ_AGENT_HEADER.c_str()));
    {
        const auto event1 = std::make_shared<json::Json>(G_NDJ_EVENT_1.c_str());
        const auto event2 = std::make_shared<json::Json>(G_NDJ_EVENT_2.c_str());
        events[0]->set("/event.module", subheader->getJson("/module").value());
        events[0]->set("/event.collector", subheader->getJson("/collector").value());
        events[0]->merge(true, *event1);
        events[1]->set("/event.module", subheader->getJson("/module").value());
        events[1]->set("/event.collector", subheader->getJson("/collector").value());
        events[1]->merge(true, *event2);
    }

    // 3 event 3 free slot, in order
    testing::Sequence seq;
    EXPECT_CALL(*(m_orchestrator->m_mockEventQueue), aproxFreeSlots()).WillOnce(testing::Return(2));

    EXPECT_CALL(*(m_orchestrator->m_mockEventQueue), tryPush(isEqualsEvent(events[0])))
        .InSequence(seq)
        .WillOnce(testing::Return(true));
    EXPECT_CALL(*(m_orchestrator->m_mockEventQueue), tryPush(isEqualsEvent(events[1])))
        .InSequence(seq)
        .WillOnce(testing::Return(true));

    EXPECT_NO_THROW(m_orchestrator->postRawNdjson(std::move(ndjson)));
}

TEST_F(OrchestratorTest, postRawNdjsonSuccess_multiEvent_discartMalformed)
{
    auto ndjson = G_NDJ_AGENT_HEADER + "\n" + G_NDJ_MODULE_SUBHEADER_1 + "\n";
    ndjson += G_NDJ_EVENT_1 + "\n";
    ndjson += std::string("hi! invalid event") + "\n\n";
    ndjson += G_NDJ_EVENT_3;
    auto subheader = std::make_shared<json::Json>(G_NDJ_MODULE_SUBHEADER_1.c_str());

    std::vector<base::Event> events {};
    events.push_back(std::make_shared<json::Json>(G_NDJ_AGENT_HEADER.c_str()));
    events.push_back(std::make_shared<json::Json>(G_NDJ_AGENT_HEADER.c_str()));
    {
        const auto event1 = std::make_shared<json::Json>(G_NDJ_EVENT_1.c_str());
        const auto event2 = std::make_shared<json::Json>(G_NDJ_EVENT_3.c_str());
        events[0]->set("/event.module", subheader->getJson("/module").value());
        events[0]->set("/event.collector", subheader->getJson("/collector").value());
        events[0]->merge(true, *event1);
        events[1]->set("/event.module", subheader->getJson("/module").value());
        events[1]->set("/event.collector", subheader->getJson("/collector").value());
        events[1]->merge(true, *event2);
    }

    // 3 event 3 free slot, in order
    testing::Sequence seq;
    EXPECT_CALL(*(m_orchestrator->m_mockEventQueue), aproxFreeSlots()).WillOnce(testing::Return(30));

    EXPECT_CALL(*(m_orchestrator->m_mockEventQueue), tryPush(isEqualsEvent(events[0])))
        .InSequence(seq)
        .WillOnce(testing::Return(true));
    EXPECT_CALL(*(m_orchestrator->m_mockEventQueue), tryPush(isEqualsEvent(events[1])))
        .InSequence(seq)
        .WillOnce(testing::Return(true));

    EXPECT_NO_THROW(m_orchestrator->postRawNdjson(std::move(ndjson)));
}
