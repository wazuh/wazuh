#include <gtest/gtest.h>

#include <chrono>
#include <deque>

#include <base/logging.hpp>
#include <base/utils/singletonLocator.hpp>
#include <base/utils/singletonLocatorStrategies.hpp>
#include <bk/mockController.hpp>
#include <builder/mockBuilder.hpp>
#include <builder/mockPolicy.hpp>
#include <fastmetrics/mockCounter.hpp>
#include <fastmetrics/mockManager.hpp>
#include <fastmetrics/registry.hpp>
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

std::shared_ptr<testing::NiceMock<MockRouterWorker>> makeMockWorkerOk(std::list<prod::Entry> entries = {})
{
    auto w = std::make_shared<testing::NiceMock<MockRouterWorker>>();
    auto r = std::make_shared<testing::NiceMock<MockRouter>>();
    auto ir = std::static_pointer_cast<router::IRouter>(r);
    ON_CALL(*w, get()).WillByDefault(testing::Return(ir));
    ON_CALL(*r, getEntries()).WillByDefault(testing::Return(entries));
    ON_CALL(*r, addEntry(testing::_, testing::_)).WillByDefault(testing::Return(std::nullopt));
    ON_CALL(*r, enableEntry(testing::_)).WillByDefault(testing::Return(std::nullopt));
    return w;
}

std::shared_ptr<testing::NiceMock<MockRouterWorker>> makeMockWorkerFailBuild()
{
    auto w = std::make_shared<testing::NiceMock<MockRouterWorker>>();
    auto r = std::make_shared<testing::NiceMock<MockRouter>>();
    ON_CALL(*w, get()).WillByDefault(testing::Return(std::static_pointer_cast<router::IRouter>(r)));
    ON_CALL(*r, addEntry(testing::_, testing::_)).WillByDefault(testing::Return(base::Error {"build error"}));
    return w;
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
    std::deque<std::function<std::shared_ptr<IWorker<IRouter>>()>> m_factoryQueue;

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
        m_workerFactory = [this]() -> std::shared_ptr<IWorker<IRouter>>
        {
            if (!m_factoryQueue.empty())
            {
                auto f = std::move(m_factoryQueue.front());
                m_factoryQueue.pop_front();
                return f();
            }
            return makeMockWorkerOk();
        };
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

    std::shared_ptr<testing::NiceMock<MockRouterWorker>> addWorkerToPool(std::list<prod::Entry> entries = {})
    {
        auto w = makeMockWorkerOk(std::move(entries));
        m_routerWorkers.emplace_back(w);
        return w;
    }

    void simulateShutdown() { m_isShutdown.store(true, std::memory_order_release); }

    // Public wrappers for protected methods
    void callDumpTesters() const { dumpTesters(); }
    void callDumpRouters() const { dumpRouters(); }
    void setShutdown(bool value) { m_isShutdown.store(value, std::memory_order_release); }
    void resetTesterWorker() { m_testerWorker = nullptr; }

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

    // Expansion helpers
    std::size_t workerPoolSize()
    {
        std::shared_lock lock {m_syncMutex};
        return m_routerWorkers.size();
    }
    void setTargetWorkerCount(std::size_t n) { m_targetWorkerCount = n; }

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

/**************************************************************************
 * hotSwapNamespace tests
 *************************************************************************/

TEST_F(OrchestratorTest, hotSwapNamespaceNameEmpty)
{
    auto result = m_orchestrator->hotSwapNamespace("", G_NAMESPACE_ID);
    EXPECT_TRUE(result.has_value());
}

TEST_F(OrchestratorTest, hotSwapNamespaceEntryNotFound)
{
    auto routerMock = std::make_shared<MockRouter>();
    auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

    EXPECT_CALL(*m_orchestrator->m_routerMocks.front(), get()).WillOnce(testing::Return(irouterMock));
    EXPECT_CALL(*routerMock, getEntry("myEntry")).WillOnce(testing::Return(base::Error {"not found"}));

    auto result = m_orchestrator->hotSwapNamespace("myEntry", G_NAMESPACE_ID);
    EXPECT_TRUE(result.has_value());
}

TEST_F(OrchestratorTest, hotSwapNamespaceWorkerFails)
{
    auto routerMock = std::make_shared<MockRouter>();
    auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

    // getEntry succeeds (entry exists)
    EXPECT_CALL(*m_orchestrator->m_routerMocks.front(), get()).WillRepeatedly(testing::Return(irouterMock));
    EXPECT_CALL(*routerMock, getEntry("myEntry"))
        .WillOnce(testing::Return(prod::EntryPost {"myEntry", G_NAMESPACE_ALT, 10}));

    // All workers will be asked to hotSwap, first one fails
    for (auto& mock : m_orchestrator->m_routerMocks)
    {
        EXPECT_CALL(*mock, get()).WillRepeatedly(testing::Return(irouterMock));
    }
    EXPECT_CALL(*routerMock, hotSwapNamespace("myEntry", testing::_))
        .WillOnce(testing::Return(base::Error {"swap failed"}));

    auto result = m_orchestrator->hotSwapNamespace("myEntry", G_NAMESPACE_ID);
    EXPECT_TRUE(result.has_value());
}

TEST_F(OrchestratorTest, hotSwapNamespaceSuccess)
{
    auto routerMock = std::make_shared<MockRouter>();
    auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

    EXPECT_CALL(*m_orchestrator->m_routerMocks.front(), get()).WillRepeatedly(testing::Return(irouterMock));
    EXPECT_CALL(*routerMock, getEntry("myEntry"))
        .WillOnce(testing::Return(prod::EntryPost {"myEntry", G_NAMESPACE_ALT, 10}));

    for (auto& mock : m_orchestrator->m_routerMocks)
    {
        EXPECT_CALL(*mock, get()).WillRepeatedly(testing::Return(irouterMock));
    }
    EXPECT_CALL(*routerMock, hotSwapNamespace("myEntry", testing::_))
        .WillRepeatedly(testing::Return(std::nullopt));
    EXPECT_CALL(*routerMock, getEntries()).WillRepeatedly(testing::Return(std::list<prod::Entry> {}));

    EXPECT_CALL(*(m_orchestrator->m_mockstore), upsertDoc(testing::_, testing::_))
        .WillOnce(::testing::Return(store::mocks::storeOk()));

    auto result = m_orchestrator->hotSwapNamespace("myEntry", G_NAMESPACE_ID);
    EXPECT_FALSE(result.has_value());
}

/**************************************************************************
 * existsEntry tests
 *************************************************************************/

TEST_F(OrchestratorTest, existsEntryNameEmpty)
{
    EXPECT_FALSE(m_orchestrator->existsEntry(""));
}

TEST_F(OrchestratorTest, existsEntryNotFound)
{
    auto routerMock = std::make_shared<MockRouter>();
    auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

    EXPECT_CALL(*m_orchestrator->m_routerMocks.front(), get()).WillOnce(testing::Return(irouterMock));
    EXPECT_CALL(*routerMock, getEntry("missing")).WillOnce(testing::Return(base::Error {"not found"}));

    EXPECT_FALSE(m_orchestrator->existsEntry("missing"));
}

TEST_F(OrchestratorTest, existsEntryFound)
{
    auto routerMock = std::make_shared<MockRouter>();
    auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

    EXPECT_CALL(*m_orchestrator->m_routerMocks.front(), get()).WillOnce(testing::Return(irouterMock));
    EXPECT_CALL(*routerMock, getEntry("exists"))
        .WillOnce(testing::Return(prod::EntryPost {"exists", G_NAMESPACE_ALT, 10}));

    EXPECT_TRUE(m_orchestrator->existsEntry("exists"));
}

/**************************************************************************
 * reloadEntry (router) tests - actual logic path
 *************************************************************************/

TEST_F(OrchestratorTest, entryReloadRebuildEntryFailureRouter)
{
    m_orchestrator->expectReloadEntryRebuildEntryFailureRouter();
    EXPECT_TRUE(m_orchestrator->reloadEntry("test").has_value());
}

TEST_F(OrchestratorTest, entryReloadEnableEntryFailureRouter)
{
    m_orchestrator->expectReloadEntryEnableEntryFailureRouter();
    EXPECT_TRUE(m_orchestrator->reloadEntry("test").has_value());
}

TEST_F(OrchestratorTest, entryReloadSuccessRouter)
{
    m_orchestrator->expectReloadSuccessRouter();
    EXPECT_FALSE(m_orchestrator->reloadEntry("test").has_value());
}

/**************************************************************************
 * renameTestEntry tests
 *************************************************************************/

TEST_F(OrchestratorTest, renameTestEntryFromEmpty)
{
    EXPECT_TRUE(m_orchestrator->renameTestEntry("", "newName").has_value());
}

TEST_F(OrchestratorTest, renameTestEntryToEmpty)
{
    EXPECT_TRUE(m_orchestrator->renameTestEntry("oldName", "").has_value());
}

TEST_F(OrchestratorTest, renameTestEntryWorkerFails)
{
    auto testerMock = std::make_shared<MockTester>();
    auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

    EXPECT_CALL(*m_orchestrator->m_testerWorkerMock, get()).WillOnce(testing::Return(itesterMock));
    EXPECT_CALL(*testerMock, renameEntry("oldName", "newName")).WillOnce(testing::Return(base::Error {"rename failed"}));

    EXPECT_TRUE(m_orchestrator->renameTestEntry("oldName", "newName").has_value());
}

TEST_F(OrchestratorTest, renameTestEntrySuccess)
{
    auto testerMock = std::make_shared<MockTester>();
    auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

    EXPECT_CALL(*m_orchestrator->m_testerWorkerMock, get()).WillRepeatedly(testing::Return(itesterMock));
    EXPECT_CALL(*testerMock, renameEntry("oldName", "newName")).WillOnce(testing::Return(std::nullopt));
    EXPECT_CALL(*testerMock, getEntries()).WillOnce(testing::Return(std::list<test::Entry> {}));

    EXPECT_CALL(*(m_orchestrator->m_mockstore), upsertDoc(testing::_, testing::_))
        .WillOnce(::testing::Return(store::mocks::storeOk()));

    EXPECT_FALSE(m_orchestrator->renameTestEntry("oldName", "newName").has_value());
}

/**************************************************************************
 * ingestTest (future overload) - queue path
 *************************************************************************/

TEST_F(OrchestratorTest, ingestTestFutureQueueSuccess)
{
    test::Options opt(test::Options::TraceLevel::NONE, std::unordered_set<std::string> {}, "testEnv");
    auto event = std::make_shared<json::Json>(R"({"message":"test"})");

    EXPECT_CALL(*m_orchestrator->m_mockTestQueue, tryPush(testing::_)).WillOnce(testing::Return(true));
    EXPECT_CALL(*m_orchestrator->m_mockEventQueue, empty()).WillOnce(testing::Return(true));
    EXPECT_CALL(*m_orchestrator->m_mockEventQueue, push(testing::_)).WillOnce(testing::Return(true));

    auto testerMock = std::make_shared<MockTester>();
    auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);
    EXPECT_CALL(*m_orchestrator->m_testerWorkerMock, get()).WillOnce(testing::Return(itesterMock));
    EXPECT_CALL(*testerMock, updateLastUsed(testing::_, testing::_)).WillOnce(testing::Return(true));

    auto future = m_orchestrator->ingestTest(std::move(event), opt);
    // Future is pending (no worker to resolve the promise), just verify no crash
    EXPECT_TRUE(future.valid());
}

TEST_F(OrchestratorTest, ingestTestFutureQueueFull)
{
    test::Options opt(test::Options::TraceLevel::NONE, std::unordered_set<std::string> {}, "testEnv");
    auto event = std::make_shared<json::Json>(R"({"message":"test"})");

    EXPECT_CALL(*m_orchestrator->m_mockTestQueue, tryPush(testing::_)).WillOnce(testing::Return(false));

    auto future = m_orchestrator->ingestTest(std::move(event), opt);
    future.wait();
    auto result = future.get();
    EXPECT_TRUE(base::isError(result));
}

/**************************************************************************
 * ingestTest (callback overload) tests
 *************************************************************************/

TEST_F(OrchestratorTest, ingestTestCallbackNullEvent)
{
    test::Options opt(test::Options::TraceLevel::NONE, std::unordered_set<std::string> {}, "testEnv");
    auto result = m_orchestrator->ingestTest(nullptr, opt, [](auto&&) {});
    EXPECT_TRUE(result.has_value());
}

TEST_F(OrchestratorTest, ingestTestCallbackInvalidOptions)
{
    test::Options opt(test::Options::TraceLevel::NONE, std::unordered_set<std::string> {}, "");
    auto event = std::make_shared<json::Json>(R"({"message":"test"})");
    auto result = m_orchestrator->ingestTest(std::move(event), opt, [](auto&&) {});
    EXPECT_TRUE(result.has_value());
}

TEST_F(OrchestratorTest, ingestTestCallbackQueueFull)
{
    test::Options opt(test::Options::TraceLevel::NONE, std::unordered_set<std::string> {}, "testEnv");
    auto event = std::make_shared<json::Json>(R"({"message":"test"})");

    EXPECT_CALL(*m_orchestrator->m_mockTestQueue, tryPush(testing::_)).WillOnce(testing::Return(false));

    auto result = m_orchestrator->ingestTest(std::move(event), opt, [](auto&&) {});
    EXPECT_TRUE(result.has_value());
}

TEST_F(OrchestratorTest, ingestTestCallbackSuccess)
{
    test::Options opt(test::Options::TraceLevel::NONE, std::unordered_set<std::string> {}, "testEnv");
    auto event = std::make_shared<json::Json>(R"({"message":"test"})");

    EXPECT_CALL(*m_orchestrator->m_mockTestQueue, tryPush(testing::_)).WillOnce(testing::Return(true));
    EXPECT_CALL(*m_orchestrator->m_mockEventQueue, empty()).WillOnce(testing::Return(false));

    auto testerMock = std::make_shared<MockTester>();
    auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);
    EXPECT_CALL(*m_orchestrator->m_testerWorkerMock, get()).WillOnce(testing::Return(itesterMock));
    EXPECT_CALL(*testerMock, updateLastUsed(testing::_, testing::_)).WillOnce(testing::Return(true));

    auto result = m_orchestrator->ingestTest(std::move(event), opt, [](auto&&) {});
    EXPECT_FALSE(result.has_value());
}

/**************************************************************************
 * requestShutdown tests
 *************************************************************************/

TEST_F(OrchestratorTest, requestShutdown)
{
    // Setup: expect stop calls and dump
    auto testerMock = std::make_shared<MockTester>();
    auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

    EXPECT_CALL(*m_orchestrator->m_testerWorkerMock, get()).WillOnce(testing::Return(itesterMock));
    EXPECT_CALL(*testerMock, getEntries()).WillOnce(testing::Return(std::list<test::Entry> {}));
    EXPECT_CALL(*(m_orchestrator->m_mockstore), upsertDoc(testing::_, testing::_))
        .WillOnce(::testing::Return(store::mocks::storeOk()));

    m_orchestrator->forEachWorkerMock([](auto mockWorker) { EXPECT_CALL(*mockWorker, stop()).Times(1); });
    EXPECT_CALL(*m_orchestrator->m_testerWorkerMock, stop()).Times(1);

    ASSERT_NO_THROW(m_orchestrator->requestShutdown());
}

/**************************************************************************
 * Orchestrator Real Constructor Tests (Options::validate, constructor, etc.)
 *************************************************************************/

class OrchestratorConstructorTest : public ::testing::Test
{
protected:
    std::shared_ptr<store::mocks::MockStore> m_mockStore;
    std::shared_ptr<builder::mocks::MockBuilder> m_mockBuilder;
    std::shared_ptr<bk::mocks::MockMakerController> m_mockControllerMaker;
    std::shared_ptr<fastqueue::mocks::MockQueue<IngestEvent>> m_mockProdQueue;
    std::shared_ptr<fastqueue::mocks::MockQueue<test::EventTest>> m_mockTestQueue;
    std::shared_ptr<fastmetrics::MockCounter> m_mockCounter;

    void SetUp() override
    {
        logging::testInit();

        SingletonLocator::registerManager<fastmetrics::IManager,
                                          base::PtrSingleton<fastmetrics::IManager, fastmetrics::MockManager>>();

        m_mockStore = std::make_shared<store::mocks::MockStore>();
        m_mockBuilder = std::make_shared<builder::mocks::MockBuilder>();
        m_mockControllerMaker = std::make_shared<bk::mocks::MockMakerController>();
        m_mockProdQueue = std::make_shared<fastqueue::mocks::MockQueue<IngestEvent>>();
        m_mockTestQueue = std::make_shared<fastqueue::mocks::MockQueue<test::EventTest>>();

        auto& manager = SingletonLocator::instance<fastmetrics::IManager>();
        auto* mockMetrics = dynamic_cast<fastmetrics::MockManager*>(&manager);
        ASSERT_NE(mockMetrics, nullptr);

        m_mockCounter = std::make_shared<fastmetrics::MockCounter>();
        static const std::string kCounterName = "test.counter";
        ON_CALL(*m_mockCounter, value()).WillByDefault(testing::Return(0.0));
        ON_CALL(*m_mockCounter, get()).WillByDefault(testing::Return(0));
        ON_CALL(*m_mockCounter, name()).WillByDefault(testing::ReturnRef(kCounterName));

        EXPECT_CALL(*mockMetrics, getOrCreateCounter(testing::_, testing::_, testing::_))
            .Times(testing::AnyNumber())
            .WillRepeatedly(testing::Return(m_mockCounter));
        ON_CALL(*mockMetrics, registerPullMetric(testing::_, testing::_, testing::_, testing::_))
            .WillByDefault(
                [](const std::string&, std::function<uint64_t()>, const std::string&, const std::string&) {});
        ON_CALL(*mockMetrics, registerPullMetricDouble(testing::_, testing::_, testing::_, testing::_))
            .WillByDefault(
                [](const std::string&, std::function<double()>, const std::string&, const std::string&) {});
    }

    void TearDown() override { SingletonLocator::unregisterManager<fastmetrics::IManager>(); }

    Orchestrator::Options makeValidOptions(int numThreads = 1)
    {
        Orchestrator::Options opt;
        opt.m_numThreads = numThreads;
        opt.m_wStore = m_mockStore;
        opt.m_builder = m_mockBuilder;
        opt.m_controllerMaker = m_mockControllerMaker;
        opt.m_prodQueue = m_mockProdQueue;
        opt.m_testQueue = m_mockTestQueue;
        opt.m_testTimeout = 1000;
        opt.m_rawIndexer = nullptr;
        return opt;
    }

    void expectStoreReturnsEmptyEntries()
    {
        // readDoc returns empty array for both router and tester tables
        EXPECT_CALL(*m_mockStore, readDoc(testing::_))
            .WillRepeatedly(testing::Return(store::mocks::storeReadDocResp(json::Json {"[]"})));
    }
};

TEST_F(OrchestratorConstructorTest, OptionsValidateNullStore)
{
    auto opt = makeValidOptions();
    opt.m_wStore = std::weak_ptr<store::IStore> {};
    ASSERT_THROW(opt.validate(), std::runtime_error);
}

TEST_F(OrchestratorConstructorTest, OptionsValidateNullBuilder)
{
    auto opt = makeValidOptions();
    opt.m_builder = std::weak_ptr<builder::IBuilder> {};
    ASSERT_THROW(opt.validate(), std::runtime_error);
}

TEST_F(OrchestratorConstructorTest, OptionsValidateNullControllerMaker)
{
    auto opt = makeValidOptions();
    opt.m_controllerMaker = nullptr;
    ASSERT_THROW(opt.validate(), std::runtime_error);
}

TEST_F(OrchestratorConstructorTest, OptionsValidateNullProdQueue)
{
    auto opt = makeValidOptions();
    opt.m_prodQueue = nullptr;
    ASSERT_THROW(opt.validate(), std::runtime_error);
}

TEST_F(OrchestratorConstructorTest, OptionsValidateNullTestQueue)
{
    auto opt = makeValidOptions();
    opt.m_testQueue = nullptr;
    ASSERT_THROW(opt.validate(), std::runtime_error);
}

TEST_F(OrchestratorConstructorTest, OptionsValidateInvalidNumThreadsNegative)
{
    auto opt = makeValidOptions();
    opt.m_numThreads = -1;
    ASSERT_THROW(opt.validate(), std::runtime_error);
}

TEST_F(OrchestratorConstructorTest, OptionsValidateInvalidNumThreadsTooHigh)
{
    auto opt = makeValidOptions();
    opt.m_numThreads = 200;
    ASSERT_THROW(opt.validate(), std::runtime_error);
}

TEST_F(OrchestratorConstructorTest, OptionsValidateInvalidTestTimeout)
{
    auto opt = makeValidOptions();
    opt.m_testTimeout = 0;
    ASSERT_THROW(opt.validate(), std::runtime_error);
}

TEST_F(OrchestratorConstructorTest, OptionsValidateSuccess)
{
    auto opt = makeValidOptions();
    ASSERT_NO_THROW(opt.validate());
}

TEST_F(OrchestratorConstructorTest, ConstructorStoreExpiredThrows)
{
    auto opt = makeValidOptions();
    // Let the store go out of scope
    opt.m_wStore = std::weak_ptr<store::IStore> {};
    ASSERT_THROW(auto o = Orchestrator(opt), std::runtime_error);
}

TEST_F(OrchestratorConstructorTest, ConstructorSuccessWithEmptyStore)
{
    expectStoreReturnsEmptyEntries();
    EXPECT_CALL(*m_mockStore, upsertDoc(testing::_, testing::_))
        .WillRepeatedly(testing::Return(store::mocks::storeOk()));
    auto opt = makeValidOptions(1);

    ASSERT_NO_THROW(
        {
            Orchestrator orch(opt);
            orch.stop();
        });
}

TEST_F(OrchestratorConstructorTest, ConstructorSuccessWithMultipleThreads)
{
    expectStoreReturnsEmptyEntries();
    EXPECT_CALL(*m_mockStore, upsertDoc(testing::_, testing::_))
        .WillRepeatedly(testing::Return(store::mocks::storeOk()));
    auto opt = makeValidOptions(3);

    ASSERT_NO_THROW(
        {
            Orchestrator orch(opt);
            orch.stop();
        });
}

TEST_F(OrchestratorConstructorTest, ConstructorStoreReadErrorCreatesDoc)
{
    // readDoc returns error -> getEntriesFromStore creates empty doc
    EXPECT_CALL(*m_mockStore, readDoc(testing::_))
        .WillRepeatedly(testing::Return(store::mocks::storeReadError<json::Json>()));
    EXPECT_CALL(*m_mockStore, createDoc(testing::_, testing::_))
        .WillRepeatedly(testing::Return(store::mocks::storeOk()));
    EXPECT_CALL(*m_mockStore, upsertDoc(testing::_, testing::_))
        .WillRepeatedly(testing::Return(store::mocks::storeOk()));

    auto opt = makeValidOptions(1);
    ASSERT_NO_THROW(
        {
            Orchestrator orch(opt);
            orch.stop();
        });
}

TEST_F(OrchestratorConstructorTest, ConstructorStartStop)
{
    expectStoreReturnsEmptyEntries();
    EXPECT_CALL(*m_mockStore, upsertDoc(testing::_, testing::_))
        .WillRepeatedly(testing::Return(store::mocks::storeOk()));
    auto opt = makeValidOptions(2);

    Orchestrator orch(opt);
    ASSERT_NO_THROW(orch.start());
    // Allow threads to start
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    ASSERT_NO_THROW(orch.stop());
}

TEST_F(OrchestratorConstructorTest, ConstructorRequestShutdown)
{
    expectStoreReturnsEmptyEntries();
    // Expect dump on stop
    EXPECT_CALL(*m_mockStore, upsertDoc(testing::_, testing::_))
        .WillRepeatedly(testing::Return(store::mocks::storeOk()));

    auto opt = makeValidOptions(1);

    Orchestrator orch(opt);
    ASSERT_NO_THROW(orch.requestShutdown());
}

TEST_F(OrchestratorConstructorTest, ConstructorWithRouterEntries)
{
    // JSON array with a valid router entry (has "priority" field)
    const std::string routerJson =
        R"([{"name":"route1","namespace":"policy","priority":10}])";
    const std::string testerJson = R"([])";

    EXPECT_CALL(*m_mockStore, readDoc(testing::_))
        .WillOnce(testing::Return(store::mocks::storeReadDocResp(json::Json {routerJson.c_str()})))
        .WillOnce(testing::Return(store::mocks::storeReadDocResp(json::Json {testerJson.c_str()})));
    EXPECT_CALL(*m_mockStore, upsertDoc(testing::_, testing::_))
        .WillRepeatedly(testing::Return(store::mocks::storeOk()));

    // Builder will be called to build the policy for the router entry
    auto mockPolicy = std::make_shared<builder::mocks::MockPolicy>();
    auto mockController = std::make_shared<bk::mocks::MockController>();
    std::unordered_set<base::Name> fakeAssets {base::Name("decoder/test/0")};
    const std::string hash = "hash123";

    EXPECT_CALL(*m_mockBuilder, buildPolicy(testing::_, testing::_))
        .WillRepeatedly(testing::Return(mockPolicy));
    EXPECT_CALL(*mockPolicy, assets()).WillRepeatedly(testing::ReturnRefOfCopy(fakeAssets));
    EXPECT_CALL(*mockPolicy, expression()).WillRepeatedly(testing::ReturnRefOfCopy(base::Expression {}));
    EXPECT_CALL(*mockPolicy, hash()).WillRepeatedly(testing::ReturnRefOfCopy(hash));
    EXPECT_CALL(*m_mockControllerMaker, create(testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Return(mockController));
    EXPECT_CALL(*mockController, stop()).Times(testing::AnyNumber());

    auto opt = makeValidOptions(1);
    ASSERT_NO_THROW(
        {
            Orchestrator orch(opt);
            orch.stop();
        });
}

TEST_F(OrchestratorConstructorTest, ConstructorWithTesterEntries)
{
    // JSON array with a valid tester entry (has "lifetime" field)
    const std::string routerJson = R"([])";
    const std::string testerJson =
        R"([{"name":"test1","namespace":"policy","lifetime":3600}])";

    EXPECT_CALL(*m_mockStore, readDoc(testing::_))
        .WillOnce(testing::Return(store::mocks::storeReadDocResp(json::Json {routerJson.c_str()})))
        .WillOnce(testing::Return(store::mocks::storeReadDocResp(json::Json {testerJson.c_str()})));
    EXPECT_CALL(*m_mockStore, upsertDoc(testing::_, testing::_))
        .WillRepeatedly(testing::Return(store::mocks::storeOk()));

    // Builder will be called to build the policy for the tester entry
    auto mockPolicy = std::make_shared<builder::mocks::MockPolicy>();
    auto mockController = std::make_shared<bk::mocks::MockController>();
    std::unordered_set<base::Name> fakeAssets {base::Name("decoder/test/0")};
    const std::string hash = "hashT";

    EXPECT_CALL(*m_mockBuilder, buildPolicy(testing::_, testing::_))
        .WillRepeatedly(testing::Return(mockPolicy));
    EXPECT_CALL(*mockPolicy, assets()).WillRepeatedly(testing::ReturnRefOfCopy(fakeAssets));
    EXPECT_CALL(*mockPolicy, expression()).WillRepeatedly(testing::ReturnRefOfCopy(base::Expression {}));
    EXPECT_CALL(*mockPolicy, hash()).WillRepeatedly(testing::ReturnRefOfCopy(hash));
    EXPECT_CALL(*m_mockControllerMaker, create(testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Return(mockController));
    EXPECT_CALL(*mockController, stop()).Times(testing::AnyNumber());

    auto opt = makeValidOptions(1);
    ASSERT_NO_THROW(
        {
            Orchestrator orch(opt);
            orch.stop();
        });
}

TEST_F(OrchestratorConstructorTest, ConstructorWithBothEntries)
{
    // Both router and tester entries with lastUse for tester
    const std::string routerJson =
        R"([{"name":"route1","namespace":"policy","priority":10}])";
    const std::string testerJson =
        R"([{"name":"test1","namespace":"policy","lifetime":3600,"lastUse":99999}])";

    EXPECT_CALL(*m_mockStore, readDoc(testing::_))
        .WillOnce(testing::Return(store::mocks::storeReadDocResp(json::Json {routerJson.c_str()})))
        .WillOnce(testing::Return(store::mocks::storeReadDocResp(json::Json {testerJson.c_str()})));
    EXPECT_CALL(*m_mockStore, upsertDoc(testing::_, testing::_))
        .WillRepeatedly(testing::Return(store::mocks::storeOk()));

    auto mockPolicy = std::make_shared<builder::mocks::MockPolicy>();
    auto mockController = std::make_shared<bk::mocks::MockController>();
    std::unordered_set<base::Name> fakeAssets {base::Name("decoder/test/0")};
    const std::string hash = "hashBoth";

    EXPECT_CALL(*m_mockBuilder, buildPolicy(testing::_, testing::_))
        .WillRepeatedly(testing::Return(mockPolicy));
    EXPECT_CALL(*mockPolicy, assets()).WillRepeatedly(testing::ReturnRefOfCopy(fakeAssets));
    EXPECT_CALL(*mockPolicy, expression()).WillRepeatedly(testing::ReturnRefOfCopy(base::Expression {}));
    EXPECT_CALL(*mockPolicy, hash()).WillRepeatedly(testing::ReturnRefOfCopy(hash));
    EXPECT_CALL(*m_mockControllerMaker, create(testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Return(mockController));
    EXPECT_CALL(*mockController, stop()).Times(testing::AnyNumber());

    auto opt = makeValidOptions(1);
    ASSERT_NO_THROW(
        {
            Orchestrator orch(opt);
            orch.stop();
        });
}

/**************************************************************************
 * dumpTesters / dumpRouters tests (via OrchestratorToTest)
 *************************************************************************/

TEST_F(OrchestratorTest, dumpTesters)
{
    auto testerMock = std::make_shared<MockTester>();
    auto itesterMock = std::static_pointer_cast<router::ITester>(testerMock);

    EXPECT_CALL(*m_orchestrator->m_testerWorkerMock, get()).WillOnce(testing::Return(itesterMock));
    EXPECT_CALL(*testerMock, getEntries()).WillOnce(testing::Return(std::list<test::Entry> {}));
    EXPECT_CALL(*(m_orchestrator->m_mockstore), upsertDoc(testing::_, testing::_))
        .WillOnce(::testing::Return(store::mocks::storeOk()));

    ASSERT_NO_THROW(m_orchestrator->callDumpTesters());
}

TEST_F(OrchestratorTest, dumpRouters)
{
    auto routerMock = std::make_shared<MockRouter>();
    auto irouterMock = std::static_pointer_cast<router::IRouter>(routerMock);

    EXPECT_CALL(*m_orchestrator->m_routerMocks.front(), get()).WillOnce(testing::Return(irouterMock));
    EXPECT_CALL(*routerMock, getEntries()).WillOnce(testing::Return(std::list<prod::Entry> {}));
    EXPECT_CALL(*(m_orchestrator->m_mockstore), upsertDoc(testing::_, testing::_))
        .WillOnce(::testing::Return(store::mocks::storeOk()));

    ASSERT_NO_THROW(m_orchestrator->callDumpRouters());
}

TEST_F(OrchestratorTest, dumpRoutersWhenShutdown)
{
    m_orchestrator->setShutdown(true);
    // Should return immediately without calling any worker
    ASSERT_NO_THROW(m_orchestrator->callDumpRouters());
}


/**************************************************************************
 * Worker pool expansion tests
 *************************************************************************/

class ExpansionTest : public ::testing::Test
{
protected:
    std::unique_ptr<OrchestratorToTest> m_orch;

    void SetUp() override { m_orch = std::make_unique<OrchestratorToTest>(); }
    void TearDown() override { m_orch.reset(); }
};

TEST_F(ExpansionTest, expandsPoolToTarget)
{
    m_orch->setTargetWorkerCount(3);
    m_orch->addWorkerToPool();

    for (int i = 0; i < 2; ++i)
    {
        m_orch->m_factoryQueue.push_back(
            []()
            {
                auto w = makeMockWorkerOk();
                EXPECT_CALL(*w, start()).Times(1);
                return w;
            });
    }

    m_orch->expandWorkerPool();

    EXPECT_EQ(m_orch->workerPoolSize(), 3U);
}

TEST_F(ExpansionTest, noopWhenAlreadyAtTarget)
{
    m_orch->setTargetWorkerCount(2);
    m_orch->addWorkerToPool();
    m_orch->addWorkerToPool();

    m_orch->expandWorkerPool();

    EXPECT_EQ(m_orch->workerPoolSize(), 2U);
}

TEST_F(ExpansionTest, buildFailurePreservesPool)
{
    const std::list<prod::Entry> entries {prod::EntryPost {"route-x", G_NAMESPACE_ALT, 10}};

    m_orch->setTargetWorkerCount(3);
    m_orch->addWorkerToPool(entries);
    m_orch->m_factoryQueue.push_back([]() { return makeMockWorkerFailBuild(); });

    m_orch->expandWorkerPool();

    EXPECT_EQ(m_orch->workerPoolSize(), 1U);
}

TEST_F(ExpansionTest, allWorkersReceiveConsistentEntries)
{
    const std::list<prod::Entry> sharedEntries {
        prod::EntryPost {"route-a", G_NAMESPACE_ALT, 10},
        prod::EntryPost {"route-b", G_NAMESPACE_ALT, 20},
    };

    m_orch->setTargetWorkerCount(3);
    m_orch->addWorkerToPool(sharedEntries);

    std::vector<std::vector<std::string>> capturedNames(2);

    for (std::size_t idx = 0; idx < 2; ++idx)
    {
        m_orch->m_factoryQueue.push_back(
            [&, idx]()
            {
                auto w = std::make_shared<testing::NiceMock<MockRouterWorker>>();
                auto r = std::make_shared<testing::NiceMock<MockRouter>>();
                ON_CALL(*w, get()).WillByDefault(testing::Return(std::static_pointer_cast<IRouter>(r)));
                ON_CALL(*r, addEntry(testing::_, testing::_))
                    .WillByDefault(
                        [&capturedNames, idx](const prod::EntryPost& e, bool) -> base::OptError
                        {
                            capturedNames[idx].push_back(e.name());
                            return std::nullopt;
                        });
                ON_CALL(*r, enableEntry(testing::_)).WillByDefault(testing::Return(std::nullopt));
                return w;
            });
    }

    m_orch->expandWorkerPool();

    ASSERT_EQ(m_orch->workerPoolSize(), 3U);
    for (std::size_t idx = 0; idx < 2; ++idx)
    {
        EXPECT_EQ(capturedNames[idx], (std::vector<std::string> {"route-a", "route-b"}))
            << "Worker " << idx << " has inconsistent entries";
    }
}

TEST_F(ExpansionTest, shutdownPreventsExpansion)
{
    m_orch->setTargetWorkerCount(3);
    m_orch->addWorkerToPool();
    m_orch->simulateShutdown();

    m_orch->expandWorkerPool();

    EXPECT_EQ(m_orch->workerPoolSize(), 1U);
}

TEST_F(ExpansionTest, enableEntryFailureStillPublishesWorker)
{
    m_orch->setTargetWorkerCount(2);
    m_orch->addWorkerToPool({prod::EntryPost {"route-a", G_NAMESPACE_ALT, 10}});

    m_orch->m_factoryQueue.push_back(
        []()
        {
            auto w = std::make_shared<testing::NiceMock<MockRouterWorker>>();
            auto r = std::make_shared<testing::NiceMock<MockRouter>>();
            ON_CALL(*w, get()).WillByDefault(testing::Return(std::static_pointer_cast<IRouter>(r)));
            ON_CALL(*r, addEntry(testing::_, testing::_)).WillByDefault(testing::Return(std::nullopt));
            ON_CALL(*r, enableEntry(testing::_)).WillByDefault(testing::Return(base::Error {"enable failed"}));
            return w;
        });

    m_orch->expandWorkerPool();

    EXPECT_EQ(m_orch->workerPoolSize(), 2U);
}

TEST_F(ExpansionTest, startThrowingPreservesPool)
{
    m_orch->setTargetWorkerCount(2);
    m_orch->addWorkerToPool();

    m_orch->m_factoryQueue.push_back(
        []()
        {
            auto w = makeMockWorkerOk();
            ON_CALL(*w, start()).WillByDefault(testing::Throw(std::runtime_error {"start failed"}));
            return w;
        });

    ASSERT_NO_THROW(m_orch->expandWorkerPool());

    EXPECT_EQ(m_orch->workerPoolSize(), 1U);
}

TEST_F(ExpansionTest, emptyPoolNoopWithWarning)
{
    m_orch->setTargetWorkerCount(3);
    // No workers added — m_routerWorkers is empty

    ASSERT_NO_THROW(m_orch->expandWorkerPool());

    EXPECT_EQ(m_orch->workerPoolSize(), 0U);
}

TEST_F(ExpansionTest, shutdownDuringBuildPreventsPublish)
{
    m_orch->setTargetWorkerCount(2);
    m_orch->addWorkerToPool();

    m_orch->m_factoryQueue.push_back(
        [this]()
        {
            // Simulate shutdown completing while the worker is being built
            m_orch->simulateShutdown();
            return makeMockWorkerOk();
        });

    m_orch->expandWorkerPool();

    EXPECT_EQ(m_orch->workerPoolSize(), 1U);
}
