#include <gtest/gtest.h>

#include <store/mockStore.hpp>

#include <router/orchestrator.hpp>

#include "mockRouter.hpp"
#include "mockTester.hpp"
#include "mockWorker.hpp"

using namespace router;

/// @brief Orchestrator to test, helper class
class OrchestratorToTest : public router::Orchestrator
{
public:
    std::shared_ptr<store::mocks::MockStore> m_mockstore;
    std::list<std::shared_ptr<MockWorker>> m_mocks;

    OrchestratorToTest()
        : router::Orchestrator()
    {
        m_testTimeout = 1000;
        m_mockstore = std::make_shared<store::mocks::MockStore>();
        m_wStore = m_mockstore;
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
    }
};


TEST_F(OrchestratorTest, start) {

    m_orchestrator->forEachWorkerMock([](auto mockWorker) {
        EXPECT_CALL(*mockWorker, start()).Times(1);
    });

    ASSERT_NO_THROW(m_orchestrator->start());
}


TEST_F(OrchestratorTest, stop)
{

    m_orchestrator->expectDumpTester();
    m_orchestrator->forEachWorkerMock([](auto mockWorker) {
        EXPECT_CALL(*mockWorker, stop()).Times(1);
    });


    ASSERT_NO_THROW(m_orchestrator->stop());
}