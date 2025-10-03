#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <agent_info_impl.hpp>

#include "logging_helper.hpp"
#include <dbsync.hpp>
#include <mock_dbsync.hpp>
#include <mock_sysinfo.hpp>

#include <chrono>
#include <memory>
#include <string>
#include <thread>

class AgentInfoImplTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            m_logOutput.clear();

            // Set up the logging callback to avoid "Log callback not set" errors
            LoggingHelper::setLogCallback([this](const modules_log_level_t /* level */, const char* log)
            {
                m_logOutput += log;
                m_logOutput += "\n";
            });

            m_mockDBSync = std::make_shared<MockDBSync>();
            m_agentInfo = std::make_shared<AgentInfoImpl>("test_path", m_mockDBSync);
        }

        void TearDown() override
        {
            // Explicitly reset to ensure proper cleanup order
            m_agentInfo.reset();
            m_mockDBSync.reset();
        }

        std::shared_ptr<IDBSync> m_mockDBSync = nullptr;
        std::shared_ptr<AgentInfoImpl> m_agentInfo = nullptr;
        std::string m_logOutput;
};

TEST_F(AgentInfoImplTest, ConstructorInitializesSuccessfully)
{
    EXPECT_NE(m_agentInfo, nullptr);
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("AgentInfo initialized"));
}

TEST_F(AgentInfoImplTest, StartMethodLogsCorrectly)
{
    m_logOutput.clear();
    m_agentInfo->start();
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("AgentInfo module started"));
}

TEST_F(AgentInfoImplTest, StopMethodLogsCorrectly)
{
    m_logOutput.clear();
    m_agentInfo->stop();
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("AgentInfo module stopped"));
}

TEST_F(AgentInfoImplTest, DestructorCallsStop)
{
    m_logOutput.clear();
    m_agentInfo.reset();
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("AgentInfo module stopped"));
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("AgentInfo destroyed"));
}

// Test removed - creating real DBSync instance without proper dependencies
// could cause issues in test environment

TEST_F(AgentInfoImplTest, StartAndStopSequence)
{
    m_logOutput.clear();
    m_agentInfo->start();
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("AgentInfo module started"));

    m_logOutput.clear();
    m_agentInfo->stop();
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("AgentInfo module stopped"));
}

TEST_F(AgentInfoImplTest, MultipleStartCallsSucceed)
{
    m_agentInfo->start();
    m_agentInfo->start();
    // Should not crash or throw
    SUCCEED();
}

TEST_F(AgentInfoImplTest, MultipleStopCallsSucceed)
{
    m_logOutput.clear();
    m_agentInfo->stop();

    // First stop should log
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("AgentInfo module stopped"));

    m_logOutput.clear();
    m_agentInfo->stop();

    // Second stop should not log (idempotent)
    EXPECT_EQ(m_logOutput, "");
}

TEST_F(AgentInfoImplTest, StopCalledInDestructorIsIdempotent)
{
    m_logOutput.clear();

    // Explicitly call stop
    m_agentInfo->stop();
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("AgentInfo module stopped"));

    m_logOutput.clear();

    // Destructor will call stop again, but should be idempotent
    m_agentInfo.reset();

    // Should only see destructor message, not another stop message
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("AgentInfo destroyed"));
    EXPECT_THAT(m_logOutput, ::testing::Not(::testing::HasSubstr("AgentInfo module stopped")));
}

TEST_F(AgentInfoImplTest, ConstructorWithCustomSysInfoSucceeds)
{
    auto mockSysInfo = std::make_shared<MockSysInfo>();
    m_logOutput.clear();

    // Create AgentInfoImpl with custom SysInfo
    auto agentInfo = std::make_shared<AgentInfoImpl>("test_path", m_mockDBSync, mockSysInfo);

    EXPECT_NE(agentInfo, nullptr);
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("AgentInfo initialized"));
}

TEST_F(AgentInfoImplTest, ConstructorWithDefaultDependenciesSucceeds)
{
    m_logOutput.clear();

    // Create AgentInfoImpl without passing dbSync or sysInfo (creates defaults)
    // Using in-memory database to avoid file I/O in tests
    auto agentInfo = std::make_shared<AgentInfoImpl>(":memory:");

    EXPECT_NE(agentInfo, nullptr);
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("AgentInfo initialized"));
}
