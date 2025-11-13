#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <agent_info_impl.hpp>

#include <dbsync.hpp>
#include <mock_dbsync.hpp>
#include <mock_sysinfo.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <thread>

/**
 * @brief Test fixture for basic AgentInfoImpl functionality
 *
 * This test fixture covers the fundamental operations of the AgentInfoImpl class:
 * - Constructor initialization with various parameter combinations
 * - Start/stop lifecycle management
 * - Proper cleanup and resource management
 * - Basic logging functionality during lifecycle operations
 */
class AgentInfoImplTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            m_logOutput.clear();

            // Create the logging function to capture log messages
            m_logFunction = [this](const modules_log_level_t /* level */, const std::string & log)
            {
                // Normalize line endings by removing carriage returns to avoid Windows compatibility issues
                std::string normalized = log;
                normalized.erase(std::remove(normalized.begin(), normalized.end(), '\r'), normalized.end());
                m_logOutput += normalized;
                m_logOutput += "\n";
            };

            // Create a mock query module function
            m_queryModuleFunction = [](const std::string& /* module_name */, const std::string& /* query */, char** response) -> int
            {
                // Mock implementation that returns success
                if (response)
                {
                    *response = nullptr;
                }

                return 0;
            };

            m_mockDBSync = std::make_shared<MockDBSync>();

            // Configure expected calls to avoid warnings
            EXPECT_CALL(*m_mockDBSync, handle())
            .WillRepeatedly(::testing::Return(nullptr));

            // Configure selectRows call for loadSyncFlags()
            EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
            .WillRepeatedly(::testing::Return());

            m_agentInfo = std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_queryModuleFunction, m_mockDBSync);
        }

        void TearDown() override
        {
            // Explicitly reset to ensure proper cleanup order
            m_agentInfo.reset();
            m_mockDBSync.reset();
        }

        std::shared_ptr<MockDBSync> m_mockDBSync = nullptr;
        std::shared_ptr<AgentInfoImpl> m_agentInfo = nullptr;
        std::function<void(const modules_log_level_t, const std::string&)> m_logFunction;
        std::function<int(const std::string&, const std::string&, char**)> m_queryModuleFunction;
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
    m_agentInfo->start(1, 86400, []()
    {
        return false;
    });
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
    m_agentInfo->start(1, 86400, []()
    {
        return false;
    });
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("AgentInfo module started"));

    m_logOutput.clear();
    m_agentInfo->stop();
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("AgentInfo module stopped"));
}

TEST_F(AgentInfoImplTest, MultipleStartCallsSucceed)
{
    m_agentInfo->start(1, 86400, []()
    {
        return false;
    });
    m_agentInfo->start(1, 86400, []()
    {
        return false;
    });
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
    auto agentInfo = std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_queryModuleFunction, m_mockDBSync, mockSysInfo);

    EXPECT_NE(agentInfo, nullptr);
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("AgentInfo initialized"));
}

TEST_F(AgentInfoImplTest, ConstructorWithDefaultDependenciesSucceeds)
{
    m_logOutput.clear();

    // Create AgentInfoImpl without passing dbSync or sysInfo (creates defaults)
    // Using in-memory database to avoid file I/O in tests
    auto agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunction, m_queryModuleFunction);

    EXPECT_NE(agentInfo, nullptr);
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("AgentInfo initialized"));
}

TEST_F(AgentInfoImplTest, StartWithIntervalTriggersWaitCondition)
{
    m_logOutput.clear();

    // Mock handle() to return nullptr - updateChanges will catch exceptions
    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    // Mock selectRows to invoke callback with default values
    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Invoke([](const nlohmann::json& /* query */, std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        nlohmann::json data;
        data["should_sync_metadata"] = 0;
        data["should_sync_groups"] = 0;
        data["last_metadata_integrity"] = 0;
        data["last_groups_integrity"] = 0;
        callback(SELECTED, data);
    }));

    // Use atomic flag to ensure thread synchronization
    std::atomic<bool> startedFirstIteration{false};

    // Use a thread to stop the agent after the first iteration completes
    std::thread stopThread([this, &startedFirstIteration]()
    {
        // Busy-wait for the first iteration to complete
        while (!startedFirstIteration.load(std::memory_order_acquire))
        {
            std::this_thread::yield();
        }

        // Add a small delay to ensure we're in the wait phase
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        m_agentInfo->stop();
    });

    // Start with a shouldContinue that keeps running until stopped
    int iterations = 0;
    m_agentInfo->start(1, 86400, [&iterations, &startedFirstIteration]()
    {
        iterations++;

        if (iterations == 1)
        {
            startedFirstIteration.store(true, std::memory_order_release);
        }

        return true;  // Keep running until stopped externally
    });

    stopThread.join();

    // Verify start was called
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("AgentInfo module started"));
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("AgentInfo module stopped"));
    EXPECT_GE(iterations, 1);  // At least one iteration should have completed
}

TEST_F(AgentInfoImplTest, ConstructorThrowsWhenLogFunctionIsNull)
{
    EXPECT_THROW(
    {
        AgentInfoImpl agentInfo("test_path", nullptr, nullptr, m_queryModuleFunction, m_mockDBSync);
    },
    std::invalid_argument);
}

TEST_F(AgentInfoImplTest, ConstructorThrowsWhenQueryModuleFunctionIsNull)
{
    EXPECT_THROW(
    {
        AgentInfoImpl agentInfo("test_path", nullptr, m_logFunction, nullptr, m_mockDBSync);
    },
    std::invalid_argument);
}
