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
#include <mutex>
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
        void clearLogOutput()
        {
            std::lock_guard<std::mutex> lock(m_logMutex);
            m_logOutput.clear();
        }

        std::string getLogOutput() const
        {
            std::lock_guard<std::mutex> lock(m_logMutex);
            return m_logOutput;
        }

        void SetUp() override
        {
            clearLogOutput();

            // Create the logging function to capture log messages
            m_logFunction = [this](const modules_log_level_t /* level */, const std::string & log)
            {
                // Normalize line endings by removing carriage returns to avoid Windows compatibility issues
                std::string normalized = log;
                normalized.erase(std::remove(normalized.begin(), normalized.end(), '\r'), normalized.end());
                std::lock_guard<std::mutex> lock(m_logMutex);
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
        mutable std::mutex m_logMutex;
        std::string m_logOutput;
};

TEST_F(AgentInfoImplTest, ConstructorInitializesSuccessfully)
{
    EXPECT_NE(m_agentInfo, nullptr);
    EXPECT_THAT(getLogOutput(), ::testing::HasSubstr("AgentInfo initialized"));
}

TEST_F(AgentInfoImplTest, StartMethodLogsCorrectly)
{
    clearLogOutput();
    m_agentInfo->start(1, 86400, []()
    {
        return false;
    });
    EXPECT_THAT(getLogOutput(), ::testing::HasSubstr("AgentInfo module started"));
}

TEST_F(AgentInfoImplTest, StopMethodLogsCorrectly)
{
    clearLogOutput();
    m_agentInfo->stop();
    EXPECT_THAT(getLogOutput(), ::testing::HasSubstr("AgentInfo module stopped"));
}

TEST_F(AgentInfoImplTest, DestructorCallsStop)
{
    clearLogOutput();
    m_agentInfo.reset();
    EXPECT_THAT(getLogOutput(), ::testing::HasSubstr("AgentInfo module stopped"));
    EXPECT_THAT(getLogOutput(), ::testing::HasSubstr("AgentInfo destroyed"));
}

// Test removed - creating real DBSync instance without proper dependencies
// could cause issues in test environment

TEST_F(AgentInfoImplTest, StartAndStopSequence)
{
    clearLogOutput();
    m_agentInfo->start(1, 86400, []()
    {
        return false;
    });
    EXPECT_THAT(getLogOutput(), ::testing::HasSubstr("AgentInfo module started"));

    clearLogOutput();
    m_agentInfo->stop();
    EXPECT_THAT(getLogOutput(), ::testing::HasSubstr("AgentInfo module stopped"));
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
    clearLogOutput();
    m_agentInfo->stop();

    // First stop should log
    EXPECT_THAT(getLogOutput(), ::testing::HasSubstr("AgentInfo module stopped"));

    clearLogOutput();
    m_agentInfo->stop();

    // Second stop should not log (idempotent)
    EXPECT_EQ(getLogOutput(), "");
}

TEST_F(AgentInfoImplTest, StopCalledInDestructorIsIdempotent)
{
    clearLogOutput();

    // Explicitly call stop
    m_agentInfo->stop();
    EXPECT_THAT(getLogOutput(), ::testing::HasSubstr("AgentInfo module stopped"));

    clearLogOutput();

    // Destructor will call stop again, but should be idempotent
    m_agentInfo.reset();

    // Should only see destructor message, not another stop message
    EXPECT_THAT(getLogOutput(), ::testing::HasSubstr("AgentInfo destroyed"));
    EXPECT_THAT(getLogOutput(), ::testing::Not(::testing::HasSubstr("AgentInfo module stopped")));
}

TEST_F(AgentInfoImplTest, ConstructorWithCustomSysInfoSucceeds)
{
    auto mockSysInfo = std::make_shared<MockSysInfo>();
    clearLogOutput();

    // Create AgentInfoImpl with custom SysInfo
    auto agentInfo = std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_queryModuleFunction, m_mockDBSync, mockSysInfo);

    EXPECT_NE(agentInfo, nullptr);
    EXPECT_THAT(getLogOutput(), ::testing::HasSubstr("AgentInfo initialized"));
}

TEST_F(AgentInfoImplTest, ConstructorWithDefaultDependenciesSucceeds)
{
    clearLogOutput();

    // Create AgentInfoImpl without passing dbSync or sysInfo (creates defaults)
    // Using in-memory database to avoid file I/O in tests
    auto agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunction, m_queryModuleFunction);

    EXPECT_NE(agentInfo, nullptr);
    EXPECT_THAT(getLogOutput(), ::testing::HasSubstr("AgentInfo initialized"));
}

TEST_F(AgentInfoImplTest, StartWithIntervalTriggersWaitCondition)
{
    clearLogOutput();

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
    // NOTE: start() has a 5-second initial delay, so we need to wait for that plus the iteration time
    std::thread stopThread([this, &startedFirstIteration]()
    {
        // Wait for the first iteration to complete (accounting for 5-second initial delay)
        while (!startedFirstIteration.load(std::memory_order_acquire))
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
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
    EXPECT_THAT(getLogOutput(), ::testing::HasSubstr("AgentInfo module started"));
    EXPECT_THAT(getLogOutput(), ::testing::HasSubstr("AgentInfo module stopped"));
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

// Regression test for the clean-stop ordering fix (issues #37629 / #37714).
//
// stop() must not return until the run loop has exited, so that shared resources
// (the main DBSync connection and the sync-protocol SQLite connection) are only
// torn down once no other thread is using them.
//
// The run loop calls ISysInfo::os() near the top of populateAgentMetadata(). We
// hold it there for a fixed window so the loop is provably still active when
// stop() is called: stop() blocks for that window; before it, stop()
// returned immediately.
TEST_F(AgentInfoImplTest, StopWaitsForRunLoopToExit)
{
    constexpr auto HOLD = std::chrono::milliseconds(300);

    auto mockSysInfo = std::make_shared<MockSysInfo>();
    std::atomic<bool> loopInBody{false};

    EXPECT_CALL(*mockSysInfo, os())
    .WillRepeatedly(::testing::Invoke([&]() -> nlohmann::json
    {
        loopInBody.store(true, std::memory_order_release);
        std::this_thread::sleep_for(HOLD);
        return nlohmann::json::object();
    }));

    auto agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_queryModuleFunction, m_mockDBSync, mockSysInfo);

    // start() blocks until stopped, so it runs on its own thread. It has a fixed
    // 5s initial delay before the first iteration.
    std::thread loopThread([&]()
    {
        agentInfo->start(3600, 86400, []()
        {
            return true;
        });
    });

    while (!loopInBody.load(std::memory_order_acquire))
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    const auto start = std::chrono::steady_clock::now();
    agentInfo->stop();
    const auto elapsed = std::chrono::steady_clock::now() - start;

    // AFTER the fix stop() blocks until the in-flight run-loop iteration finishes;
    // BEFORE the fix it returned immediately (< 1 ms).
    EXPECT_GE(elapsed, HOLD / 2) << "stop() returned before the run loop had exited";

    loopThread.join();
}

// After stop() tears down the sync protocol, the asynchronous response path
// (parseResponseBuffer, called on the dispatch thread) must fail gracefully
// instead of dereferencing the freed sync protocol.
TEST_F(AgentInfoImplTest, ParseResponseBufferAfterStopIsSafe)
{
    // Initialize a real (in-memory, no DB file) sync protocol so that stop()
    // genuinely destroys it and the call below exercises the m_syncProtocolMutex
    // guard, not the trivial "was never initialized" path.
    m_agentInfo->initSyncProtocol("agent_info");

    const uint8_t data[] = {0x01, 0x02, 0x03};

    // stop() destroys the sync protocol under m_syncProtocolMutex.
    m_agentInfo->stop();

    // The now-torn-down protocol must be rejected safely (no use-after-free).
    clearLogOutput();
    EXPECT_FALSE(m_agentInfo->parseResponseBuffer(data, sizeof(data)));
    EXPECT_THAT(getLogOutput(), ::testing::HasSubstr("Sync protocol not initialized"));
}
