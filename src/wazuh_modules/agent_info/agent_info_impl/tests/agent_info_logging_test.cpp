#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <agent_info_impl.hpp>

#include <dbsync.hpp>
#include <mock_dbsync.hpp>
#include <mock_file_io_utils.hpp>
#include <mock_filesystem_wrapper.hpp>
#include <mock_sysinfo.hpp>

#include <filesystem>
#include <memory>
#include <string>
#include <utility>
#include <vector>

/**
 * @brief Test fixture for AgentInfoImpl logging functionality
 *
 * This test fixture focuses on testing the logging mechanisms:
 * - Verification that log functions are called with correct levels
 * - Testing different log levels (INFO, ERROR, DEBUG_VERBOSE)
 * - Ensuring proper logging during metadata population
 * - Error logging during DBSync operations
 * - Event processing debug logging
 * - Exception handling and error logging
 */
class AgentInfoLoggingTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            m_logMessages.clear();

            m_mockDBSync = std::make_shared<MockDBSync>();
            m_mockSysInfo = std::make_shared<MockSysInfo>();
            m_mockFileIO = std::make_shared<MockFileIOUtils>();
            m_mockFileSystem = std::make_shared<MockFileSystemWrapper>();

            // Configure expected calls to avoid warnings
            EXPECT_CALL(*m_mockDBSync, handle())
            .WillRepeatedly(::testing::Return(nullptr));

            // Configure selectRows call for loadSyncFlags()
            EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
            .WillRepeatedly(::testing::Return());

            m_logFunc = [this](modules_log_level_t level, const std::string & msg)
            {
                m_logMessages.push_back({level, msg});
            };

            // Create a mock query module function
            m_queryModuleFunc = [](const std::string& /* module_name */, const std::string& /* query */, char** response) -> int
            {
                // Mock implementation that returns success
                if (response)
                {
                    *response = nullptr;
                }

                return 0;
            };
        }

        void TearDown() override
        {
            m_agentInfo.reset();
            m_mockDBSync.reset();
            m_mockSysInfo.reset();
            m_mockFileIO.reset();
            m_mockFileSystem.reset();
        }

        std::shared_ptr<MockDBSync> m_mockDBSync;
        std::shared_ptr<MockSysInfo> m_mockSysInfo;
        std::shared_ptr<MockFileIOUtils> m_mockFileIO;
        std::shared_ptr<MockFileSystemWrapper> m_mockFileSystem;
        std::shared_ptr<AgentInfoImpl> m_agentInfo;
        std::function<void(modules_log_level_t, const std::string&)> m_logFunc;
        std::function<int(const std::string&, const std::string&, char**)> m_queryModuleFunc;
        std::vector<std::pair<modules_log_level_t, std::string>> m_logMessages;
        std::string m_logOutput;
};

TEST_F(AgentInfoLoggingTest, PopulateMetadataUsesLogFunction)
{
    // Setup: Mock client.keys and merged.mg
    EXPECT_CALL(*m_mockFileSystem, exists(::testing::_))
    .WillOnce(::testing::Return(true))
    .WillOnce(::testing::Return(true));

    EXPECT_CALL(*m_mockFileIO, readLineByLine(::testing::_, ::testing::_))
    .WillOnce(::testing::Invoke([](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        callback("001 test-agent 192.168.1.1 key");
    }))
    .WillOnce(::testing::Invoke([](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        callback("<!-- Source file: test-group/agent.conf -->");
    }));

    nlohmann::json osData = {{"os_name", "Ubuntu"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    EXPECT_CALL(*m_mockDBSync, handle()).WillRepeatedly(::testing::Return(nullptr));

    // Create agent info with m_logFunc
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      "test_path",
                      nullptr,
                      m_logFunc,  // Use log function
                      m_queryModuleFunc,
                      m_mockDBSync,
                      m_mockSysInfo,
                      m_mockFileIO,
                      m_mockFileSystem
                  );

    m_agentInfo->start(1, 86400, []()
    {
        return false;
    });

    // Verify log function was called
    bool foundMetadataLog = false;
    bool foundGroupsLog = false;

    for (const auto& [level, msg] : m_logMessages)
    {
        if (msg.find("Agent metadata populated successfully") != std::string::npos)
        {
            foundMetadataLog = true;
            EXPECT_EQ(level, LOG_DEBUG);
        }

        if (msg.find("Agent groups populated successfully") != std::string::npos)
        {
            foundGroupsLog = true;
            EXPECT_EQ(level, LOG_DEBUG);
        }
    }

    EXPECT_TRUE(foundMetadataLog);
    EXPECT_TRUE(foundGroupsLog);
}

TEST_F(AgentInfoLoggingTest, UpdateChangesErrorUsesLogFunction)
{
    // Create a mock that will cause updateChanges to fail
    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Throw(std::runtime_error("DBSync error")));

    EXPECT_CALL(*m_mockFileSystem, exists(::testing::_))
    .WillRepeatedly(::testing::Return(false));

    EXPECT_CALL(*m_mockSysInfo, os())
    .WillRepeatedly(::testing::Return(nlohmann::json()));

    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      "test_path",
                      nullptr,
                      m_logFunc,
                      m_queryModuleFunc,
                      m_mockDBSync,
                      m_mockSysInfo,
                      m_mockFileIO,
                      m_mockFileSystem
                  );

    // Start will trigger updateChanges which will fail
    m_agentInfo->start(1, 86400, []()
    {
        return false;
    });

    // Verify error was logged via m_logFunction
    bool foundError = false;

    for (const auto& [level, msg] : m_logMessages)
    {
        if (msg.find("Error updating changes") != std::string::npos)
        {
            foundError = true;
            EXPECT_EQ(level, LOG_ERROR);
        }
    }

    EXPECT_TRUE(foundError);
}

TEST_F(AgentInfoLoggingTest, ProcessEventDebugUsesLogFunction)
{
    auto reportFunc = [](const std::string& /* event */) {};

    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      reportFunc,
                      m_logFunc,
                      m_queryModuleFunc,
                      m_mockDBSync
                  );

    nlohmann::json testData;
    testData["agent_id"] = "001";
    testData["agent_name"] = "test";

    m_agentInfo->processEvent(INSERTED, testData, "agent_metadata");

    // Verify debug message was logged
    bool foundDebug = false;

    for (const auto& [level, msg] : m_logMessages)
    {
        if (msg.find("Event reported for table") != std::string::npos)
        {
            foundDebug = true;
            EXPECT_EQ(level, LOG_DEBUG_VERBOSE);
        }
    }

    EXPECT_TRUE(foundDebug);
}

TEST_F(AgentInfoLoggingTest, ProcessEventErrorUsesLogFunction)
{
    // Create a callback that throws
    auto throwingReportFunc = [](const std::string& /* event */)
    {
        throw std::runtime_error("Report callback error");
    };

    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      throwingReportFunc,
                      m_logFunc,
                      m_queryModuleFunc,
                      m_mockDBSync
                  );

    nlohmann::json testData;
    testData["agent_id"] = "001";

    m_agentInfo->processEvent(INSERTED, testData, "agent_metadata");

    // Verify error was logged
    bool foundError = false;

    for (const auto& [level, msg] : m_logMessages)
    {
        if (msg.find("Error processing event") != std::string::npos)
        {
            foundError = true;
            EXPECT_EQ(level, LOG_ERROR);
        }
    }

    EXPECT_TRUE(foundError);
}
