#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <agent_info_impl.hpp>

#include <mock_file_io_utils.hpp>
#include <mock_filesystem_wrapper.hpp>
#include <mock_sysinfo.hpp>

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

/**
 * @brief Test fixture for AgentInfoImpl integration with real DBSync
 *
 * This test fixture focuses on testing the integration with a real DBSync instance:
 * - End-to-end testing with actual DBSync operations
 * - Testing updateChanges() method with real database
 * - Verifying event generation from actual database operations
 * - Integration testing of the complete workflow from metadata population to event reporting
 * - Using in-memory database to avoid file I/O dependencies
 */
class AgentInfoRealDBSyncTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            m_logOutput.clear();
            m_reportedEvents.clear();

            m_reportDiffFunc = [this](const std::string & event)
            {
                m_reportedEvents.push_back(nlohmann::json::parse(event));
            };

            m_logFunc = [this](modules_log_level_t /* level */, const std::string & msg)
            {
                m_logOutput += msg + "\n";
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

            m_mockFileSystem = std::make_shared<MockFileSystemWrapper>();
            m_mockFileIO = std::make_shared<MockFileIOUtils>();
            m_mockSysInfo = std::make_shared<MockSysInfo>();
        }

        void TearDown() override
        {
            m_agentInfo.reset();
            m_mockFileSystem.reset();
            m_mockFileIO.reset();
            m_mockSysInfo.reset();
        }

        std::shared_ptr<AgentInfoImpl> m_agentInfo;
        std::shared_ptr<MockFileSystemWrapper> m_mockFileSystem;
        std::shared_ptr<MockFileIOUtils> m_mockFileIO;
        std::shared_ptr<MockSysInfo> m_mockSysInfo;
        std::function<void(const std::string&)> m_reportDiffFunc;
        std::function<void(modules_log_level_t, const std::string&)> m_logFunc;
        std::function<int(const std::string&, const std::string&, char**)> m_queryModuleFunc;
        std::vector<nlohmann::json> m_reportedEvents;
        std::string m_logOutput;
};

TEST_F(AgentInfoRealDBSyncTest, StartWithRealDBSyncTriggersEvents)
{
    // Setup mocks to provide data
    EXPECT_CALL(*m_mockFileSystem, exists(::testing::_))
    .WillRepeatedly(::testing::Return(true));

    EXPECT_CALL(*m_mockFileIO, readLineByLine(::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Invoke([](const std::filesystem::path & path, const std::function<bool(const std::string&)>& callback)
    {
        // Check which file is being read and provide appropriate content
        std::string pathStr = path.string();

        if (pathStr.find("client.keys") != std::string::npos)
        {
            callback("456 real-dbsync-test 10.0.0.1 key");
        }
        else if (pathStr.find("merged.mg") != std::string::npos)
        {
            callback("#group: dbsync-test-group");
        }

        // For any other files, just return without calling callback (simulating empty file)
    }));

    nlohmann::json osData = {{"os_name", "TestOS"}, {"architecture", "test64"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    // Create agent info with real DBSync (using in-memory database)
    // This will trigger updateChanges internally through start()
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      m_reportDiffFunc,
                      m_logFunc,
                      m_queryModuleFunc,
                      nullptr,  // Use real DBSync
                      m_mockSysInfo,
                      m_mockFileIO,
                      m_mockFileSystem
                  );

    // Set to agent mode for this test
    m_agentInfo->setIsAgent(true);

    m_agentInfo->start(1, []()
    {
        return false;
    });

    // Verify events were reported (updateChanges was called internally)
    EXPECT_GE(m_reportedEvents.size(), static_cast<size_t>(1));

    // Find the agent_metadata event
    bool foundMetadataEvent = false;

    for (const auto& event : m_reportedEvents)
    {
        if (event["type"] == "agent_metadata")
        {
            foundMetadataEvent = true;
            EXPECT_EQ(event["module"], "agent_info");
            EXPECT_EQ(event["data"]["agent"]["id"], "456");
            break;
        }
    }

    EXPECT_TRUE(foundMetadataEvent);
}

TEST_F(AgentInfoRealDBSyncTest, StartInManagerModeUsesDefaultValues)
{
    // For manager mode, no client.keys or merged.mg reading needed
    // Only need sysinfo with hostname
    nlohmann::json osData = {{"os_name", "TestOS"}, {"architecture", "test64"}, {"hostname", "test-manager-hostname"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    // Create agent info with real DBSync (using in-memory database)
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:",
                                                  m_reportDiffFunc,
                                                  m_logFunc,
                                                  m_queryModuleFunc,
                                                  nullptr, // Use real DBSync
                                                  m_mockSysInfo,
                                                  m_mockFileIO,
                                                  m_mockFileSystem);

    // Set to manager mode (false)
    m_agentInfo->setIsAgent(false);

    m_agentInfo->start(1, []()
    {
        return false;
    });

    // Verify events were reported
    EXPECT_GE(m_reportedEvents.size(), static_cast<size_t>(1));

    // Find and verify the agent_metadata event
    bool foundMetadataEvent = false;
    bool foundGroupsEvent = false;

    for (const auto& event : m_reportedEvents)
    {
        if (event["type"] == "agent_metadata")
        {
            foundMetadataEvent = true;
            EXPECT_EQ(event["module"], "agent_info");
            EXPECT_EQ(event["data"]["agent"]["id"], "000");
            EXPECT_EQ(event["data"]["agent"]["name"], "test-manager-hostname");
            EXPECT_EQ(event["data"]["event"]["type"], "created");
        }
        else if (event["type"] == "agent_groups")
        {
            foundGroupsEvent = true;
            // In manager mode, groups should be deleted (empty)
            EXPECT_EQ(event["data"]["event"]["type"], "deleted");
        }
    }

    EXPECT_TRUE(foundMetadataEvent);
    // Groups event may or may not be present depending on initial state,
    // but if present it should be a delete event for empty groups
    (void)foundGroupsEvent; // May or may not be set depending on DB state
}
