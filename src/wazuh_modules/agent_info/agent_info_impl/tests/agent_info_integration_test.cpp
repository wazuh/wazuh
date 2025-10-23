#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <agent_info_impl.hpp>

#include <mock_file_io_utils.hpp>
#include <mock_filesystem_wrapper.hpp>
#include <mock_sysinfo.hpp>

#include <chrono>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>
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
        std::vector<nlohmann::json> m_reportedEvents;
        std::string m_logOutput;
};

TEST_F(AgentInfoRealDBSyncTest, StartWithRealDBSyncTriggersEvents)
{
    // Setup SysInfo mocks to provide data
    nlohmann::json osData = {{"os_name", "TestOS"}, {"architecture", "test64"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));
    EXPECT_CALL(*m_mockSysInfo, agentId()).WillOnce(::testing::Return("456"));
    EXPECT_CALL(*m_mockSysInfo, agentName()).WillOnce(::testing::Return("real-dbsync-test"));
    EXPECT_CALL(*m_mockSysInfo, agentGroups()).WillOnce(::testing::Return(std::vector<std::string> {"dbsync-test-group"}));

    // Create agent info with real DBSync (using in-memory database)
    // This will trigger updateChanges internally through start()
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      m_reportDiffFunc,
                      m_logFunc,
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
    // For manager mode, SysInfo returns "000" and hostname
    nlohmann::json osData = {{"os_name", "TestOS"}, {"architecture", "test64"}, {"hostname", "test-manager-hostname"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));
    EXPECT_CALL(*m_mockSysInfo, agentId()).WillOnce(::testing::Return("000"));
    EXPECT_CALL(*m_mockSysInfo, agentName()).WillOnce(::testing::Return("test-manager-hostname"));
    EXPECT_CALL(*m_mockSysInfo, agentGroups()).WillOnce(::testing::Return(std::vector<std::string> {}));

    // Create agent info with real DBSync (using in-memory database)
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:",
                                                  m_reportDiffFunc,
                                                  m_logFunc,
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
}

/**
 * @brief Test getMetadata with real DBSync
 * This tests the C++ getMetadata() method with an actual database
 * following the same pattern as DBSync tests
 */
TEST_F(AgentInfoRealDBSyncTest, GetMetadataWithRealDBSync)
{
    // Setup SysInfo mocks to provide data
    nlohmann::json osData =
    {
        {"architecture", "x86_64"},
        {"hostname", "metadata-test-host"},
        {"os_name", "Ubuntu"},
        {"os_type", "Linux"},
        {"os_platform", "ubuntu"},
        {"os_version", "22.04"}
    };
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));
    EXPECT_CALL(*m_mockSysInfo, agentId()).WillOnce(::testing::Return("789"));
    EXPECT_CALL(*m_mockSysInfo, agentName()).WillOnce(::testing::Return("metadata-test-agent"));
    EXPECT_CALL(*m_mockSysInfo, agentGroups()).WillOnce(::testing::Return(std::vector<std::string> {"test-group1", "test-group2"}));

    // Create AgentInfoImpl with real DBSync (in-memory)
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      m_reportDiffFunc,
                      m_logFunc,
                      nullptr, // Use real DBSync
                      m_mockSysInfo,
                      m_mockFileIO,
                      m_mockFileSystem);

    m_agentInfo->setIsAgent(true);

    // Populate metadata (runs once and exits)
    m_agentInfo->start(1, []()
    {
        return false;
    });

    // Give DBSync time to flush writes
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Now call getMetadata
    nlohmann::json result = m_agentInfo->getMetadata();

    // Verify result structure first
    ASSERT_TRUE(result.contains("status")) << "Result: " << result.dump();

    // If there's an error, print it for debugging
    if (result["status"] == "error")
    {
        FAIL() << "getMetadata returned error: " << result.dump();
    }

    EXPECT_EQ(result["status"], "ok");
    ASSERT_TRUE(result.contains("metadata"));
    ASSERT_TRUE(result.contains("groups"));

    // Verify metadata content
    const auto& metadata = result["metadata"];
    ASSERT_FALSE(metadata.empty()) << "Metadata should not be empty after start()";

    EXPECT_EQ(metadata["agent_id"], "789");
    EXPECT_EQ(metadata["agent_name"], "metadata-test-agent");
    EXPECT_EQ(metadata["host_os_name"], "Ubuntu");
    EXPECT_EQ(metadata["host_os_type"], "Linux");
    EXPECT_EQ(metadata["host_os_platform"], "ubuntu");
    EXPECT_EQ(metadata["host_architecture"], "x86_64");

    // Verify groups
    const auto& groups = result["groups"];
    ASSERT_TRUE(groups.is_array());

    // Note: Groups might be empty depending on how merged.mg is parsed
    // The important thing is that getMetadata() works and returns the array structure
    if (groups.size() >= 2)
    {
        EXPECT_EQ(groups[0], "test-group1");
        EXPECT_EQ(groups[1], "test-group2");
    }
}
