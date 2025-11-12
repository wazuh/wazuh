#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <agent_info_impl.hpp>

#include <dbsync.hpp>
#include <mock_dbsync.hpp>
#include <mock_file_io_utils.hpp>
#include <mock_filesystem_wrapper.hpp>
#include <mock_sysinfo.hpp>

#include <memory>
#include <string>
#include <vector>

/**
 * @brief Test fixture for AgentInfoImpl event processing functionality
 *
 * This test fixture focuses on testing the DBSync event processing capabilities:
 * - Processing INSERTED, MODIFIED, and DELETED events
 * - Converting database events to ECS format
 * - Handling agent_metadata and agent_groups table events
 * - Event notification and callback mechanisms
 * - Error handling during event processing
 * - Changed fields tracking for MODIFIED events
 */
class AgentInfoEventProcessingTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            m_logOutput.clear();
            m_reportedEvents.clear();

            m_mockDBSync = std::make_shared<MockDBSync>();
            m_mockSysInfo = std::make_shared<MockSysInfo>();
            m_mockFileIO = std::make_shared<MockFileIOUtils>();
            m_mockFileSystem = std::make_shared<MockFileSystemWrapper>();

            // Configure expected calls to avoid warnings
            EXPECT_CALL(*m_mockDBSync, handle())
            .WillRepeatedly(::testing::Return(nullptr));

            // Set up callbacks to capture events
            m_reportDiffFunc = [this](const std::string & event)
            {
                m_reportedEvents.push_back(nlohmann::json::parse(event));
            };

            // Note: persist callback removed as per PR feedback - new implementation uses
            // synchronizeMetadataOrGroups instead of persistDifference with callbacks

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
        std::function<void(const std::string&)> m_reportDiffFunc;
        std::function<void(modules_log_level_t, const std::string&)> m_logFunc;
        std::function<int(const std::string&, const std::string&, char**)> m_queryModuleFunc;
        std::vector<nlohmann::json> m_reportedEvents;
        std::string m_logOutput;
};

TEST_F(AgentInfoEventProcessingTest, ProcessInsertedEvent)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      m_reportDiffFunc,
                      m_logFunc,
                      m_queryModuleFunc,
                      m_mockDBSync
                  );

    // Create test data for agent_metadata insertion
    nlohmann::json testData;
    testData["agent_id"] = "001";
    testData["agent_name"] = "test-agent";
    testData["agent_version"] = "4.5.0";
    testData["host_architecture"] = "x86_64";
    testData["host_hostname"] = "test-host";
    testData["host_os_name"] = "Ubuntu";
    testData["host_os_type"] = "Linux";
    testData["host_os_platform"] = "ubuntu";
    testData["host_os_version"] = "22.04";

    // Process the event
    m_agentInfo->processEvent(INSERTED, testData, "agent_metadata");

    // Verify report callback was invoked
    ASSERT_EQ(m_reportedEvents.size(), 1u);
    EXPECT_EQ(m_reportedEvents[0]["module"], "agent_info");
    EXPECT_EQ(m_reportedEvents[0]["type"], "agent_metadata");
    EXPECT_EQ(m_reportedEvents[0]["data"]["event"]["type"], "created");
    EXPECT_EQ(m_reportedEvents[0]["data"]["agent"]["id"], "001");
    EXPECT_EQ(m_reportedEvents[0]["data"]["agent"]["name"], "test-agent");

    // Note: Persist callback verification removed as per PR feedback
    // New implementation uses synchronizeMetadataOrGroups without persist callbacks
}

TEST_F(AgentInfoEventProcessingTest, ProcessModifiedEvent)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      m_reportDiffFunc,
                      m_logFunc,
                      m_queryModuleFunc,
                      m_mockDBSync
                  );

    // Create test data for agent_metadata modification
    nlohmann::json testData;
    testData["new"]["agent_id"] = "001";
    testData["new"]["agent_name"] = "updated-agent";
    testData["new"]["agent_version"] = "4.5.0";

    testData["old"]["agent_id"] = "001";
    testData["old"]["agent_name"] = "old-agent";
    testData["old"]["agent_version"] = "4.4.0";

    // Process the event
    m_agentInfo->processEvent(MODIFIED, testData, "agent_metadata");

    // Verify report callback was invoked
    ASSERT_EQ(m_reportedEvents.size(), 1u);
    EXPECT_EQ(m_reportedEvents[0]["data"]["event"]["type"], "modified");
    EXPECT_EQ(m_reportedEvents[0]["data"]["agent"]["name"], "updated-agent");

    // Verify changed_fields tracking
    EXPECT_TRUE(m_reportedEvents[0]["data"]["event"].contains("changed_fields"));
    auto changedFields = m_reportedEvents[0]["data"]["event"]["changed_fields"];
    EXPECT_FALSE(changedFields.empty());

    // Note: Persist callback verification removed as per PR feedback
}

TEST_F(AgentInfoEventProcessingTest, ProcessDeletedEvent)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      m_reportDiffFunc,
                      m_logFunc,
                      m_queryModuleFunc,
                      m_mockDBSync
                  );

    // Create test data for agent_groups deletion
    nlohmann::json testData;
    testData["agent_id"] = "001";
    testData["group_name"] = "removed-group";

    // Process the event
    m_agentInfo->processEvent(DELETED, testData, "agent_groups");

    // Verify report callback was invoked
    ASSERT_EQ(m_reportedEvents.size(), 1u);
    EXPECT_EQ(m_reportedEvents[0]["data"]["event"]["type"], "deleted");
    EXPECT_EQ(m_reportedEvents[0]["data"]["agent"]["id"], "001");

    // Note: Persist callback verification removed as per PR feedback
}

TEST_F(AgentInfoEventProcessingTest, ProcessAgentGroupsEvent)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      m_reportDiffFunc,
                      m_logFunc,
                      m_queryModuleFunc,
                      m_mockDBSync
                  );

    // Create test data for agent_groups
    nlohmann::json testData;
    testData["agent_id"] = "002";
    testData["group_name"] = "web-servers";

    // Process the event
    m_agentInfo->processEvent(INSERTED, testData, "agent_groups");

    // Verify ECS format for groups
    ASSERT_EQ(m_reportedEvents.size(), 1u);
    EXPECT_EQ(m_reportedEvents[0]["data"]["agent"]["id"], "002");
    EXPECT_TRUE(m_reportedEvents[0]["data"]["agent"]["groups"].is_array());
    EXPECT_EQ(m_reportedEvents[0]["data"]["agent"]["groups"][0], "web-servers");
}

TEST_F(AgentInfoEventProcessingTest, ProcessEventWithExceptionInCallback)
{
    // Create a callback that throws an exception
    auto throwingReportFunc = [](const std::string& /* event */)
    {
        throw std::runtime_error("Test exception in report callback");
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
    testData["agent_name"] = "test";

    // Process event - exception should be caught and logged
    EXPECT_NO_THROW(m_agentInfo->processEvent(INSERTED, testData, "agent_metadata"));

    // Verify error was logged
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Error processing event"));
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Test exception in report callback"));
}
