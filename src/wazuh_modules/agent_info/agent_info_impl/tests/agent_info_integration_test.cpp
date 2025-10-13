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
    // Setup mocks to provide data
    EXPECT_CALL(*m_mockFileSystem, exists(::testing::_))
    .WillOnce(::testing::Return(true))
    .WillOnce(::testing::Return(true));

    EXPECT_CALL(*m_mockFileIO, readLineByLine(::testing::_, ::testing::_))
    .WillOnce(::testing::Invoke([](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        callback("456 real-dbsync-test 10.0.0.1 key");
    }))
    .WillOnce(::testing::Invoke([](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        callback("#group: dbsync-test-group");
    }));

    nlohmann::json osData = {{"os_name", "TestOS"}, {"architecture", "test64"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    // Create agent info with real DBSync (using in-memory database)
    // This will trigger updateChanges internally through start()
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      m_reportDiffFunc,
                      nullptr,
                      m_logFunc,
                      nullptr,  // Use real DBSync
                      m_mockSysInfo,
                      m_mockFileIO,
                      m_mockFileSystem
                  );

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
