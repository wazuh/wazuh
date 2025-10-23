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

/**
 * @brief Test fixture for AgentInfoImpl metadata population functionality
 *
 * This test fixture focuses on testing the metadata population features:
 * - Reading agent ID and name from client.keys file
 * - Reading agent groups from merged.mg file
 * - Gathering OS information from SysInfo
 * - Handling file I/O errors and edge cases
 * - Parsing different file formats and content variations
 */
class AgentInfoMetadataTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            m_logOutput.clear();

            // Create the logging function to capture log messages
            m_logFunction = [this](const modules_log_level_t /* level */, const std::string & log)
            {
                m_logOutput += log;
                m_logOutput += "\n";
            };

            m_mockDBSync = std::make_shared<MockDBSync>();
            m_mockSysInfo = std::make_shared<MockSysInfo>();
            m_mockFileIO = std::make_shared<MockFileIOUtils>();
            m_mockFileSystem = std::make_shared<MockFileSystemWrapper>();
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
        std::function<void(const modules_log_level_t, const std::string&)> m_logFunction;
        std::string m_logOutput;
};

TEST_F(AgentInfoMetadataTest, PopulatesMetadataSuccessfully)
{
    // Setup: Mock sysinfo OS data
    nlohmann::json osData = {{"architecture", "x86_64"},
        {"hostname", "test-host"},
        {"os_name", "Ubuntu"},
        {"os_type", "Linux"},
        {"os_platform", "ubuntu"},
        {"os_version", "22.04"}
    };
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    // Setup: Mock agent ID, name, and groups from SysInfo
    EXPECT_CALL(*m_mockSysInfo, agentId()).WillOnce(::testing::Return("001"));
    EXPECT_CALL(*m_mockSysInfo, agentName()).WillOnce(::testing::Return("agent1"));
    EXPECT_CALL(*m_mockSysInfo, agentGroups()).WillOnce(::testing::Return(std::vector<std::string> {"default", "group1", "group2"}));

    // Mock handle() to return nullptr - updateChanges will catch exceptions
    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    // Create agent info and start
    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

    // With nullptr handle, updateChanges will log errors but not crash
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent metadata populated successfully"));
}

TEST_F(AgentInfoMetadataTest, HandlesClientKeysNotFound)
{
    // Mock sysinfo
    nlohmann::json osData = {{"os_name", "Ubuntu"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    // SysInfo returns empty values when client.keys doesn't exist
    EXPECT_CALL(*m_mockSysInfo, agentId()).WillOnce(::testing::Return(""));
    EXPECT_CALL(*m_mockSysInfo, agentName()).WillOnce(::testing::Return(""));
    EXPECT_CALL(*m_mockSysInfo, agentGroups()).WillOnce(::testing::Return(std::vector<std::string> {}));

    // Mock handle() to return nullptr
    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Failed to read agent ID and name"));
}

TEST_F(AgentInfoMetadataTest, HandlesEmptyGroups)
{
    nlohmann::json osData = {{"os_name", "Ubuntu"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    // Agent exists but no groups
    EXPECT_CALL(*m_mockSysInfo, agentId()).WillOnce(::testing::Return("001"));
    EXPECT_CALL(*m_mockSysInfo, agentName()).WillOnce(::testing::Return("agent1"));
    EXPECT_CALL(*m_mockSysInfo, agentGroups()).WillOnce(::testing::Return(std::vector<std::string> {}));

    // Mock handle() to return nullptr
    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent groups cleared (no groups found)"));
}

TEST_F(AgentInfoMetadataTest, HandlesInvalidClientKeysFormat)
{
    nlohmann::json osData = {{"os_name", "Ubuntu"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    // Invalid format - only ID, no name
    EXPECT_CALL(*m_mockSysInfo, agentId()).WillOnce(::testing::Return("001"));
    EXPECT_CALL(*m_mockSysInfo, agentName()).WillOnce(::testing::Return(""));
    EXPECT_CALL(*m_mockSysInfo, agentGroups()).WillOnce(::testing::Return(std::vector<std::string> {"group1"}));

    // Mock handle() to return nullptr
    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Failed to read agent ID and name"));
}

TEST_F(AgentInfoMetadataTest, ParsesMultipleGroups)
{
    nlohmann::json osData = {{"architecture", "aarch64"}, {"hostname", "server1"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    EXPECT_CALL(*m_mockSysInfo, agentId()).WillOnce(::testing::Return("002"));
    EXPECT_CALL(*m_mockSysInfo, agentName()).WillOnce(::testing::Return("test-agent"));
    EXPECT_CALL(*m_mockSysInfo, agentGroups()).WillOnce(::testing::Return(std::vector<std::string> {"default", "web-servers", "database", "monitoring"}));

    // Mock handle() to return nullptr
    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent groups populated successfully: 4 groups"));
}

TEST_F(AgentInfoMetadataTest, HandlesExceptionDuringPopulate)
{
    // Setup: Make SysInfo throw an exception
    EXPECT_CALL(*m_mockSysInfo, agentId())
    .WillOnce(::testing::Throw(std::runtime_error("SysInfo error")));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);

    // start() should catch the exception and log it
    EXPECT_NO_THROW(m_agentInfo->start(1, []()
    {
        return false;
    }));

    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Failed to populate agent metadata"));
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("SysInfo error"));
}

TEST_F(AgentInfoMetadataTest, IncludesAllOSFieldsInMetadata)
{
    nlohmann::json osData = {{"architecture", "x86_64"},
        {"hostname", "test-machine"},
        {"os_name", "CentOS"},
        {"os_type", "Linux"},
        {"os_platform", "centos"},
        {"os_version", "8.5"}
    };
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    // Mock agent ID, name, and groups from SysInfo
    EXPECT_CALL(*m_mockSysInfo, agentId()).WillOnce(::testing::Return("123"));
    EXPECT_CALL(*m_mockSysInfo, agentName()).WillOnce(::testing::Return("my-agent"));
    EXPECT_CALL(*m_mockSysInfo, agentGroups()).WillOnce(::testing::Return(std::vector<std::string> {"default"}));

    // Mock handle() to return nullptr
    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

    // Verify that start() completed and populated metadata
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent metadata populated successfully"));
}

TEST_F(AgentInfoMetadataTest, HandlesPartialOSData)
{
    // Only provide some OS fields
    nlohmann::json osData =
    {
        {"hostname", "incomplete-host"}, {"os_name", "Windows"}
        // Missing: architecture, os_type, os_platform, os_version
    };
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    // Mock agent ID, name, and groups from SysInfo
    EXPECT_CALL(*m_mockSysInfo, agentId()).WillOnce(::testing::Return("456"));
    EXPECT_CALL(*m_mockSysInfo, agentName()).WillOnce(::testing::Return("partial-os-agent"));
    EXPECT_CALL(*m_mockSysInfo, agentGroups()).WillOnce(::testing::Return(std::vector<std::string> {"test"}));

    // Mock handle() to return nullptr
    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

    // Verify that start() completed
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent metadata populated successfully"));
}

/**
 * @brief Comprehensive tests for readAgentGroups() method
 *
 * These tests cover various scenarios for parsing agent groups from merged.mg file:
 * - File not found
 * - File exists but no groups (only default)
 * - File with single group
 * - File with multiple groups
 * - Edge cases (whitespace, empty lines, malformed comments)
 */

TEST_F(AgentInfoMetadataTest, ReadAgentGroups_FileNotFound)
{
    nlohmann::json osData = {{"os_name", "Ubuntu"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    // Mock agent exists but no groups (merged.mg doesn't exist)
    EXPECT_CALL(*m_mockSysInfo, agentId()).WillOnce(::testing::Return("001"));
    EXPECT_CALL(*m_mockSysInfo, agentName()).WillOnce(::testing::Return("agent1"));
    EXPECT_CALL(*m_mockSysInfo, agentGroups()).WillOnce(::testing::Return(std::vector<std::string> {}));

    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

    // Should log that no groups were found
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent groups cleared (no groups found)"));
}

TEST_F(AgentInfoMetadataTest, ReadAgentGroups_OnlyDefaultGroup)
{
    nlohmann::json osData = {{"os_name", "Ubuntu"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    // Mock agent with only default group
    EXPECT_CALL(*m_mockSysInfo, agentId()).WillOnce(::testing::Return("001"));
    EXPECT_CALL(*m_mockSysInfo, agentName()).WillOnce(::testing::Return("agent1"));
    EXPECT_CALL(*m_mockSysInfo, agentGroups()).WillOnce(::testing::Return(std::vector<std::string> {"default"}));

    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

    // Default group should be included
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent groups populated successfully: 1 groups"));
}

TEST_F(AgentInfoMetadataTest, ReadAgentGroups_SingleGroup)
{
    nlohmann::json osData = {{"os_name", "Ubuntu"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    // Mock agent with default and one custom group
    EXPECT_CALL(*m_mockSysInfo, agentId()).WillOnce(::testing::Return("001"));
    EXPECT_CALL(*m_mockSysInfo, agentName()).WillOnce(::testing::Return("agent1"));
    EXPECT_CALL(*m_mockSysInfo, agentGroups()).WillOnce(::testing::Return(std::vector<std::string> {"default", "mygroup"}));

    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

    // Should find 2 groups (default + mygroup)
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent groups populated successfully: 2 groups"));
}

TEST_F(AgentInfoMetadataTest, ReadAgentGroups_MultipleGroups)
{
    nlohmann::json osData = {{"os_name", "Ubuntu"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    // Mock agent with multiple groups
    EXPECT_CALL(*m_mockSysInfo, agentId()).WillOnce(::testing::Return("001"));
    EXPECT_CALL(*m_mockSysInfo, agentName()).WillOnce(::testing::Return("agent1"));
    EXPECT_CALL(*m_mockSysInfo, agentGroups()).WillOnce(::testing::Return(std::vector<std::string> {"default", "mygroup", "mysecondgroup"}));

    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

    // Should find 3 groups (default, mygroup, and mysecondgroup)
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent groups populated successfully: 3 groups"));
}

TEST_F(AgentInfoMetadataTest, ReadAgentGroups_WithWhitespaceAndExtraLines)
{
    nlohmann::json osData = {{"os_name", "Ubuntu"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    // Mock agent with groups that would have whitespace and various formats in merged.mg
    EXPECT_CALL(*m_mockSysInfo, agentId()).WillOnce(::testing::Return("001"));
    EXPECT_CALL(*m_mockSysInfo, agentName()).WillOnce(::testing::Return("agent1"));
    EXPECT_CALL(*m_mockSysInfo, agentGroups()).WillOnce(::testing::Return(std::vector<std::string> {"default", "group-with-no-spaces", "group-with-leading-space", "group-with-dashes-123"}));

    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

    // Should find 4 groups (default + 3 custom groups)
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent groups populated successfully: 4 groups"));
}

TEST_F(AgentInfoMetadataTest, ReadAgentGroups_MalformedComments)
{
    nlohmann::json osData = {{"os_name", "Ubuntu"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    // Mock agent with only valid group (malformed entries would be filtered by agentInfoHelper)
    EXPECT_CALL(*m_mockSysInfo, agentId()).WillOnce(::testing::Return("001"));
    EXPECT_CALL(*m_mockSysInfo, agentName()).WillOnce(::testing::Return("agent1"));
    EXPECT_CALL(*m_mockSysInfo, agentGroups()).WillOnce(::testing::Return(std::vector<std::string> {"valid-group"}));

    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

    // Should only find 1 valid group
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent groups populated successfully: 1 groups"));
}
