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
    // Setup: Mock client.keys file reading
    EXPECT_CALL(*m_mockFileSystem, exists(::testing::_))
    .WillOnce(::testing::Return(true))  // client.keys exists
    .WillOnce(::testing::Return(true)); // merged.mg exists

    EXPECT_CALL(*m_mockFileIO, readLineByLine(::testing::_, ::testing::_))
    .WillOnce(::testing::Invoke(
                  [](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        // Simulate client.keys content: "001 agent1 192.168.1.1 key123"
        callback("001 agent1 192.168.1.1 key123");
    }))
    .WillOnce(::testing::Invoke(
                  [](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        // Simulate merged.mg content: "#group: group1,group2"
        callback("#group: group1,group2");
    }));

    // Setup: Mock sysinfo OS data
    nlohmann::json osData = {{"architecture", "x86_64"},
        {"hostname", "test-host"},
        {"os_name", "Ubuntu"},
        {"os_type", "Linux"},
        {"os_platform", "ubuntu"},
        {"os_version", "22.04"}
    };
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    // Mock handle() to return nullptr - updateChanges will catch exceptions
    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    // Create agent info and start
    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, nullptr, m_logFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start();

    // With nullptr handle, updateChanges will log errors but not crash
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent metadata populated successfully"));
}

TEST_F(AgentInfoMetadataTest, HandlesClientKeysNotFound)
{
    // Setup: client.keys doesn't exist
    EXPECT_CALL(*m_mockFileSystem, exists(::testing::_))
    .WillOnce(::testing::Return(false))  // client.keys doesn't exist
    .WillOnce(::testing::Return(false)); // merged.mg doesn't exist

    // Mock sysinfo
    nlohmann::json osData = {{"os_name", "Ubuntu"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    // Mock handle() to return nullptr
    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, nullptr, m_logFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start();

    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Failed to read agent ID and name from client.keys"));
}

TEST_F(AgentInfoMetadataTest, HandlesEmptyGroups)
{
    // Setup: Files exist
    EXPECT_CALL(*m_mockFileSystem, exists(::testing::_))
    .WillOnce(::testing::Return(true))  // client.keys exists
    .WillOnce(::testing::Return(true)); // merged.mg exists

    EXPECT_CALL(*m_mockFileIO, readLineByLine(::testing::_, ::testing::_))
    .WillOnce(
        ::testing::Invoke([](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        callback("001 agent1 192.168.1.1 key123");
    }))
    .WillOnce(::testing::Invoke(
                  [](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        // merged.mg with no group line - callback returns true to continue reading
        callback("some other line");
        return true;
    }));

    nlohmann::json osData = {{"os_name", "Ubuntu"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    // Mock handle() to return nullptr
    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, nullptr, m_logFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start();

    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent groups cleared (no groups found)"));
}

TEST_F(AgentInfoMetadataTest, HandlesInvalidClientKeysFormat)
{
    // Setup: Files exist but client.keys has invalid format
    EXPECT_CALL(*m_mockFileSystem, exists(::testing::_))
    .WillOnce(::testing::Return(true))  // client.keys exists
    .WillOnce(::testing::Return(true)); // merged.mg exists

    EXPECT_CALL(*m_mockFileIO, readLineByLine(::testing::_, ::testing::_))
    .WillOnce(::testing::Invoke(
                  [](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        // Invalid format - only one token
        callback("001");
    }))
    .WillOnce(
        ::testing::Invoke([](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        callback("#group: group1");
    }));

    nlohmann::json osData = {{"os_name", "Ubuntu"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    // Mock handle() to return nullptr
    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, nullptr, m_logFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start();

    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Failed to read agent ID and name from client.keys"));
}

TEST_F(AgentInfoMetadataTest, ParsesMultipleGroups)
{
    EXPECT_CALL(*m_mockFileSystem, exists(::testing::_))
    .WillOnce(::testing::Return(true))
    .WillOnce(::testing::Return(true));

    EXPECT_CALL(*m_mockFileIO, readLineByLine(::testing::_, ::testing::_))
    .WillOnce(
        ::testing::Invoke([](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        callback("002 test-agent 10.0.0.1 secretkey");
    }))
    .WillOnce(::testing::Invoke(
                  [](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        // Multiple groups with spaces
        callback("#group: web-servers, database, monitoring ");
    }));

    nlohmann::json osData = {{"architecture", "aarch64"}, {"hostname", "server1"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    // Mock handle() to return nullptr
    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, nullptr, m_logFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start();

    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent groups populated successfully: 3 groups"));
}

TEST_F(AgentInfoMetadataTest, HandlesExceptionDuringPopulate)
{
    // Setup: Make fileSystem throw an exception
    EXPECT_CALL(*m_mockFileSystem, exists(::testing::_))
    .WillOnce(::testing::Throw(std::runtime_error("Filesystem error")));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, nullptr, m_logFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);

    // start() should catch the exception and log it
    EXPECT_NO_THROW(m_agentInfo->start());

    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Failed to populate agent metadata"));
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Filesystem error"));
}

TEST_F(AgentInfoMetadataTest, IncludesAllOSFieldsInMetadata)
{
    EXPECT_CALL(*m_mockFileSystem, exists(::testing::_))
    .WillOnce(::testing::Return(true))
    .WillOnce(::testing::Return(true));

    EXPECT_CALL(*m_mockFileIO, readLineByLine(::testing::_, ::testing::_))
    .WillOnce(
        ::testing::Invoke([](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        callback("123 my-agent 192.168.1.100 mykey");
    }))
    .WillOnce(
        ::testing::Invoke([](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        callback("#group: default");
    }));

    nlohmann::json osData = {{"architecture", "x86_64"},
        {"hostname", "test-machine"},
        {"os_name", "CentOS"},
        {"os_type", "Linux"},
        {"os_platform", "centos"},
        {"os_version", "8.5"}
    };
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    // Mock handle() to return nullptr
    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, nullptr, m_logFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start();

    // Verify that start() completed and populated metadata
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent metadata populated successfully"));
}

TEST_F(AgentInfoMetadataTest, HandlesPartialOSData)
{
    EXPECT_CALL(*m_mockFileSystem, exists(::testing::_))
    .WillOnce(::testing::Return(true))
    .WillOnce(::testing::Return(true));

    EXPECT_CALL(*m_mockFileIO, readLineByLine(::testing::_, ::testing::_))
    .WillOnce(
        ::testing::Invoke([](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        callback("456 partial-os-agent 10.10.10.10 key456");
    }))
    .WillOnce(
        ::testing::Invoke([](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        callback("#group: test");
    }));

    // Only provide some OS fields
    nlohmann::json osData =
    {
        {"hostname", "incomplete-host"}, {"os_name", "Windows"}
        // Missing: architecture, os_type, os_platform, os_version
    };
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    // Mock handle() to return nullptr
    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, nullptr, m_logFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start();

    // Verify that start() completed
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent metadata populated successfully"));
}