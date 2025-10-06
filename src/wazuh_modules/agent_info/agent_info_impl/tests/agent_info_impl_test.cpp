#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <agent_info_impl.hpp>

#include "logging_helper.hpp"
#include <dbsync.hpp>
#include <mock_dbsync.hpp>
#include <mock_file_io_utils.hpp>
#include <mock_filesystem_wrapper.hpp>
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

// ============================================================================
// Tests for populateAgentMetadata functionality
// ============================================================================

class AgentInfoMetadataTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            m_logOutput.clear();

            LoggingHelper::setLogCallback(
                [this](const modules_log_level_t /* level */, const char* log)
            {
                m_logOutput += log;
                m_logOutput += "\n";
            });

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

    // Setup: Expect DBSync insertData to be called twice (metadata + groups)
    EXPECT_CALL(*m_mockDBSync, insertData(::testing::_))
    .Times(2)
    .WillRepeatedly(::testing::Invoke(
                        [](const nlohmann::json & data)
    {
        // Verify the data structure
        EXPECT_TRUE(data.contains("table"));
        EXPECT_TRUE(data.contains("data"));
        EXPECT_TRUE(data["data"].is_array());
    }));

    // Create agent info and start
    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start();

    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent metadata populated successfully"));
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent groups populated successfully: 2 groups"));
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

    // Expect insertData to still be called for metadata and groups (empty)
    EXPECT_CALL(*m_mockDBSync, insertData(::testing::_)).Times(2);

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
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

    // Expect insertData with empty groups array
    EXPECT_CALL(*m_mockDBSync, insertData(::testing::_))
    .Times(2)
    .WillRepeatedly(::testing::Invoke(
                        [](const nlohmann::json & data)
    {
        if (data["table"] == "agent_groups")
        {
            EXPECT_TRUE(data["data"].is_array());
            EXPECT_EQ(data["data"].size(), 0); // Empty groups
        }
    }));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
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

    EXPECT_CALL(*m_mockDBSync, insertData(::testing::_)).Times(2);

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
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

    bool groupsValidated = false;
    EXPECT_CALL(*m_mockDBSync, insertData(::testing::_))
    .Times(2)
    .WillRepeatedly(::testing::Invoke(
                        [&groupsValidated](const nlohmann::json & data)
    {
        if (data["table"] == "agent_groups")
        {
            EXPECT_EQ(data["data"].size(), 3);
            EXPECT_EQ(data["data"][0]["group_name"], "web-servers");
            EXPECT_EQ(data["data"][1]["group_name"], "database");
            EXPECT_EQ(data["data"][2]["group_name"], "monitoring");
            EXPECT_EQ(data["data"][0]["agent_id"], "002");
            groupsValidated = true;
        }
    }));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start();

    EXPECT_TRUE(groupsValidated);
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent groups populated successfully: 3 groups"));
}

TEST_F(AgentInfoMetadataTest, HandlesExceptionDuringPopulate)
{
    // Setup: Make fileSystem throw an exception
    EXPECT_CALL(*m_mockFileSystem, exists(::testing::_))
    .WillOnce(::testing::Throw(std::runtime_error("Filesystem error")));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);

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

    bool metadataValidated = false;
    EXPECT_CALL(*m_mockDBSync, insertData(::testing::_))
    .Times(2)
    .WillRepeatedly(::testing::Invoke(
                        [&metadataValidated](const nlohmann::json & data)
    {
        if (data["table"] == "agent_metadata")
        {
            const auto& item = data["data"][0];
            EXPECT_EQ(item["agent_id"], "123");
            EXPECT_EQ(item["agent_name"], "my-agent");
            EXPECT_EQ(item["host_architecture"], "x86_64");
            EXPECT_EQ(item["host_hostname"], "test-machine");
            EXPECT_EQ(item["host_os_name"], "CentOS");
            EXPECT_EQ(item["host_os_type"], "Linux");
            EXPECT_EQ(item["host_os_platform"], "centos");
            EXPECT_EQ(item["host_os_version"], "8.5");
            EXPECT_TRUE(item.contains("agent_version"));
            EXPECT_TRUE(item.contains("checksum"));
            metadataValidated = true;
        }
    }));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start();

    EXPECT_TRUE(metadataValidated);
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

    bool metadataValidated = false;
    EXPECT_CALL(*m_mockDBSync, insertData(::testing::_))
    .Times(2)
    .WillRepeatedly(::testing::Invoke(
                        [&metadataValidated](const nlohmann::json & data)
    {
        if (data["table"] == "agent_metadata")
        {
            const auto& item = data["data"][0];
            EXPECT_EQ(item["host_hostname"], "incomplete-host");
            EXPECT_EQ(item["host_os_name"], "Windows");
            // These fields should not be present since they weren't in osData
            EXPECT_FALSE(item.contains("host_architecture"));
            EXPECT_FALSE(item.contains("host_os_type"));
            EXPECT_FALSE(item.contains("host_os_platform"));
            EXPECT_FALSE(item.contains("host_os_version"));
            metadataValidated = true;
        }
    }));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start();

    EXPECT_TRUE(metadataValidated);
}
