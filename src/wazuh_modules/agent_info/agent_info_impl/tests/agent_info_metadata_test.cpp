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
            m_mockSysInfo = std::make_shared<MockSysInfo>();
            m_mockFileIO = std::make_shared<MockFileIOUtils>();
            m_mockFileSystem = std::make_shared<MockFileSystemWrapper>();

            // Configure expected calls to avoid warnings
            EXPECT_CALL(*m_mockDBSync, handle())
            .WillRepeatedly(::testing::Return(nullptr));

            // Configure selectRows call for loadSyncFlags()
            EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
            .WillRepeatedly(::testing::Return());
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
        std::function<int(const std::string&, const std::string&, char**)> m_queryModuleFunction;
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
        // Simulate merged.mg content with XML comments
        callback("<!-- Source file: default/agent.conf -->");
        callback("<!-- Source file: group1/agent.conf -->");
        callback("<!-- Source file: group2/agent.conf -->");
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
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_queryModuleFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

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
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_queryModuleFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

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
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_queryModuleFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

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
        callback("<!-- Source file: group1/agent.conf -->");
    }));

    nlohmann::json osData = {{"os_name", "Ubuntu"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    // Mock handle() to return nullptr
    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_queryModuleFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

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
        // Multiple groups in XML comments - multi-group format
        callback("#abcd1234");  // Hash in first line for multi-group format
        callback("<!-- Source file: default/agent.conf -->");
        callback("<!-- Source file: web-servers/agent.conf -->");
        callback("<!-- Source file: database/agent.conf -->");
        callback("<!-- Source file: monitoring/agent.conf -->");
    }));

    nlohmann::json osData = {{"architecture", "aarch64"}, {"hostname", "server1"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    // Mock handle() to return nullptr
    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_queryModuleFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent groups populated successfully: 4 groups"));
}

TEST_F(AgentInfoMetadataTest, HandlesExceptionDuringPopulate)
{
    // Setup: Make fileSystem throw an exception
    EXPECT_CALL(*m_mockFileSystem, exists(::testing::_))
    .WillOnce(::testing::Throw(std::runtime_error("Filesystem error")));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_queryModuleFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);

    // start() should catch the exception and log it
    EXPECT_NO_THROW(m_agentInfo->start(1, []()
    {
        return false;
    }));

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
        callback("<!-- Source file: default/agent.conf -->");
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
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_queryModuleFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

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
        callback("<!-- Source file: test/agent.conf -->");
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
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_queryModuleFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
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
    // Setup: merged.mg doesn't exist
    EXPECT_CALL(*m_mockFileSystem, exists(::testing::_))
    .WillOnce(::testing::Return(true))   // client.keys exists
    .WillOnce(::testing::Return(false)); // merged.mg doesn't exist

    EXPECT_CALL(*m_mockFileIO, readLineByLine(::testing::_, ::testing::_))
    .WillOnce(
        ::testing::Invoke([](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        callback("001 agent1 192.168.1.1 key123");
    }));
    // No second call expected since merged.mg doesn't exist

    nlohmann::json osData = {{"os_name", "Ubuntu"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_queryModuleFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

    // Should log that no groups were found
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent groups cleared (no groups found)"));
}

TEST_F(AgentInfoMetadataTest, ReadAgentGroups_OnlyDefaultGroup)
{
    // Setup: merged.mg exists but only has default group
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
        callback("#1397d1cd");
        callback("!357 agent.conf");
        callback("<!-- Source file: default/agent.conf -->");
        callback("<agent_config>");
        callback("  <!-- Shared agent configuration here -->");
        callback("</agent_config>");
    }));

    nlohmann::json osData = {{"os_name", "Ubuntu"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_queryModuleFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

    // Default group should be excluded, so no groups found
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent groups populated successfully: 1 groups"));
}

TEST_F(AgentInfoMetadataTest, ReadAgentGroups_SingleGroup)
{
    // Setup: merged.mg with single non-default group
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
        callback("#1397d1cd");
        callback("!357 agent.conf");
        callback("<!-- Source file: default/agent.conf -->");
        callback("<agent_config>");
        callback("</agent_config>");
        callback("<!-- Source file: mygroup/agent.conf -->");
        callback("<agent_config>");
        callback("</agent_config>");
    }));

    nlohmann::json osData = {{"os_name", "Ubuntu"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_queryModuleFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

    // Should find 1 group
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent groups populated successfully: 2 groups"));
}

TEST_F(AgentInfoMetadataTest, ReadAgentGroups_MultipleGroups)
{
    // Setup: merged.mg with multiple groups (matching user's example)
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
        // This matches the user's exact example
        callback("#1397d1cd");
        callback("!357 agent.conf");
        callback("<!-- Source file: default/agent.conf -->");
        callback("<agent_config>");
        callback("  <!-- Shared agent configuration here -->");
        callback("</agent_config>");
        callback("<!-- Source file: mygroup/agent.conf -->");
        callback("<agent_config>");
        callback("  <!-- Shared agent configuration here -->");
        callback("</agent_config>");
        callback("<!-- Source file: mysecondgroup/agent.conf -->");
        callback("<agent_config>");
        callback("  <!-- Shared agent configuration here -->");
        callback("</agent_config>");
    }));

    nlohmann::json osData = {{"os_name", "Ubuntu"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_queryModuleFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

    // Should find 2 groups (mygroup and mysecondgroup), excluding default
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent groups populated successfully: 3 groups"));
}

TEST_F(AgentInfoMetadataTest, ReadAgentGroups_WithWhitespaceAndExtraLines)
{
    // Setup: Test edge cases with whitespace, empty lines, and various formats
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
        callback("");  // empty line
        callback("<!-- Source file: default/agent.conf -->");
        callback("   ");  // whitespace only
        callback("<!--Source file: group-with-no-spaces/agent.conf-->");  // No spaces around comment
        callback("  <!-- Source file: group-with-leading-space/agent.conf -->  ");  // Leading/trailing spaces
        callback("<!-- Some other comment -->");  // Non-group comment
        callback("<!-- Source file: group-with-dashes-123/agent.conf -->");  // Group with dashes and numbers
        callback("<agent_config>");
    }));

    nlohmann::json osData = {{"os_name", "Ubuntu"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_queryModuleFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

    // Should find 3 groups (excluding default)
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent groups populated successfully: 4 groups"));
}

TEST_F(AgentInfoMetadataTest, ReadAgentGroups_MalformedComments)
{
    // Setup: Test with various malformed comments that should be ignored
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
        callback("#12345678");  // Multi-group format: hash in first line
        callback("<!-- Source file: valid-group/agent.conf -->");
        callback("<!-- Source file: /agent.conf -->");  // Missing group name
        callback("<!-- Source file: another-group/wrong.conf -->");  // Wrong file name (not agent.conf)
        callback("<!-- Source file: third-group/ -->");  // Missing agent.conf
        callback("<!-- Source file: agent.conf -->");  // Missing group path separator
    }));

    nlohmann::json osData = {{"os_name", "Ubuntu"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_queryModuleFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

    // Should only find 1 valid group
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent groups populated successfully: 1 groups"));
}

TEST_F(AgentInfoMetadataTest, ReadAgentGroups_SingleGroupFormat_Default)
{
    // Test single-group format with "default" group
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
        // Single group format: first line is #groupname
        callback("#default");
        callback("!77 ar.conf");
        callback("restart-ossec0 - restart-ossec.sh - 0");
        callback("!76 agent.conf");
        callback("<agent_config>");
        callback("</agent_config>");
    }));

    nlohmann::json osData = {{"os_name", "Ubuntu"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_queryModuleFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

    // Should find default group in single-group format
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent groups populated successfully: 1 groups"));
}

TEST_F(AgentInfoMetadataTest, ReadAgentGroups_SingleGroupFormat_CustomGroup)
{
    // Test single-group format with custom group name
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
        // Single group format: first line is #groupname
        callback("#web-servers");
        callback("!77 ar.conf");
        callback("restart-ossec0 - restart-ossec.sh - 0");
        callback("!76 agent.conf");
        callback("<agent_config>");
        callback("</agent_config>");
    }));

    nlohmann::json osData = {{"os_name", "Ubuntu"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_queryModuleFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

    // Should find web-servers group in single-group format
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent groups populated successfully: 1 groups"));
}

TEST_F(AgentInfoMetadataTest, ReadAgentGroups_MultiGroupFormat_WithHash)
{
    // Test multi-group format with hash in first line
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
        // Multi-group format: first line is #hash_id
        callback("#93f39afe");
        callback("!234 agent.conf");
        callback("<!-- Source file: default/agent.conf -->");
        callback("<agent_config>");
        callback("</agent_config>");
        callback("<!-- Source file: web-servers/agent.conf -->");
        callback("<agent_config>");
        callback("</agent_config>");
    }));

    nlohmann::json osData = {{"os_name", "Ubuntu"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_queryModuleFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

    // Should find 2 groups from XML comments
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent groups populated successfully: 2 groups"));
}

/**
 * @brief Real-world test cases from user examples
 */
TEST_F(AgentInfoMetadataTest, ReadAgentGroups_RealWorld_SingleGroup)
{
    // Test exact format from user's example: single group "mygroup"
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
        // Real single-group format from user
        callback("#mygroup");
        callback("!76 agent.conf");
        callback("<agent_config>");
        callback("");
        callback("  <!-- Shared agent configuration here -->");
        callback("");
        callback("</agent_config>");
    }));

    nlohmann::json osData = {{"os_name", "Ubuntu"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_queryModuleFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

    // Should find exactly 1 group: "mygroup"
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent groups populated successfully: 1 groups"));
}

TEST_F(AgentInfoMetadataTest, ReadAgentGroups_RealWorld_MultiGroup)
{
    // Test exact format from user's example: multiple groups with hash
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
        // Real multi-group format from user
        callback("#93f39afe");
        callback("!234 agent.conf");
        callback("<!-- Source file: default/agent.conf -->");
        callback("<agent_config>");
        callback("");
        callback("  <!-- Shared agent configuration here -->");
        callback("");
        callback("</agent_config>");
        callback("<!-- Source file: mygroup/agent.conf -->");
        callback("<agent_config>");
        callback("");
        callback("  <!-- Shared agent configuration here -->");
        callback("");
        callback("</agent_config>");
    }));

    nlohmann::json osData = {{"os_name", "Ubuntu"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    m_agentInfo =
        std::make_shared<AgentInfoImpl>("test_path", nullptr, m_logFunction, m_queryModuleFunction, m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);
    m_agentInfo->start(1, []()
    {
        return false;
    });

    // Should find 2 groups: "default" and "mygroup"
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent groups populated successfully: 2 groups"));
}

TEST_F(AgentInfoMetadataTest, ReadAgentGroupsWithInvalidHash)
{
    // Setup merged.mg with invalid hash (contains non-hex character)
    EXPECT_CALL(*m_mockFileSystem, exists(::testing::_))
    .WillOnce(::testing::Return(true))  // client.keys exists
    .WillOnce(::testing::Return(true)); // merged.mg exists

    EXPECT_CALL(*m_mockFileIO, readLineByLine(::testing::_, ::testing::_))
    .WillOnce(::testing::Invoke([](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        // Simulate client.keys content
        callback("123 test-agent 10.0.0.1 key");
    }))
    .WillOnce(::testing::Invoke([](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        // Simulate merged.mg with 8 characters but contains non-hex char 'g'
        // This should be treated as a group name, not a hash
        callback("#12345g78");
    }));

    nlohmann::json osData = {{"os_name", "TestOS"}, {"architecture", "test64"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      "test_path", nullptr, m_logFunction, m_queryModuleFunction,
                      m_mockDBSync, m_mockSysInfo, m_mockFileIO, m_mockFileSystem);

    m_agentInfo->setIsAgent(true);

    m_agentInfo->start(1, []()
    {
        return false;
    });

    // Should treat "12345g78" as a group name since it's not a valid hexadecimal hash
    // This covers the case where looksLikeHash becomes false (line 541)
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent groups populated successfully: 1 groups"));
}
