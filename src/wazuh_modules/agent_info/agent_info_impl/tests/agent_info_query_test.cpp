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
 * @brief Test fixture for AgentInfoImpl::getMetadata() functionality
 *
 * This test fixture focuses on testing the query system:
 * - getMetadata() returns proper JSON with metadata and groups
 * - Handles empty database (no metadata available)
 * - Handles database errors gracefully
 * - Returns proper status codes (ok/error)
 */
class AgentInfoQueryTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            m_logOutput.clear();

            // Create the logging function to capture log messages
            m_logFunction = [this](const modules_log_level_t /* level */, const std::string& log)
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

/**
 * @brief Test getMetadata returns complete metadata when database has data
 */
TEST_F(AgentInfoQueryTest, GetMetadataReturnsCompleteData)
{
    // Create AgentInfoImpl instance
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      nullptr,
                      m_logFunction,
                      m_mockDBSync,
                      m_mockSysInfo,
                      m_mockFileIO,
                      m_mockFileSystem);

    // Mock selectRows to return metadata
    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillOnce(::testing::Invoke(
                  [](const nlohmann::json& query, ResultCallbackData callback)
    {
        // First call is for agent_metadata table
        if (query["table"] == "agent_metadata")
        {
            nlohmann::json metadata = {
                {"agent_id", "001"},
                {"agent_name", "test-agent"},
                {"agent_version", "v4.8.0"},
                {"host_architecture", "x86_64"},
                {"host_hostname", "test-host"},
                {"host_os_name", "Ubuntu"},
                {"host_os_type", "Linux"},
                {"host_os_platform", "ubuntu"},
                {"host_os_version", "22.04"},
                {"checksum", "abc123"}
            };
            callback(SELECTED, metadata);
        }
    }))
    .WillOnce(::testing::Invoke(
                  [](const nlohmann::json& query, ResultCallbackData callback)
    {
        // Second call is for agent_groups table
        if (query["table"] == "agent_groups")
        {
            nlohmann::json group1 = {{"agent_id", "001"}, {"group_name", "default"}};
            nlohmann::json group2 = {{"agent_id", "001"}, {"group_name", "webserver"}};
            callback(SELECTED, group1);
            callback(SELECTED, group2);
        }
    }));

    // Execute getMetadata
    nlohmann::json result = m_agentInfo->getMetadata();

    // Verify result structure
    ASSERT_TRUE(result.contains("status"));
    EXPECT_EQ(result["status"], "ok");

    ASSERT_TRUE(result.contains("metadata"));
    EXPECT_EQ(result["metadata"]["agent_id"], "001");
    EXPECT_EQ(result["metadata"]["agent_name"], "test-agent");
    EXPECT_EQ(result["metadata"]["agent_version"], "v4.8.0");
    EXPECT_EQ(result["metadata"]["host_architecture"], "x86_64");
    EXPECT_EQ(result["metadata"]["host_hostname"], "test-host");
    EXPECT_EQ(result["metadata"]["host_os_name"], "Ubuntu");
    EXPECT_EQ(result["metadata"]["host_os_type"], "Linux");
    EXPECT_EQ(result["metadata"]["host_os_platform"], "ubuntu");
    EXPECT_EQ(result["metadata"]["host_os_version"], "22.04");
    EXPECT_EQ(result["metadata"]["checksum"], "abc123");

    ASSERT_TRUE(result.contains("groups"));
    ASSERT_TRUE(result["groups"].is_array());
    ASSERT_EQ(result["groups"].size(), 2);
    EXPECT_EQ(result["groups"][0], "default");
    EXPECT_EQ(result["groups"][1], "webserver");
}

/**
 * @brief Test getMetadata returns empty metadata when database is empty
 */
TEST_F(AgentInfoQueryTest, GetMetadataReturnsEmptyWhenNoData)
{
    // Create AgentInfoImpl instance
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      nullptr,
                      m_logFunction,
                      m_mockDBSync,
                      m_mockSysInfo,
                      m_mockFileIO,
                      m_mockFileSystem);

    // Mock selectRows to return no data
    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .Times(2); // Called twice: once for metadata, once for groups

    // Execute getMetadata
    nlohmann::json result = m_agentInfo->getMetadata();

    // Verify result structure
    ASSERT_TRUE(result.contains("status"));
    EXPECT_EQ(result["status"], "ok");

    ASSERT_TRUE(result.contains("metadata"));
    EXPECT_TRUE(result["metadata"].is_object());
    EXPECT_TRUE(result["metadata"].empty());

    ASSERT_TRUE(result.contains("groups"));
    ASSERT_TRUE(result["groups"].is_array());
    EXPECT_TRUE(result["groups"].empty());
}

/**
 * @brief Test getMetadata handles database exception gracefully
 */
TEST_F(AgentInfoQueryTest, GetMetadataHandlesException)
{
    // Create AgentInfoImpl instance
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      nullptr,
                      m_logFunction,
                      m_mockDBSync,
                      m_mockSysInfo,
                      m_mockFileIO,
                      m_mockFileSystem);

    // Mock selectRows to throw exception
    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillOnce(::testing::Throw(std::runtime_error("Database error")));

    // Execute getMetadata
    nlohmann::json result = m_agentInfo->getMetadata();

    // Verify error result
    ASSERT_TRUE(result.contains("status"));
    EXPECT_EQ(result["status"], "error");

    ASSERT_TRUE(result.contains("message"));
    EXPECT_THAT(result["message"].get<std::string>(),
                ::testing::HasSubstr("Failed to retrieve metadata"));
    EXPECT_THAT(result["message"].get<std::string>(),
                ::testing::HasSubstr("Database error"));

    // Verify error was logged
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Failed to retrieve metadata"));
}

/**
 * @brief Test getMetadata with metadata but no groups
 */
TEST_F(AgentInfoQueryTest, GetMetadataWithNoGroups)
{
    // Create AgentInfoImpl instance
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      nullptr,
                      m_logFunction,
                      m_mockDBSync,
                      m_mockSysInfo,
                      m_mockFileIO,
                      m_mockFileSystem);

    // Mock selectRows to return metadata but no groups
    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillOnce(::testing::Invoke(
                  [](const nlohmann::json& query, ResultCallbackData callback)
    {
        // Return metadata
        if (query["table"] == "agent_metadata")
        {
            nlohmann::json metadata = {
                {"agent_id", "001"},
                {"agent_name", "test-agent"},
                {"checksum", "abc123"}
            };
            callback(SELECTED, metadata);
        }
    }))
    .WillOnce(::testing::Return()); // No groups returned

    // Execute getMetadata
    nlohmann::json result = m_agentInfo->getMetadata();

    // Verify result
    EXPECT_EQ(result["status"], "ok");
    EXPECT_EQ(result["metadata"]["agent_id"], "001");
    ASSERT_TRUE(result["groups"].is_array());
    EXPECT_TRUE(result["groups"].empty());
}

/**
 * @brief Test getMetadata extracts only group_name field
 */
TEST_F(AgentInfoQueryTest, GetMetadataExtractsGroupNames)
{
    // Create AgentInfoImpl instance
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      nullptr,
                      m_logFunction,
                      m_mockDBSync,
                      m_mockSysInfo,
                      m_mockFileIO,
                      m_mockFileSystem);

    // Mock selectRows
    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillOnce(::testing::Invoke(
                  [](const nlohmann::json& query, ResultCallbackData callback)
    {
        if (query["table"] == "agent_metadata")
        {
            nlohmann::json metadata = {{"agent_id", "001"}, {"checksum", "abc"}};
            callback(SELECTED, metadata);
        }
    }))
    .WillOnce(::testing::Invoke(
                  [](const nlohmann::json& query, ResultCallbackData callback)
    {
        // Groups with extra fields (should extract only group_name)
        if (query["table"] == "agent_groups")
        {
            nlohmann::json group1 = {
                {"agent_id", "001"},
                {"group_name", "group_a"},
                {"extra_field", "should_be_ignored"}
            };
            nlohmann::json group2 = {
                {"agent_id", "001"},
                {"group_name", "group_b"}
            };
            callback(SELECTED, group1);
            callback(SELECTED, group2);
        }
    }));

    // Execute getMetadata
    nlohmann::json result = m_agentInfo->getMetadata();

    // Verify only group names are extracted
    ASSERT_EQ(result["groups"].size(), 2);
    EXPECT_EQ(result["groups"][0], "group_a");
    EXPECT_EQ(result["groups"][1], "group_b");
}
