#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <agent_info_impl.hpp>

#include <dbsync.hpp>
#include <mock_dbsync.hpp>

#include <memory>
#include <string>

/**
 * @brief Test fixture for AgentInfoImpl helper functions
 *
 * This test fixture focuses on testing the utility and helper functions:
 * - calculateMetadataChecksum() for generating consistent checksums
 * - calculateHashId() for generating unique identifiers
 * - ecsData() for converting database format to ECS (Elastic Common Schema)
 * - Data format conversion and validation
 * - Edge cases with partial or missing data
 */
class AgentInfoHelperFunctionsTest : public ::testing::Test
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
            m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, nullptr, m_logFunction, m_mockDBSync);
        }

        void TearDown() override
        {
            m_agentInfo.reset();
            m_mockDBSync.reset();
        }

        std::shared_ptr<MockDBSync> m_mockDBSync;
        std::shared_ptr<AgentInfoImpl> m_agentInfo;
        std::function<void(const modules_log_level_t, const std::string&)> m_logFunction;
        std::string m_logOutput;
};

TEST_F(AgentInfoHelperFunctionsTest, CalculateMetadataChecksumIsDeterministic)
{
    nlohmann::json metadata1;
    metadata1["agent_id"] = "001";
    metadata1["agent_name"] = "test";
    metadata1["host_os_name"] = "Ubuntu";

    nlohmann::json metadata2;
    metadata2["agent_id"] = "001";
    metadata2["agent_name"] = "test";
    metadata2["host_os_name"] = "Ubuntu";

    // Same metadata should produce same checksum
    std::string checksum1 = m_agentInfo->calculateMetadataChecksum(metadata1);
    std::string checksum2 = m_agentInfo->calculateMetadataChecksum(metadata2);

    EXPECT_EQ(checksum1, checksum2);
    EXPECT_FALSE(checksum1.empty());
}

TEST_F(AgentInfoHelperFunctionsTest, CalculateMetadataChecksumDifferentForDifferentData)
{
    nlohmann::json metadata1;
    metadata1["agent_id"] = "001";
    metadata1["agent_name"] = "agent1";

    nlohmann::json metadata2;
    metadata2["agent_id"] = "002";
    metadata2["agent_name"] = "agent2";

    std::string checksum1 = m_agentInfo->calculateMetadataChecksum(metadata1);
    std::string checksum2 = m_agentInfo->calculateMetadataChecksum(metadata2);

    EXPECT_NE(checksum1, checksum2);
}

TEST_F(AgentInfoHelperFunctionsTest, CalculateHashIdForMetadataTable)
{
    nlohmann::json data;
    data["agent_id"] = "123";

    std::string hashId = m_agentInfo->calculateHashId(data, "agent_metadata");

    EXPECT_FALSE(hashId.empty());
    EXPECT_GT(hashId.length(), 10); // SHA-1 hash should be long
}

TEST_F(AgentInfoHelperFunctionsTest, CalculateHashIdForGroupsTable)
{
    nlohmann::json data;
    data["agent_id"] = "123";
    data["group_name"] = "web-servers";

    std::string hashId = m_agentInfo->calculateHashId(data, "agent_groups");

    EXPECT_FALSE(hashId.empty());
    EXPECT_GT(hashId.length(), 10);
}

TEST_F(AgentInfoHelperFunctionsTest, EcsDataFormatsMetadataCorrectly)
{
    nlohmann::json data;
    data["agent_id"] = "001";
    data["agent_name"] = "test-agent";
    data["agent_version"] = "4.5.0";
    data["host_architecture"] = "x86_64";
    data["host_hostname"] = "test-host";
    data["host_os_name"] = "Ubuntu";
    data["host_os_type"] = "Linux";
    data["host_os_platform"] = "ubuntu";
    data["host_os_version"] = "22.04";
    data["checksum"] = "abc123";

    nlohmann::json ecsFormatted = m_agentInfo->ecsData(data, "agent_metadata");

    EXPECT_EQ(ecsFormatted["agent"]["id"], "001");
    EXPECT_EQ(ecsFormatted["agent"]["name"], "test-agent");
    EXPECT_EQ(ecsFormatted["agent"]["version"], "4.5.0");
    EXPECT_EQ(ecsFormatted["host"]["architecture"], "x86_64");
    EXPECT_EQ(ecsFormatted["host"]["hostname"], "test-host");
    EXPECT_EQ(ecsFormatted["host"]["os"]["name"], "Ubuntu");
    EXPECT_EQ(ecsFormatted["host"]["os"]["type"], "Linux");
    EXPECT_EQ(ecsFormatted["host"]["os"]["platform"], "ubuntu");
    EXPECT_EQ(ecsFormatted["host"]["os"]["version"], "22.04");
    EXPECT_EQ(ecsFormatted["checksum"], "abc123");
}

TEST_F(AgentInfoHelperFunctionsTest, EcsDataFormatsGroupsCorrectly)
{
    nlohmann::json data;
    data["agent_id"] = "002";
    data["group_name"] = "database";

    nlohmann::json ecsFormatted = m_agentInfo->ecsData(data, "agent_groups");

    EXPECT_EQ(ecsFormatted["agent"]["id"], "002");
    EXPECT_TRUE(ecsFormatted["agent"]["groups"].is_array());
    EXPECT_EQ(ecsFormatted["agent"]["groups"][0], "database");
}

TEST_F(AgentInfoHelperFunctionsTest, EcsDataHandlesPartialMetadata)
{
    nlohmann::json data;
    data["agent_id"] = "003";
    // Missing other fields

    nlohmann::json ecsFormatted = m_agentInfo->ecsData(data, "agent_metadata");

    EXPECT_EQ(ecsFormatted["agent"]["id"], "003");
    EXPECT_FALSE(ecsFormatted["agent"].contains("name"));
    EXPECT_FALSE(ecsFormatted.contains("host"));
}