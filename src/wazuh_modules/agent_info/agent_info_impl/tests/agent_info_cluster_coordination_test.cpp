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

// Declarations for mock setter functions (defined in agent_info_mock.cpp)
void mock_set_cluster_name(const std::string& name);
void mock_set_cluster_node(const std::string& node);

/**
 * @brief Test fixture for cluster_name/cluster_node sync flag routing
 *
 * Tests that:
 * - cluster_name changes set the groups sync flag (not metadata)
 * - cluster_node changes set no sync flag
 * - Other metadata changes set the metadata sync flag
 * - Combined changes set appropriate flags
 *
 * Uses real DBSync with in-memory database and configurable mock
 * cluster_name/cluster_node values to simulate changes between iterations.
 */
class AgentInfoClusterCoordinationTest : public ::testing::Test
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

            m_queryModuleFunc = [](const std::string& /* module_name */, const std::string& /* query */, char** response) -> int
            {
                if (response)
                {
                    *response = nullptr;
                }

                return 0;
            };

            m_mockFileSystem = std::make_shared<MockFileSystemWrapper>();
            m_mockFileIO = std::make_shared<MockFileIOUtils>();
            m_mockSysInfo = std::make_shared<MockSysInfo>();

            // Reset mock cluster values to defaults
            mock_set_cluster_name("test_cluster");
            mock_set_cluster_node("test_node");
        }

        void TearDown() override
        {
            m_agentInfo.reset();
            m_mockFileSystem.reset();
            m_mockFileIO.reset();
            m_mockSysInfo.reset();

            // Reset mock cluster values
            mock_set_cluster_name("test_cluster");
            mock_set_cluster_node("test_node");
        }

        void setupDefaultMocks()
        {
            EXPECT_CALL(*m_mockFileSystem, exists(::testing::_))
            .WillRepeatedly(::testing::Return(true));

            EXPECT_CALL(*m_mockFileIO, readLineByLine(::testing::_, ::testing::_))
            .WillRepeatedly(::testing::Invoke([](const std::filesystem::path & path, const std::function<bool(const std::string&)>& callback)
            {
                std::string pathStr = path.string();

                if (pathStr.find("client.keys") != std::string::npos)
                {
                    callback("001 test-agent 10.0.0.1 key");
                }
                else if (pathStr.find("merged.mg") != std::string::npos)
                {
                    callback("#test-group");
                }
            }));
        }

        /// Run start() for a single iteration, capturing sync flag log messages
        void runSingleIteration()
        {
            m_agentInfo->start(1, 86400, []()
            {
                return false;
            });
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

TEST_F(AgentInfoClusterCoordinationTest, ClusterNameChange_SetsGroupsSyncFlag)
{
    setupDefaultMocks();

    // First iteration: initial insert with cluster_name = "test_cluster"
    nlohmann::json osData1 =
    {
        {"os_name", "TestOS"}, {"architecture", "x86_64"}, {"os_type", "linux"},
        {"os_platform", "ubuntu"}, {"os_version", "22.04"}, {"hostname", "test-host"}
    };

    // Second iteration: cluster_name changes to "new_cluster"
    nlohmann::json osData2 = osData1;

    EXPECT_CALL(*m_mockSysInfo, os())
    .WillOnce(::testing::Return(osData1))
    .WillOnce(::testing::Return(osData2));

    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      m_reportDiffFunc,
                      m_logFunc,
                      m_queryModuleFunc,
                      nullptr,  // Real DBSync
                      m_mockSysInfo,
                      m_mockFileIO,
                      m_mockFileSystem
                  );

    // First run: populates initial data (INSERTED event)
    runSingleIteration();
    m_logOutput.clear();

    // Change cluster_name for second iteration
    mock_set_cluster_name("new_cluster");

    // Second run: should detect cluster_name change and set groups sync flag
    runSingleIteration();

    // Verify groups sync flag was set (not metadata sync flag)
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Set sync flag for agent_groups to 1"));
    // Metadata sync flag should NOT be set for cluster_name-only change
    EXPECT_THAT(m_logOutput, ::testing::Not(::testing::HasSubstr("Set sync flag for agent_metadata to 1")));
}

TEST_F(AgentInfoClusterCoordinationTest, ClusterNodeChange_NoSyncFlagSet)
{
    setupDefaultMocks();

    nlohmann::json osData =
    {
        {"os_name", "TestOS"}, {"architecture", "x86_64"}, {"os_type", "linux"},
        {"os_platform", "ubuntu"}, {"os_version", "22.04"}, {"hostname", "test-host"}
    };

    EXPECT_CALL(*m_mockSysInfo, os())
    .WillOnce(::testing::Return(osData))
    .WillOnce(::testing::Return(osData));

    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      m_reportDiffFunc,
                      m_logFunc,
                      m_queryModuleFunc,
                      nullptr,
                      m_mockSysInfo,
                      m_mockFileIO,
                      m_mockFileSystem
                  );

    // First run: populates initial data
    runSingleIteration();
    m_logOutput.clear();

    // Change only cluster_node for second iteration
    mock_set_cluster_node("new_node");

    // Second run: should detect cluster_node change but NOT set any sync flag
    runSingleIteration();

    // Neither sync flag should be set for cluster_node-only change
    EXPECT_THAT(m_logOutput, ::testing::Not(::testing::HasSubstr("Set sync flag for agent_metadata to 1")));
    EXPECT_THAT(m_logOutput, ::testing::Not(::testing::HasSubstr("Set sync flag for agent_groups to 1")));
}

TEST_F(AgentInfoClusterCoordinationTest, ClusterNameAndClusterNode_OnlyGroupsFlagSet)
{
    setupDefaultMocks();

    nlohmann::json osData =
    {
        {"os_name", "TestOS"}, {"architecture", "x86_64"}, {"os_type", "linux"},
        {"os_platform", "ubuntu"}, {"os_version", "22.04"}, {"hostname", "test-host"}
    };

    EXPECT_CALL(*m_mockSysInfo, os())
    .WillOnce(::testing::Return(osData))
    .WillOnce(::testing::Return(osData));

    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      m_reportDiffFunc,
                      m_logFunc,
                      m_queryModuleFunc,
                      nullptr,
                      m_mockSysInfo,
                      m_mockFileIO,
                      m_mockFileSystem
                  );

    // First run
    runSingleIteration();
    m_logOutput.clear();

    // Change both cluster_name and cluster_node
    mock_set_cluster_name("new_cluster");
    mock_set_cluster_node("new_node");

    // Second run
    runSingleIteration();

    // Only groups sync flag should be set (cluster_name → groups, cluster_node → nothing)
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Set sync flag for agent_groups to 1"));
    EXPECT_THAT(m_logOutput, ::testing::Not(::testing::HasSubstr("Set sync flag for agent_metadata to 1")));
}

TEST_F(AgentInfoClusterCoordinationTest, ClusterNameAndOtherMetadata_OnlyMetadataFlagSet)
{
    EXPECT_CALL(*m_mockFileSystem, exists(::testing::_))
    .WillRepeatedly(::testing::Return(true));

    nlohmann::json osData1 =
    {
        {"os_name", "TestOS"}, {"architecture", "x86_64"}, {"os_type", "linux"},
        {"os_platform", "ubuntu"}, {"os_version", "22.04"}, {"hostname", "test-host"}
    };

    // Change agent_name (via client.keys) AND cluster_name on second iteration
    nlohmann::json osData2 = osData1;

    EXPECT_CALL(*m_mockSysInfo, os())
    .WillOnce(::testing::Return(osData1))
    .WillOnce(::testing::Return(osData2));

    // Each iteration calls readLineByLine twice (client.keys + merged.mg), so 2 iterations = 4 calls
    EXPECT_CALL(*m_mockFileIO, readLineByLine(::testing::_, ::testing::_))
    // Iteration 1: client.keys
    .WillOnce(::testing::Invoke([](const std::filesystem::path & path, const std::function<bool(const std::string&)>& callback)
    {
        std::string pathStr = path.string();

        if (pathStr.find("client.keys") != std::string::npos)
        {
            callback("001 test-agent 10.0.0.1 key");
        }
        else if (pathStr.find("merged.mg") != std::string::npos)
        {
            callback("#test-group");
        }
    }))
    // Iteration 1: merged.mg
    .WillOnce(::testing::Invoke([](const std::filesystem::path & path, const std::function<bool(const std::string&)>& callback)
    {
        std::string pathStr = path.string();

        if (pathStr.find("client.keys") != std::string::npos)
        {
            callback("001 test-agent 10.0.0.1 key");
        }
        else if (pathStr.find("merged.mg") != std::string::npos)
        {
            callback("#test-group");
        }
    }))
    // Iteration 2: client.keys (changed agent_name)
    .WillOnce(::testing::Invoke([](const std::filesystem::path & path, const std::function<bool(const std::string&)>& callback)
    {
        std::string pathStr = path.string();

        if (pathStr.find("client.keys") != std::string::npos)
        {
            callback("001 renamed-agent 10.0.0.1 key");
        }
        else if (pathStr.find("merged.mg") != std::string::npos)
        {
            callback("#test-group");
        }
    }))
    // Iteration 2: merged.mg
    .WillOnce(::testing::Invoke([](const std::filesystem::path & path, const std::function<bool(const std::string&)>& callback)
    {
        std::string pathStr = path.string();

        if (pathStr.find("client.keys") != std::string::npos)
        {
            callback("001 renamed-agent 10.0.0.1 key");
        }
        else if (pathStr.find("merged.mg") != std::string::npos)
        {
            callback("#test-group");
        }
    }));

    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      m_reportDiffFunc,
                      m_logFunc,
                      m_queryModuleFunc,
                      nullptr,
                      m_mockSysInfo,
                      m_mockFileIO,
                      m_mockFileSystem
                  );

    // First run
    runSingleIteration();
    m_logOutput.clear();

    // Change cluster_name for second iteration (agent_name also changes via mock)
    mock_set_cluster_name("new_cluster");

    // Second run
    runSingleIteration();

    // Only metadata flag should be set: metadata subsumes cluster_name when both change
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Set sync flag for agent_metadata to 1"));
    EXPECT_THAT(m_logOutput, ::testing::Not(::testing::HasSubstr("Set sync flag for agent_groups to 1")));
}

TEST_F(AgentInfoClusterCoordinationTest, ClusterNodeAndOtherMetadata_OnlyMetadataFlagSet)
{
    nlohmann::json osData =
    {
        {"os_name", "TestOS"}, {"architecture", "x86_64"}, {"os_type", "linux"},
        {"os_platform", "ubuntu"}, {"os_version", "22.04"}, {"hostname", "test-host"}
    };

    EXPECT_CALL(*m_mockSysInfo, os())
    .WillOnce(::testing::Return(osData))
    .WillOnce(::testing::Return(osData));

    // Second iteration returns a different agent_name via client.keys
    EXPECT_CALL(*m_mockFileSystem, exists(::testing::_))
    .WillRepeatedly(::testing::Return(true));

    // Each iteration calls readLineByLine twice (client.keys + merged.mg), so 2 iterations = 4 calls
    EXPECT_CALL(*m_mockFileIO, readLineByLine(::testing::_, ::testing::_))
    // Iteration 1: client.keys
    .WillOnce(::testing::Invoke([](const std::filesystem::path & path, const std::function<bool(const std::string&)>& callback)
    {
        std::string pathStr = path.string();

        if (pathStr.find("client.keys") != std::string::npos)
        {
            callback("001 test-agent 10.0.0.1 key");
        }
        else if (pathStr.find("merged.mg") != std::string::npos)
        {
            callback("#test-group");
        }
    }))
    // Iteration 1: merged.mg
    .WillOnce(::testing::Invoke([](const std::filesystem::path & path, const std::function<bool(const std::string&)>& callback)
    {
        std::string pathStr = path.string();

        if (pathStr.find("client.keys") != std::string::npos)
        {
            callback("001 test-agent 10.0.0.1 key");
        }
        else if (pathStr.find("merged.mg") != std::string::npos)
        {
            callback("#test-group");
        }
    }))
    // Iteration 2: client.keys (changed agent_name)
    .WillOnce(::testing::Invoke([](const std::filesystem::path & path, const std::function<bool(const std::string&)>& callback)
    {
        std::string pathStr = path.string();

        if (pathStr.find("client.keys") != std::string::npos)
        {
            callback("001 renamed-agent 10.0.0.1 key");
        }
        else if (pathStr.find("merged.mg") != std::string::npos)
        {
            callback("#test-group");
        }
    }))
    // Iteration 2: merged.mg
    .WillOnce(::testing::Invoke([](const std::filesystem::path & path, const std::function<bool(const std::string&)>& callback)
    {
        std::string pathStr = path.string();

        if (pathStr.find("client.keys") != std::string::npos)
        {
            callback("001 renamed-agent 10.0.0.1 key");
        }
        else if (pathStr.find("merged.mg") != std::string::npos)
        {
            callback("#test-group");
        }
    }));

    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      m_reportDiffFunc,
                      m_logFunc,
                      m_queryModuleFunc,
                      nullptr,
                      m_mockSysInfo,
                      m_mockFileIO,
                      m_mockFileSystem
                  );

    // First run
    runSingleIteration();
    m_logOutput.clear();

    // Change cluster_node and agent_name (via mock) for second iteration
    mock_set_cluster_node("new_node");

    // Second run
    runSingleIteration();

    // Only metadata sync flag should be set (agent_name changed, cluster_node is ignored)
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Set sync flag for agent_metadata to 1"));
    EXPECT_THAT(m_logOutput, ::testing::Not(::testing::HasSubstr("Set sync flag for agent_groups to 1")));
}

TEST_F(AgentInfoClusterCoordinationTest, OtherMetadataOnly_OnlyMetadataFlagSet)
{
    nlohmann::json osData =
    {
        {"os_name", "TestOS"}, {"architecture", "x86_64"}, {"os_type", "linux"},
        {"os_platform", "ubuntu"}, {"os_version", "22.04"}, {"hostname", "test-host"}
    };

    EXPECT_CALL(*m_mockSysInfo, os())
    .WillOnce(::testing::Return(osData))
    .WillOnce(::testing::Return(osData));

    // Second iteration returns a different agent_name via client.keys
    EXPECT_CALL(*m_mockFileSystem, exists(::testing::_))
    .WillRepeatedly(::testing::Return(true));

    // Each iteration calls readLineByLine twice (client.keys + merged.mg), so 2 iterations = 4 calls
    EXPECT_CALL(*m_mockFileIO, readLineByLine(::testing::_, ::testing::_))
    // Iteration 1: client.keys
    .WillOnce(::testing::Invoke([](const std::filesystem::path & path, const std::function<bool(const std::string&)>& callback)
    {
        std::string pathStr = path.string();

        if (pathStr.find("client.keys") != std::string::npos)
        {
            callback("001 test-agent 10.0.0.1 key");
        }
        else if (pathStr.find("merged.mg") != std::string::npos)
        {
            callback("#test-group");
        }
    }))
    // Iteration 1: merged.mg
    .WillOnce(::testing::Invoke([](const std::filesystem::path & path, const std::function<bool(const std::string&)>& callback)
    {
        std::string pathStr = path.string();

        if (pathStr.find("client.keys") != std::string::npos)
        {
            callback("001 test-agent 10.0.0.1 key");
        }
        else if (pathStr.find("merged.mg") != std::string::npos)
        {
            callback("#test-group");
        }
    }))
    // Iteration 2: client.keys (changed agent_name)
    .WillOnce(::testing::Invoke([](const std::filesystem::path & path, const std::function<bool(const std::string&)>& callback)
    {
        std::string pathStr = path.string();

        if (pathStr.find("client.keys") != std::string::npos)
        {
            callback("001 renamed-agent 10.0.0.1 key");
        }
        else if (pathStr.find("merged.mg") != std::string::npos)
        {
            callback("#test-group");
        }
    }))
    // Iteration 2: merged.mg
    .WillOnce(::testing::Invoke([](const std::filesystem::path & path, const std::function<bool(const std::string&)>& callback)
    {
        std::string pathStr = path.string();

        if (pathStr.find("client.keys") != std::string::npos)
        {
            callback("001 renamed-agent 10.0.0.1 key");
        }
        else if (pathStr.find("merged.mg") != std::string::npos)
        {
            callback("#test-group");
        }
    }));

    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      m_reportDiffFunc,
                      m_logFunc,
                      m_queryModuleFunc,
                      nullptr,
                      m_mockSysInfo,
                      m_mockFileIO,
                      m_mockFileSystem
                  );

    // First run
    runSingleIteration();
    m_logOutput.clear();

    // Only agent_name changes (via mock), no cluster changes
    // Second run
    runSingleIteration();

    // Only metadata sync flag should be set (no cluster_name change → no groups flag)
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Set sync flag for agent_metadata to 1"));
    EXPECT_THAT(m_logOutput, ::testing::Not(::testing::HasSubstr("Set sync flag for agent_groups to 1")));
}

TEST_F(AgentInfoClusterCoordinationTest, FirstRun_InsertedEvent_SetsMetadataFlag)
{
    setupDefaultMocks();

    nlohmann::json osData =
    {
        {"os_name", "TestOS"}, {"architecture", "x86_64"}, {"os_type", "linux"},
        {"os_platform", "ubuntu"}, {"os_version", "22.04"}, {"hostname", "test-host"}
    };

    EXPECT_CALL(*m_mockSysInfo, os())
    .WillOnce(::testing::Return(osData));

    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      m_reportDiffFunc,
                      m_logFunc,
                      m_queryModuleFunc,
                      nullptr,
                      m_mockSysInfo,
                      m_mockFileIO,
                      m_mockFileSystem
                  );

    // First run: INSERTED event should set metadata sync flag (categorizeMetadataChanges returns true for INSERTED)
    runSingleIteration();

    // On first run, metadata sync flag is set but then skipped due to m_isFirstRun
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Set sync flag for agent_metadata to 1"));
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("First run detected for agent-metadata, skipping synchronization"));
}
