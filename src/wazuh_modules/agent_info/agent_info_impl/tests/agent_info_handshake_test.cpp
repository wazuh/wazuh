#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <agent_info_impl.hpp>

#include <mock_file_io_utils.hpp>
#include <mock_filesystem_wrapper.hpp>
#include <mock_sysinfo.hpp>

#include <atomic>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

/**
 * @brief Tests for the live handshake re-query mechanism (#37543).
 *
 * agent-info previously read cluster_name/cluster_node/agent_groups from a cache
 * populated once at module startup, so a manager-side cluster_name change was never
 * picked up until the whole agent process restarted. These tests verify that
 * populateAgentMetadata() now re-queries a fresh handshake on every cycle via the
 * injected handshake callback, falls back to the cached values on failure, and that
 * the fallback (no-callback) behavior used by the other test suites is unaffected.
 */
class AgentInfoHandshakeTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            m_logOutput.clear();
            m_reportedEvents.clear();

            m_reportDiffFunc = [this](const std::string & event)
            {
                m_reportedEvents.push_back(event);
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
        }

        void TearDown() override
        {
            m_agentInfo.reset();
            m_mockFileSystem.reset();
            m_mockFileIO.reset();
            m_mockSysInfo.reset();
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

        /// Run start() for a single iteration
        void runSingleIteration()
        {
            m_agentInfo->start(1, 86400, []()
            {
                return false;
            });
        }

        /// Copies `value` into the buffer, matching wm_agent_info_query_agentd_handshake's contract.
        static void writeField(char* dest, size_t destSize, const std::string& value)
        {
            std::strncpy(dest, value.c_str(), destSize - 1);
            dest[destSize - 1] = '\0';
        }

        std::shared_ptr<AgentInfoImpl> m_agentInfo;
        std::shared_ptr<MockFileSystemWrapper> m_mockFileSystem;
        std::shared_ptr<MockFileIOUtils> m_mockFileIO;
        std::shared_ptr<MockSysInfo> m_mockSysInfo;
        std::function<void(const std::string&)> m_reportDiffFunc;
        std::function<void(modules_log_level_t, const std::string&)> m_logFunc;
        std::function<int(const std::string&, const std::string&, char**)> m_queryModuleFunc;
        std::vector<std::string> m_reportedEvents;
        std::string m_logOutput;
};

TEST_F(AgentInfoHandshakeTest, LiveHandshakeQuery_PicksUpClusterNameChange)
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

    // First cycle reports "initial_cluster", second cycle reports "renamed_cluster" —
    // simulating the manager renaming its cluster and the agent reconnecting in between.
    int callCount = 0;
    handshake_query_callback_t handshakeFunc =
        [&callCount](char* clusterName, size_t clusterNameSize, char* clusterNode, size_t clusterNodeSize,
                     char* agentGroups, size_t agentGroupsSize) -> bool
    {
        ++callCount;
        writeField(clusterName, clusterNameSize, callCount == 1 ? "initial_cluster" : "renamed_cluster");
        writeField(clusterNode, clusterNodeSize, "node01");
        writeField(agentGroups, agentGroupsSize, "");
        return true;
    };

    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      m_reportDiffFunc,
                      m_logFunc,
                      m_queryModuleFunc,
                      nullptr, // Real DBSync
                      m_mockSysInfo,
                      m_mockFileIO,
                      m_mockFileSystem,
                      handshakeFunc
                  );

    // First run: initial insert with cluster_name = "initial_cluster"
    runSingleIteration();
    m_logOutput.clear();

    // Second run: live query now returns "renamed_cluster" — should be detected as a
    // cluster_name change, routing to the groups sync flag (not metadata)
    runSingleIteration();

    EXPECT_EQ(callCount, 2);
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Set sync flag for agent_groups to 1"));
    EXPECT_THAT(m_logOutput, ::testing::Not(::testing::HasSubstr("Set sync flag for agent_metadata to 1")));
}

TEST_F(AgentInfoHandshakeTest, LiveHandshakeQueryFailure_KeepsLastKnownValue)
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

    // First cycle succeeds with "stable_cluster"; second cycle fails the live query
    // (e.g. agentd transiently unreachable) — cluster_name must not blank out.
    int callCount = 0;
    handshake_query_callback_t handshakeFunc =
        [&callCount](char* clusterName, size_t clusterNameSize, char* clusterNode, size_t clusterNodeSize,
                     char* agentGroups, size_t agentGroupsSize) -> bool
    {
        ++callCount;

        if (callCount == 1)
        {
            writeField(clusterName, clusterNameSize, "stable_cluster");
            writeField(clusterNode, clusterNodeSize, "node01");
            writeField(agentGroups, agentGroupsSize, "");
            return true;
        }

        return false;
    };

    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      m_reportDiffFunc,
                      m_logFunc,
                      m_queryModuleFunc,
                      nullptr,
                      m_mockSysInfo,
                      m_mockFileIO,
                      m_mockFileSystem,
                      handshakeFunc
                  );

    runSingleIteration();
    m_logOutput.clear();

    // Live query fails on the second cycle: no cluster_name/cluster_node change should
    // be detected (falls back to the cached getter, which the mock keeps at defaults).
    runSingleIteration();

    EXPECT_EQ(callCount, 2);
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Live handshake query failed, falling back to last known values"));
    EXPECT_THAT(m_logOutput, ::testing::Not(::testing::HasSubstr("Set sync flag for agent_groups to 1")));
    EXPECT_THAT(m_logOutput, ::testing::Not(::testing::HasSubstr("Set sync flag for agent_metadata to 1")));
}

TEST_F(AgentInfoHandshakeTest, NoHandshakeCallback_FallsBackToCachedGetters)
{
    // Regression guard: constructing AgentInfoImpl without the 9th argument (as every
    // pre-existing test does) must behave exactly as before — no live query attempted.
    setupDefaultMocks();

    nlohmann::json osData =
    {
        {"os_name", "TestOS"}, {"architecture", "x86_64"}, {"os_type", "linux"},
        {"os_platform", "ubuntu"}, {"os_version", "22.04"}, {"hostname", "test-host"}
    };

    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

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

    runSingleIteration();

    EXPECT_THAT(m_logOutput, ::testing::Not(::testing::HasSubstr("Live handshake query failed")));
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent metadata populated successfully"));
}
