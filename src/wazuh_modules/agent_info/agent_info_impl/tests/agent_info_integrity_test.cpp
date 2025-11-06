#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <agent_info_impl.hpp>
#include <agent_sync_protocol.hpp>

#include <mock_dbsync.hpp>
#include <mock_file_io_utils.hpp>
#include <mock_filesystem_wrapper.hpp>
#include <mock_sysinfo.hpp>

#include <memory>
#include <string>
#include <chrono>

/**
 * @brief Test fixture for AgentInfoImpl integrity check functionality
 *
 * Tests the integrity check operations:
 * - Integrity interval configuration
 * - Periodic integrity check execution
 * - Timestamp tracking in database
 * - synchronizeMetadataOrGroups with CHECK modes
 */
class AgentInfoIntegrityTest : public ::testing::Test
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

            m_mockDBSync = std::make_shared<MockDBSync>();
            m_mockFileSystem = std::make_shared<MockFileSystemWrapper>();
            m_mockFileIO = std::make_shared<MockFileIOUtils>();
            m_mockSysInfo = std::make_shared<MockSysInfo>();

            EXPECT_CALL(*m_mockDBSync, handle())
            .WillRepeatedly(::testing::Return(nullptr));
        }

        void TearDown() override
        {
            m_agentInfo.reset();
            m_mockDBSync.reset();
            m_mockFileSystem.reset();
            m_mockFileIO.reset();
            m_mockSysInfo.reset();
        }

        MQ_Functions createMockMQFunctions()
        {
            MQ_Functions mqFuncs;

            mqFuncs.start = [](const char* /* key */, short /* type */, short /* attempts */) -> int
            {
                return 1;
            };

            mqFuncs.send_binary = [](int /* queue */, const void* /* message */, size_t /* message_len */,
                                     const char* /* locmsg */, char /* loc */) -> int
            {
                return 0;
            };

            return mqFuncs;
        }

        std::shared_ptr<AgentInfoImpl> m_agentInfo;
        std::shared_ptr<MockDBSync> m_mockDBSync;
        std::shared_ptr<MockFileSystemWrapper> m_mockFileSystem;
        std::shared_ptr<MockFileIOUtils> m_mockFileIO;
        std::shared_ptr<MockSysInfo> m_mockSysInfo;
        std::function<void(const std::string&)> m_reportDiffFunc;
        std::function<void(modules_log_level_t, const std::string&)> m_logFunc;
        std::vector<std::string> m_reportedEvents;
        std::string m_logOutput;
};

TEST_F(AgentInfoIntegrityTest, StartLogsIntegrityInterval)
{
    // Mock selectRows to return last integrity time from 2 seconds ago (to trigger check)
    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Invoke([](const nlohmann::json& /* query */, std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        auto now = std::chrono::system_clock::now();
        auto twoSecondsAgo = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count() - 2;

        nlohmann::json data;
        data["should_sync_metadata"] = 0;
        data["should_sync_groups"] = 0;
        data["last_metadata_integrity"] = twoSecondsAgo;
        data["last_groups_integrity"] = twoSecondsAgo;
        callback(SELECTED, data);
    }));

    auto queryModuleFunc = [](const std::string& /* module_name */, const std::string& /* query */, char** response) -> int
    {
        if (response)
        {
            *response = nullptr;
        }

        return 0;
    };

    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      m_reportDiffFunc,
                      m_logFunc,
                      queryModuleFunc,
                      m_mockDBSync,
                      m_mockSysInfo,
                      m_mockFileIO,
                      m_mockFileSystem
                  );

    m_logOutput.clear();
    m_agentInfo->start(60, 86400, []()
    {
        return false;
    });

    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("AgentInfo module started"));
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("interval: 60 seconds"));
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("integrity interval: 86400 seconds"));
}

TEST_F(AgentInfoIntegrityTest, IntegrityCheckSkippedWithoutSyncProtocol)
{
    // Mock selectRows to return last integrity time from 2 seconds ago (to trigger check)
    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Invoke([](const nlohmann::json& /* query */, std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        auto now = std::chrono::system_clock::now();
        auto twoSecondsAgo = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count() - 2;

        nlohmann::json data;
        data["should_sync_metadata"] = 0;
        data["should_sync_groups"] = 0;
        data["last_metadata_integrity"] = twoSecondsAgo;
        data["last_groups_integrity"] = twoSecondsAgo;
        callback(SELECTED, data);
    }));

    EXPECT_CALL(*m_mockFileSystem, exists(::testing::_))
    .WillRepeatedly(::testing::Return(false));

    auto queryModuleFunc = [](const std::string& /* module_name */, const std::string& /* query */, char** response) -> int
    {
        if (response)
        {
            *response = nullptr;
        }

        return 0;
    };

    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      m_reportDiffFunc,
                      m_logFunc,
                      queryModuleFunc,
                      m_mockDBSync,
                      m_mockSysInfo,
                      m_mockFileIO,
                      m_mockFileSystem
                  );

    m_logOutput.clear();

    // Use very short integrity interval (1 second) to trigger check
    m_agentInfo->start(1, 1, []()
    {
        return false;
    });

    // Should see warning about sync protocol not being available
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Sync protocol not available, skipping integrity check"));
}

TEST_F(AgentInfoIntegrityTest, IntegrityCheckTriggeredWhenIntervalElapsed)
{
    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(reinterpret_cast<void*>(0x1)));

    EXPECT_CALL(*m_mockDBSync, addTableRelationship(::testing::_))
    .WillRepeatedly(::testing::Return());

    // Mock selectRows to return last integrity time from 2 seconds ago (to trigger check)
    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Invoke([](const nlohmann::json& /* query */, std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        auto now = std::chrono::system_clock::now();
        auto twoSecondsAgo = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count() - 2;

        nlohmann::json data;
        data["should_sync_metadata"] = 0;
        data["should_sync_groups"] = 0;
        data["last_metadata_integrity"] = twoSecondsAgo;
        data["last_groups_integrity"] = twoSecondsAgo;
        callback(SELECTED, data);
    }));

    auto queryModuleFunc = [](const std::string& /* module_name */, const std::string& /* query */, char** response) -> int
    {
        if (response)
        {
            *response = nullptr;
        }

        return 0;
    };

    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      m_reportDiffFunc,
                      m_logFunc,
                      queryModuleFunc,
                      m_mockDBSync,
                      m_mockSysInfo,
                      m_mockFileIO,
                      m_mockFileSystem
                  );

    m_agentInfo->setSyncParameters(1, 1, 1, 1000);

    MQ_Functions mqFuncs = createMockMQFunctions();
    m_agentInfo->initSyncProtocol("test_module", ":memory:", mqFuncs);

    EXPECT_CALL(*m_mockFileSystem, exists(::testing::_))
    .WillRepeatedly(::testing::Return(true));

    EXPECT_CALL(*m_mockFileIO, readLineByLine(::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Invoke([](const std::filesystem::path & path, const std::function<bool(const std::string&)>& callback)
    {
        std::string pathStr = path.string();

        if (pathStr.find("client.keys") != std::string::npos)
        {
            callback("123 test-agent 10.0.0.1 key");
        }
    }));

    nlohmann::json osData = {{"os_name", "TestOS"}, {"architecture", "test64"}};
    EXPECT_CALL(*m_mockSysInfo, os())
    .WillRepeatedly(::testing::Return(osData));

    m_agentInfo->setIsAgent(true);

    m_logOutput.clear();

    // Use very short integrity interval (1 second) to trigger check immediately
    m_agentInfo->start(1, 1, []()
    {
        return false;
    });

    // Should see integrity check being initiated
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Starting integrity check"));
}

TEST_F(AgentInfoIntegrityTest, IntegrityCheckRunsAfterDeltaSyncCompletes)
{
    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(reinterpret_cast<void*>(0x1)));

    EXPECT_CALL(*m_mockDBSync, addTableRelationship(::testing::_))
    .WillRepeatedly(::testing::Return());

    // Mock selectRows to return sync flags set (delta sync needed)
    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Invoke([](const nlohmann::json& /* query */, std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        nlohmann::json data;
        data["should_sync_metadata"] = 1; // Delta sync needed
        data["should_sync_groups"] = 0;
        data["last_metadata_integrity"] = 0;
        data["last_groups_integrity"] = 0;
        callback(SELECTED, data);
    }));

    auto queryModuleFunc = [](const std::string& /* module_name */, const std::string& /* query */, char** response) -> int
    {
        if (response)
        {
            nlohmann::json responseJson;
            responseJson["error"] = 50; // Module unavailable
            std::string responseStr = responseJson.dump();
            *response = strdup(responseStr.c_str());
        }

        return 0;
    };

    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      m_reportDiffFunc,
                      m_logFunc,
                      queryModuleFunc,
                      m_mockDBSync,
                      m_mockSysInfo,
                      m_mockFileIO,
                      m_mockFileSystem
                  );

    m_agentInfo->setSyncParameters(1, 1, 0, 1000);

    MQ_Functions mqFuncs = createMockMQFunctions();
    m_agentInfo->initSyncProtocol("test_module", ":memory:", mqFuncs);

    EXPECT_CALL(*m_mockFileSystem, exists(::testing::_))
    .WillRepeatedly(::testing::Return(true));

    EXPECT_CALL(*m_mockFileIO, readLineByLine(::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Invoke([](const std::filesystem::path & path, const std::function<bool(const std::string&)>& callback)
    {
        std::string pathStr = path.string();

        if (pathStr.find("client.keys") != std::string::npos)
        {
            callback("123 test-agent 10.0.0.1 key");
        }
    }));

    nlohmann::json osData = {{"os_name", "TestOS"}, {"architecture", "test64"}};
    EXPECT_CALL(*m_mockSysInfo, os())
    .WillRepeatedly(::testing::Return(osData));

    m_agentInfo->setIsAgent(true);

    m_logOutput.clear();

    // Short integrity interval, but delta sync is pending
    m_agentInfo->start(1, 1, []()
    {
        return false;
    });

    // Should see delta coordination first (no modules available = success)
    // Delta sync initializes the integrity timestamp, but check won't run until next iteration
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Synchronization needed for agent_metadata"));
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Successfully coordinated agent_metadata"));
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Initialized integrity check timestamp for agent_metadata"));
    // Integrity check doesn't run in same iteration - it will run after interval elapses in future iterations
    EXPECT_THAT(m_logOutput, ::testing::Not(::testing::HasSubstr("Starting integrity check")));
}

TEST_F(AgentInfoIntegrityTest, IntegrityCheckForBothMetadataAndGroups)
{
    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Return(reinterpret_cast<void*>(0x1)));

    EXPECT_CALL(*m_mockDBSync, addTableRelationship(::testing::_))
    .WillRepeatedly(::testing::Return());

    // Mock selectRows to return last integrity time from 2 seconds ago (to trigger check)
    EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Invoke([](const nlohmann::json& /* query */, std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        auto now = std::chrono::system_clock::now();
        auto twoSecondsAgo = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count() - 2;

        nlohmann::json data;
        data["should_sync_metadata"] = 0;
        data["should_sync_groups"] = 0;
        data["last_metadata_integrity"] = twoSecondsAgo;
        data["last_groups_integrity"] = twoSecondsAgo;
        callback(SELECTED, data);
    }));

    auto queryModuleFunc = [](const std::string& /* module_name */, const std::string& /* query */, char** response) -> int
    {
        if (response)
        {
            *response = nullptr;
        }

        return 0;
    };

    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      m_reportDiffFunc,
                      m_logFunc,
                      queryModuleFunc,
                      m_mockDBSync,
                      m_mockSysInfo,
                      m_mockFileIO,
                      m_mockFileSystem
                  );

    m_agentInfo->setSyncParameters(1, 1, 1, 1000);

    MQ_Functions mqFuncs = createMockMQFunctions();
    m_agentInfo->initSyncProtocol("test_module", ":memory:", mqFuncs);

    EXPECT_CALL(*m_mockFileSystem, exists(::testing::_))
    .WillRepeatedly(::testing::Return(true));

    EXPECT_CALL(*m_mockFileIO, readLineByLine(::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Invoke([](const std::filesystem::path & path, const std::function<bool(const std::string&)>& callback)
    {
        std::string pathStr = path.string();

        if (pathStr.find("client.keys") != std::string::npos)
        {
            callback("123 test-agent 10.0.0.1 key");
        }
    }));

    nlohmann::json osData = {{"os_name", "TestOS"}, {"architecture", "test64"}};
    EXPECT_CALL(*m_mockSysInfo, os())
    .WillRepeatedly(::testing::Return(osData));

    m_agentInfo->setIsAgent(true);

    m_logOutput.clear();

    // Use very short integrity interval to trigger both checks
    m_agentInfo->start(1, 1, []()
    {
        return false;
    });

    // Should see integrity checks for both metadata and groups
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Starting integrity check for agent_metadata"));
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Starting integrity check for agent_groups"));
}
