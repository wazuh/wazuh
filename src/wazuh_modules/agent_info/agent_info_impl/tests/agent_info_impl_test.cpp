#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <agent_info_impl.hpp>

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

            // Create the logging function to capture log messages
            m_logFunction = [this](const modules_log_level_t /* level */, const std::string & log)
            {
                m_logOutput += log;
                m_logOutput += "\n";
            };

            m_mockDBSync = std::make_shared<MockDBSync>();
            m_agentInfo = std::make_shared<AgentInfoImpl>("test_path", nullptr, nullptr, m_logFunction, m_mockDBSync);
        }

        void TearDown() override
        {
            // Explicitly reset to ensure proper cleanup order
            m_agentInfo.reset();
            m_mockDBSync.reset();
        }

        std::shared_ptr<IDBSync> m_mockDBSync = nullptr;
        std::shared_ptr<AgentInfoImpl> m_agentInfo = nullptr;
        std::function<void(const modules_log_level_t, const std::string&)> m_logFunction;
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
    auto agentInfo = std::make_shared<AgentInfoImpl>("test_path", nullptr, nullptr, m_logFunction, m_mockDBSync, mockSysInfo);

    EXPECT_NE(agentInfo, nullptr);
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("AgentInfo initialized"));
}

TEST_F(AgentInfoImplTest, ConstructorWithDefaultDependenciesSucceeds)
{
    m_logOutput.clear();

    // Create AgentInfoImpl without passing dbSync or sysInfo (creates defaults)
    // Using in-memory database to avoid file I/O in tests
    auto agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, nullptr, m_logFunction);

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

// ============================================================================
// Tests for DBSync integration (updateChanges, processEvent, notifyChange)
// ============================================================================

class AgentInfoDBSyncIntegrationTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            m_logOutput.clear();
            m_reportedEvents.clear();
            m_persistedEvents.clear();

            m_mockDBSync = std::make_shared<MockDBSync>();

            // Set up callbacks to capture events
            m_reportDiffFunc = [this](const std::string & event)
            {
                m_reportedEvents.push_back(event);
            };

            m_persistDiffFunc = [this](const std::string & id, Operation op, const std::string & index, const std::string & data)
            {
                nlohmann::json persistedEvent;
                persistedEvent["id"] = id;
                persistedEvent["operation"] = static_cast<int>(op);
                persistedEvent["index"] = index;
                persistedEvent["data"] = nlohmann::json::parse(data);
                m_persistedEvents.push_back(persistedEvent);
            };

            m_logFunc = [this](modules_log_level_t level, const std::string & msg)
            {
                m_logOutput += msg + "\n";
            };
        }

        void TearDown() override
        {
            m_agentInfo.reset();
            m_mockDBSync.reset();
        }

        std::shared_ptr<MockDBSync> m_mockDBSync;
        std::shared_ptr<AgentInfoImpl> m_agentInfo;
        std::function<void(const std::string&)> m_reportDiffFunc;
        std::function<void(const std::string&, Operation, const std::string&, const std::string&)> m_persistDiffFunc;
        std::function<void(modules_log_level_t, const std::string&)> m_logFunc;
        std::vector<std::string> m_reportedEvents;
        std::vector<nlohmann::json> m_persistedEvents;
        std::string m_logOutput;
};

TEST_F(AgentInfoDBSyncIntegrationTest, ConstructorWithCallbacksSucceeds)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      "test_path",
                      m_reportDiffFunc,
                      m_persistDiffFunc,
                      m_logFunc,
                      m_mockDBSync
                  );

    EXPECT_NE(m_agentInfo, nullptr);
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("AgentInfo initialized"));
}

TEST_F(AgentInfoDBSyncIntegrationTest, CallbacksAreOptional)
{
    // Test that the module works without report and persist callbacks (nullptr)
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      nullptr,  // No report callback
                      nullptr,  // No persist callback
                      m_logFunc, // Log function is required
                      m_mockDBSync
                  );

    EXPECT_NE(m_agentInfo, nullptr);

    // Should not crash when starting
    EXPECT_NO_THROW(m_agentInfo->start());
}

TEST_F(AgentInfoDBSyncIntegrationTest, GetCreateStatementReturnsValidSQL)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      nullptr,
                      nullptr,
                      m_logFunc,
                      m_mockDBSync
                  );

    // GetCreateStatement is called during construction, verify it works
    EXPECT_NE(m_agentInfo, nullptr);
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("AgentInfo initialized"));
}

TEST_F(AgentInfoDBSyncIntegrationTest, PersistDifferenceWithCallback)
{
    bool callbackInvoked = false;
    std::string capturedId;
    Operation capturedOp;
    std::string capturedIndex;
    std::string capturedData;

    auto persistFunc = [&](const std::string & id, Operation op, const std::string & index, const std::string & data)
    {
        callbackInvoked = true;
        capturedId = id;
        capturedOp = op;
        capturedIndex = index;
        capturedData = data;
    };

    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      nullptr,
                      persistFunc,
                      m_logFunc,
                      m_mockDBSync
                  );

    // Call persistDifference
    m_agentInfo->persistDifference("test-id", Operation::CREATE, "test-index", "{\"test\":\"data\"}");

    EXPECT_TRUE(callbackInvoked);
    EXPECT_EQ(capturedId, "test-id");
    EXPECT_EQ(capturedOp, Operation::CREATE);
    EXPECT_EQ(capturedIndex, "test-index");
    EXPECT_EQ(capturedData, "{\"test\":\"data\"}");
}

TEST_F(AgentInfoDBSyncIntegrationTest, PersistDifferenceWithoutCallback)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      nullptr,
                      nullptr,  // No persist callback
                      m_logFunc,
                      m_mockDBSync
                  );

    // Should not crash when persist callback is null
    EXPECT_NO_THROW(m_agentInfo->persistDifference("test-id", Operation::CREATE, "test-index", "{}"));
}

// ============================================================================
// Tests for DBSync event processing (processEvent, notifyChange)
// ============================================================================

class AgentInfoEventProcessingTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            m_logOutput.clear();
            m_reportedEvents.clear();
            m_persistedEvents.clear();

            m_mockDBSync = std::make_shared<MockDBSync>();
            m_mockSysInfo = std::make_shared<MockSysInfo>();
            m_mockFileIO = std::make_shared<MockFileIOUtils>();
            m_mockFileSystem = std::make_shared<MockFileSystemWrapper>();

            // Set up callbacks to capture events
            m_reportDiffFunc = [this](const std::string & event)
            {
                m_reportedEvents.push_back(nlohmann::json::parse(event));
            };

            m_persistDiffFunc = [this](const std::string & id, Operation op, const std::string & index, const std::string & data)
            {
                nlohmann::json persistedEvent;
                persistedEvent["id"] = id;
                persistedEvent["operation"] = static_cast<int>(op);
                persistedEvent["index"] = index;
                persistedEvent["data"] = nlohmann::json::parse(data);
                m_persistedEvents.push_back(persistedEvent);
            };

            m_logFunc = [this](modules_log_level_t level, const std::string & msg)
            {
                m_logOutput += msg + "\n";
            };
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
        std::function<void(const std::string&)> m_reportDiffFunc;
        std::function<void(const std::string&, Operation, const std::string&, const std::string&)> m_persistDiffFunc;
        std::function<void(modules_log_level_t, const std::string&)> m_logFunc;
        std::vector<nlohmann::json> m_reportedEvents;
        std::vector<nlohmann::json> m_persistedEvents;
        std::string m_logOutput;
};

TEST_F(AgentInfoEventProcessingTest, ProcessInsertedEvent)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      m_reportDiffFunc,
                      m_persistDiffFunc,
                      m_logFunc,
                      m_mockDBSync
                  );

    // Create test data for agent_metadata insertion
    nlohmann::json testData;
    testData["agent_id"] = "001";
    testData["agent_name"] = "test-agent";
    testData["agent_version"] = "4.5.0";
    testData["host_architecture"] = "x86_64";
    testData["host_hostname"] = "test-host";
    testData["host_os_name"] = "Ubuntu";
    testData["host_os_type"] = "Linux";
    testData["host_os_platform"] = "ubuntu";
    testData["host_os_version"] = "22.04";
    testData["checksum"] = "abc123";

    // Process the event
    m_agentInfo->processEvent(INSERTED, testData, "agent_metadata");

    // Verify report callback was invoked
    ASSERT_EQ(m_reportedEvents.size(), 1);
    EXPECT_EQ(m_reportedEvents[0]["module"], "agent_info");
    EXPECT_EQ(m_reportedEvents[0]["type"], "agent_metadata");
    EXPECT_EQ(m_reportedEvents[0]["data"]["event"]["type"], "created");
    EXPECT_EQ(m_reportedEvents[0]["data"]["agent"]["id"], "001");
    EXPECT_EQ(m_reportedEvents[0]["data"]["agent"]["name"], "test-agent");
    EXPECT_FALSE(m_reportedEvents[0]["data"].contains("checksum")); // Checksum should be removed

    // Verify persist callback was invoked
    ASSERT_EQ(m_persistedEvents.size(), 1);
    EXPECT_EQ(m_persistedEvents[0]["operation"], static_cast<int>(Operation::CREATE));
    EXPECT_EQ(m_persistedEvents[0]["index"], "wazuh-states-agent-metadata");
}

TEST_F(AgentInfoEventProcessingTest, ProcessModifiedEvent)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      m_reportDiffFunc,
                      m_persistDiffFunc,
                      m_logFunc,
                      m_mockDBSync
                  );

    // Create test data for agent_metadata modification
    nlohmann::json testData;
    testData["new"]["agent_id"] = "001";
    testData["new"]["agent_name"] = "updated-agent";
    testData["new"]["agent_version"] = "4.5.0";
    testData["new"]["checksum"] = "def456";

    testData["old"]["agent_id"] = "001";
    testData["old"]["agent_name"] = "old-agent";
    testData["old"]["agent_version"] = "4.4.0";
    testData["old"]["checksum"] = "abc123";

    // Process the event
    m_agentInfo->processEvent(MODIFIED, testData, "agent_metadata");

    // Verify report callback was invoked
    ASSERT_EQ(m_reportedEvents.size(), 1);
    EXPECT_EQ(m_reportedEvents[0]["data"]["event"]["type"], "modified");
    EXPECT_EQ(m_reportedEvents[0]["data"]["agent"]["name"], "updated-agent");

    // Verify changed_fields tracking
    EXPECT_TRUE(m_reportedEvents[0]["data"]["event"].contains("changed_fields"));
    auto changedFields = m_reportedEvents[0]["data"]["event"]["changed_fields"];
    EXPECT_FALSE(changedFields.empty());

    // Verify persist callback was invoked
    ASSERT_EQ(m_persistedEvents.size(), 1);
    EXPECT_EQ(m_persistedEvents[0]["operation"], static_cast<int>(Operation::MODIFY));
}

TEST_F(AgentInfoEventProcessingTest, ProcessDeletedEvent)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      m_reportDiffFunc,
                      m_persistDiffFunc,
                      m_logFunc,
                      m_mockDBSync
                  );

    // Create test data for agent_groups deletion
    nlohmann::json testData;
    testData["agent_id"] = "001";
    testData["group_name"] = "removed-group";

    // Process the event
    m_agentInfo->processEvent(DELETED, testData, "agent_groups");

    // Verify report callback was invoked
    ASSERT_EQ(m_reportedEvents.size(), 1);
    EXPECT_EQ(m_reportedEvents[0]["data"]["event"]["type"], "deleted");
    EXPECT_EQ(m_reportedEvents[0]["data"]["agent"]["id"], "001");

    // Verify persist callback was invoked
    ASSERT_EQ(m_persistedEvents.size(), 1);
    EXPECT_EQ(m_persistedEvents[0]["operation"], static_cast<int>(Operation::DELETE_));
    EXPECT_EQ(m_persistedEvents[0]["index"], "wazuh-states-agent-groups");
}

TEST_F(AgentInfoEventProcessingTest, ProcessAgentGroupsEvent)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      m_reportDiffFunc,
                      m_persistDiffFunc,
                      m_logFunc,
                      m_mockDBSync
                  );

    // Create test data for agent_groups
    nlohmann::json testData;
    testData["agent_id"] = "002";
    testData["group_name"] = "web-servers";

    // Process the event
    m_agentInfo->processEvent(INSERTED, testData, "agent_groups");

    // Verify ECS format for groups
    ASSERT_EQ(m_reportedEvents.size(), 1);
    EXPECT_EQ(m_reportedEvents[0]["data"]["agent"]["id"], "002");
    EXPECT_TRUE(m_reportedEvents[0]["data"]["agent"]["groups"].is_array());
    EXPECT_EQ(m_reportedEvents[0]["data"]["agent"]["groups"][0], "web-servers");
}

TEST_F(AgentInfoEventProcessingTest, ProcessEventWithExceptionInCallback)
{
    // Create a callback that throws an exception
    auto throwingReportFunc = [](const std::string& /* event */)
    {
        throw std::runtime_error("Test exception in report callback");
    };

    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      throwingReportFunc,
                      m_persistDiffFunc,
                      m_logFunc,
                      m_mockDBSync
                  );

    nlohmann::json testData;
    testData["agent_id"] = "001";
    testData["agent_name"] = "test";
    testData["checksum"] = "abc";

    // Process event - exception should be caught and logged
    EXPECT_NO_THROW(m_agentInfo->processEvent(INSERTED, testData, "agent_metadata"));

    // Verify error was logged
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Error processing event"));
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Test exception in report callback"));
}

TEST_F(AgentInfoEventProcessingTest, NotifyChangeCallsProcessEvent)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      m_reportDiffFunc,
                      m_persistDiffFunc,
                      m_logFunc,
                      m_mockDBSync
                  );

    nlohmann::json testData;
    testData["agent_id"] = "001";
    testData["agent_name"] = "test-agent";
    testData["checksum"] = "abc";

    // Call notifyChange (which should call processEvent)
    m_agentInfo->notifyChange(INSERTED, testData, "agent_metadata");

    // Verify event was processed
    ASSERT_EQ(m_reportedEvents.size(), 1);
    EXPECT_EQ(m_reportedEvents[0]["module"], "agent_info");
}

// ============================================================================
// Tests for helper functions (calculateMetadataChecksum, calculateHashId, ecsData)
// ============================================================================

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

// ============================================================================
// Tests for logging with m_logFunction callback
// ============================================================================

class AgentInfoLoggingTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            m_logMessages.clear();

            m_mockDBSync = std::make_shared<MockDBSync>();
            m_mockSysInfo = std::make_shared<MockSysInfo>();
            m_mockFileIO = std::make_shared<MockFileIOUtils>();
            m_mockFileSystem = std::make_shared<MockFileSystemWrapper>();

            m_logFunc = [this](modules_log_level_t level, const std::string & msg)
            {
                m_logMessages.push_back({level, msg});
            };
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
        std::function<void(modules_log_level_t, const std::string&)> m_logFunc;
        std::vector<std::pair<modules_log_level_t, std::string>> m_logMessages;
        std::string m_logOutput;
};

TEST_F(AgentInfoLoggingTest, PopulateMetadataUsesLogFunction)
{
    // Setup: Mock client.keys and merged.mg
    EXPECT_CALL(*m_mockFileSystem, exists(::testing::_))
    .WillOnce(::testing::Return(true))
    .WillOnce(::testing::Return(true));

    EXPECT_CALL(*m_mockFileIO, readLineByLine(::testing::_, ::testing::_))
    .WillOnce(::testing::Invoke([](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        callback("001 test-agent 192.168.1.1 key");
    }))
    .WillOnce(::testing::Invoke([](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        callback("#group: test-group");
    }));

    nlohmann::json osData = {{"os_name", "Ubuntu"}};
    EXPECT_CALL(*m_mockSysInfo, os()).WillOnce(::testing::Return(osData));

    EXPECT_CALL(*m_mockDBSync, handle()).WillRepeatedly(::testing::Return(nullptr));

    // Create agent info with m_logFunc
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      "test_path",
                      nullptr,
                      nullptr,
                      m_logFunc,  // Use log function
                      m_mockDBSync,
                      m_mockSysInfo,
                      m_mockFileIO,
                      m_mockFileSystem
                  );

    m_agentInfo->start();

    // Verify log function was called
    bool foundMetadataLog = false;
    bool foundGroupsLog = false;

    for (const auto& [level, msg] : m_logMessages)
    {
        if (msg.find("Agent metadata populated successfully") != std::string::npos)
        {
            foundMetadataLog = true;
            EXPECT_EQ(level, LOG_INFO);
        }

        if (msg.find("Agent groups populated successfully") != std::string::npos)
        {
            foundGroupsLog = true;
            EXPECT_EQ(level, LOG_INFO);
        }
    }

    EXPECT_TRUE(foundMetadataLog);
    EXPECT_TRUE(foundGroupsLog);
}

TEST_F(AgentInfoLoggingTest, UpdateChangesErrorUsesLogFunction)
{
    // Create a mock that will cause updateChanges to fail
    EXPECT_CALL(*m_mockDBSync, handle())
    .WillRepeatedly(::testing::Throw(std::runtime_error("DBSync error")));

    EXPECT_CALL(*m_mockFileSystem, exists(::testing::_))
    .WillRepeatedly(::testing::Return(false));

    EXPECT_CALL(*m_mockSysInfo, os())
    .WillRepeatedly(::testing::Return(nlohmann::json()));

    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      "test_path",
                      nullptr,
                      nullptr,
                      m_logFunc,
                      m_mockDBSync,
                      m_mockSysInfo,
                      m_mockFileIO,
                      m_mockFileSystem
                  );

    // Start will trigger updateChanges which will fail
    m_agentInfo->start();

    // Verify error was logged via m_logFunction
    bool foundError = false;

    for (const auto& [level, msg] : m_logMessages)
    {
        if (msg.find("Error updating changes") != std::string::npos)
        {
            foundError = true;
            EXPECT_EQ(level, LOG_ERROR);
        }
    }

    EXPECT_TRUE(foundError);
}

TEST_F(AgentInfoLoggingTest, ProcessEventDebugUsesLogFunction)
{
    auto reportFunc = [](const std::string& /* event */) {};

    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      reportFunc,
                      nullptr,
                      m_logFunc,
                      m_mockDBSync
                  );

    nlohmann::json testData;
    testData["agent_id"] = "001";
    testData["agent_name"] = "test";
    testData["checksum"] = "abc";

    m_agentInfo->processEvent(INSERTED, testData, "agent_metadata");

    // Verify debug message was logged
    bool foundDebug = false;

    for (const auto& [level, msg] : m_logMessages)
    {
        if (msg.find("Event reported for table") != std::string::npos)
        {
            foundDebug = true;
            EXPECT_EQ(level, LOG_DEBUG_VERBOSE);
        }
    }

    EXPECT_TRUE(foundDebug);
}

TEST_F(AgentInfoLoggingTest, ProcessEventErrorUsesLogFunction)
{
    // Create a callback that throws
    auto throwingReportFunc = [](const std::string& /* event */)
    {
        throw std::runtime_error("Report callback error");
    };

    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      throwingReportFunc,
                      nullptr,
                      m_logFunc,
                      m_mockDBSync
                  );

    nlohmann::json testData;
    testData["agent_id"] = "001";
    testData["checksum"] = "abc";

    m_agentInfo->processEvent(INSERTED, testData, "agent_metadata");

    // Verify error was logged
    bool foundError = false;

    for (const auto& [level, msg] : m_logMessages)
    {
        if (msg.find("Error processing event") != std::string::npos)
        {
            foundError = true;
            EXPECT_EQ(level, LOG_ERROR);
        }
    }

    EXPECT_TRUE(foundError);
}

// ============================================================================
// Integration test with real DBSync to cover updateChanges via start()
// ============================================================================

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

    m_agentInfo->start();

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
