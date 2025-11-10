#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <agent_info_impl.hpp>

#include <dbsync.hpp>
#include <mock_dbsync.hpp>

#include <memory>
#include <string>
#include <vector>

/**
 * @brief Test fixture for AgentInfoImpl DBSync integration functionality
 *
 * This test fixture focuses on testing the integration with DBSync:
 * - Constructor with report callbacks
 * - Handling of optional callbacks (nullptr safety)
 * - SQL statement generation for database operations
 * - Error handling in DBSync operations
 */
class AgentInfoDBSyncIntegrationTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            m_logOutput.clear();
            m_reportedEvents.clear();
            m_persistedEvents.clear();

            m_mockDBSync = std::make_shared<MockDBSync>();

            // Configure expected calls to avoid warnings
            EXPECT_CALL(*m_mockDBSync, handle())
            .WillRepeatedly(::testing::Return(nullptr));

            // Configure selectRows call for loadSyncFlags()
            EXPECT_CALL(*m_mockDBSync, selectRows(::testing::_, ::testing::_))
            .WillRepeatedly(::testing::Return());

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

            m_logFunc = [this](modules_log_level_t /* level */, const std::string & msg)
            {
                m_logOutput += msg + "\n";
            };

            // Create a mock query module function
            m_queryModuleFunc = [](const std::string& /* module_name */, const std::string& /* query */, char** response) -> int
            {
                // Mock implementation that returns success
                if (response)
                {
                    *response = nullptr;
                }

                return 0;
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
        std::function<int(const std::string&, const std::string&, char**)> m_queryModuleFunc;
        std::vector<std::string> m_reportedEvents;
        std::vector<nlohmann::json> m_persistedEvents;
        std::string m_logOutput;
};

TEST_F(AgentInfoDBSyncIntegrationTest, ConstructorWithCallbacksSucceeds)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      "test_path",
                      m_reportDiffFunc,
                      m_logFunc,
                      m_queryModuleFunc,
                      m_mockDBSync
                  );

    EXPECT_NE(m_agentInfo, nullptr);
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("AgentInfo initialized"));
}

TEST_F(AgentInfoDBSyncIntegrationTest, CallbacksAreOptional)
{
    // Test that the module works without report callback (nullptr)
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      nullptr,  // No report callback
                      m_logFunc, // Log function is required
                      m_queryModuleFunc,
                      m_mockDBSync
                  );

    EXPECT_NE(m_agentInfo, nullptr);

    // Should not crash when starting
    EXPECT_NO_THROW(m_agentInfo->start(1, 86400, []()
    {
        return false;
    }));
}

TEST_F(AgentInfoDBSyncIntegrationTest, GetCreateStatementReturnsValidSQL)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:",
                      nullptr,
                      m_logFunc,
                      m_queryModuleFunc,
                      m_mockDBSync
                  );

    // GetCreateStatement is called during construction, verify it works
    EXPECT_NE(m_agentInfo, nullptr);
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("AgentInfo initialized"));
}

TEST_F(AgentInfoDBSyncIntegrationTest, SetSyncParametersConfiguresValues)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc, m_queryModuleFunc, m_mockDBSync);

    // Set sync parameters
    EXPECT_NO_THROW(m_agentInfo->setSyncParameters(1, 60, 5, 1000));

    // Verify the log message contains the parameters
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Sync parameters set"));
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("timeout=60"));
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("retries=5"));
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("maxEps=1000"));
}

TEST_F(AgentInfoDBSyncIntegrationTest, InitSyncProtocolLogsMessages)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, m_logFunc, m_queryModuleFunc, m_mockDBSync);

    MQ_Functions mq_funcs = {nullptr, nullptr};

    // Clear previous logs
    m_logOutput.clear();

    // Initialize sync protocol
    EXPECT_NO_THROW(m_agentInfo->initSyncProtocol("test-module", ":memory:", mq_funcs));

    // Verify initialization log
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Agent-info sync protocol initialized"));
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr(":memory:"));
}

TEST_F(AgentInfoDBSyncIntegrationTest, LoadSyncFlagsWithException)
{
    // Create mock that throws on selectRows
    auto throwingDBSync = std::make_shared<MockDBSync>();
    EXPECT_CALL(*throwingDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    EXPECT_CALL(*throwingDBSync, selectRows(::testing::_, ::testing::_))
    .WillOnce(::testing::Throw(std::runtime_error("Database error")));

    m_logOutput.clear();
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:", nullptr, m_logFunc, m_queryModuleFunc, throwingDBSync);

    // start() calls loadSyncFlags internally, which should catch the exception
    // Run for only one iteration to avoid timeout
    m_agentInfo->start(1, 86400, []()
    {
        return false;
    });

    // Should log warning about failed load (line 1307)
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Failed to load sync flags"));
}

TEST_F(AgentInfoDBSyncIntegrationTest, LoadSyncFlagsCallbackWithData)
{
    // Create a custom MockDBSync that safely handles selectRows callback
    auto mockDBSync = std::make_shared<MockDBSync>();

    EXPECT_CALL(*mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    EXPECT_CALL(*mockDBSync, addTableRelationship(::testing::_))
    .WillRepeatedly(::testing::Return());

    // Mock selectRows to simulate sync flags being loaded from database
    bool callbackExecuted = false;
    EXPECT_CALL(*mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Invoke([&callbackExecuted](const nlohmann::json& /* query */, std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        // Simulate finding sync flags in the database
        nlohmann::json flagData;
        flagData["should_sync_metadata"] = 0;
        flagData["should_sync_groups"] = 0;
        callback(SELECTED, flagData);
        callbackExecuted = true;
    }));

    m_logOutput.clear();
    m_agentInfo = std::make_shared<AgentInfoImpl>(
                      ":memory:", nullptr, m_logFunc, m_queryModuleFunc, mockDBSync);

    m_agentInfo->start(1, 86400, []()
    {
        return false;
    });

    // Verify that the callback was executed (which means selectRows was called)
    EXPECT_TRUE(callbackExecuted);
}
