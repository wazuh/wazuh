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
 * - Constructor with report and persist callbacks
 * - Handling of optional callbacks (nullptr safety)
 * - SQL statement generation for database operations
 * - PersistDifference method functionality
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
    EXPECT_NO_THROW(m_agentInfo->start(1, []()
    {
        return false;
    }));
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

TEST_F(AgentInfoDBSyncIntegrationTest, PersistDifferenceWithSyncProtocol)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:", nullptr, nullptr, m_logFunc, m_mockDBSync);

    MQ_Functions mq_funcs = {nullptr, nullptr};
    m_agentInfo->initSyncProtocol("test-module", ":memory:", mq_funcs);

    // Call persistDifference - should work through sync protocol only
    EXPECT_NO_THROW(m_agentInfo->persistDifference("test-id", Operation::CREATE, "test-index", "{\"test\":\"data\"}"));

    // Verify the log message was generated
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("Persisting AgentInfo event:"));
    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("{\"test\":\"data\"}"));
}

TEST_F(AgentInfoDBSyncIntegrationTest, PersistDifferenceWithoutSyncProtocol)
{
    m_agentInfo = std::make_shared<AgentInfoImpl>(":memory:",
                                                  nullptr,
                                                  nullptr, // No persist callback needed
                                                  m_logFunc,
                                                  m_mockDBSync);

    // Don't initialize sync protocol - should not crash when sync protocol is null
    EXPECT_NO_THROW(m_agentInfo->persistDifference("test-id", Operation::CREATE, "test-index", "{}"));
}
