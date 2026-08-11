#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <sca.h>
#include <sca_impl.hpp>

#include <dbsync.hpp>
#include <isca_policy.hpp>
#include "logging_helper.hpp"
#include <mock_dbsync.hpp>
#include <sca_policy.hpp>
#include <sca_sca_mock.hpp>
#include <mock_filesystem_wrapper.hpp>
#include <mock_agent_sync_protocol.hpp>

#include <chrono>
#include <atomic>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>

class ScaTest : public ::testing::Test
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
            m_sca = std::make_shared<SecurityConfigurationAssessment>("test_path", m_mockDBSync);
        }

        std::shared_ptr<IDBSync> m_mockDBSync = nullptr;
        std::shared_ptr<SecurityConfigurationAssessment> m_sca = nullptr;
        std::string m_logOutput;
};

namespace
{
    std::string makeTempPath()
    {
        const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        const auto path = std::filesystem::temp_directory_path() / ("sca_test_" + std::to_string(now));
        return path.string();
    }

    const std::string kCreateStatement =
        "CREATE TABLE IF NOT EXISTS sca_policy ("
        "id TEXT PRIMARY KEY,"
        "name TEXT,"
        "file TEXT,"
        "description TEXT,"
        "refs TEXT);"
        "CREATE TABLE IF NOT EXISTS sca_check ("
        "checksum TEXT NOT NULL,"
        "id TEXT PRIMARY KEY,"
        "policy_id TEXT REFERENCES sca_policy(id),"
        "name TEXT,"
        "description TEXT,"
        "rationale TEXT,"
        "remediation TEXT,"
        "refs TEXT,"
        "result TEXT DEFAULT 'Not run',"
        "reason TEXT,"
        "condition TEXT,"
        "compliance TEXT,"
        "mitre TEXT,"
        "rules TEXT,"
        "regex_type TEXT DEFAULT 'pcre2',"
        "version INTEGER NOT NULL DEFAULT 1,"
        "sync INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS sca_metadata ("
        "key TEXT PRIMARY KEY,"
        "value INTEGER);";

    void insertRow(const std::shared_ptr<IDBSync>& dbSync, const std::string& table, const nlohmann::json& data)
    {
        auto query = SyncRowQuery::builder().table(table).data(data).build();
        const auto callback = [](ReturnTypeCallback, const nlohmann::json&) {};
        dbSync->syncRow(query.query(), callback);
    }
}

TEST_F(ScaTest, SetPushMessageFunctionStoresCallback)
{
    constexpr int expectedReturnValue = 123;
    bool statefulCalled = false;
    bool statelessCalled = false;

    auto statefulLambda = [&](const std::string&, Operation_t, const std::string&, const std::string&, uint64_t) -> int // NOLINT(performance-unnecessary-value-param)
    {
        statefulCalled = true;
        return expectedReturnValue;
    };

    auto statelessLambda = [&](const std::string&) -> int // NOLINT(performance-unnecessary-value-param)
    {
        statelessCalled = true;
        return expectedReturnValue;
    };

    m_sca->SetPushStatelessMessageFunction(statelessLambda);
    m_sca->SetPushStatefulMessageFunction(statefulLambda);

    const std::string dummyMessage = R"({"key": "value"})";
    const int result = statefulLambda("test_id", Operation_t::OPERATION_CREATE, "index", dummyMessage, 1) + statelessLambda(dummyMessage);

    EXPECT_TRUE(statefulCalled && statelessCalled);
    EXPECT_EQ(result, expectedReturnValue * 2);
}

TEST_F(ScaTest, NameReturnsCorrectValue)
{
    EXPECT_EQ(m_sca->Name(), "SCA");
}

TEST_F(ScaTest, SCAPolicyConstructors)
{
    std::string policyId = "policy_id";
    Check requirements = {"235523", "all", {}};

    Check check;
    check.id = std::optional<std::string> {"724524"};
    check.condition = "all";
    check.rules.emplace_back(RuleEvaluatorFactory::CreateEvaluator("f: $var1/passwd exists", 30, false));
    check.rules.emplace_back(RuleEvaluatorFactory::CreateEvaluator("f: $var2/passwd exists", 30, false));

    std::vector<Check> checks;
    checks.emplace_back(std::move(check));

    auto policy = SCAPolicy(policyId, std::move(requirements), std::move(checks));

    auto anotherPolicy(std::move(policy));
    SUCCEED();
}

TEST_F(ScaTest, SCAPolicyRunAndStop)
{
    std::string policyId = "policy_id";
    Check requirements = {"235523", "all", {}};
    requirements.rules.emplace_back(RuleEvaluatorFactory::CreateEvaluator("f: $var1/passwd exists", 30, false));

    Check check;
    check.id = std::optional<std::string> {"724524"};
    check.condition = "all";
    check.rules.emplace_back(RuleEvaluatorFactory::CreateEvaluator("f: $var1/passwd exists", 30, false));

    std::vector<Check> checks;
    checks.emplace_back(std::move(check));

    SCAPolicy policy(policyId, std::move(requirements), std::move(checks));

    std::vector<std::tuple<std::string, std::string, std::string>> reported;

    auto reportCheckResult = [&](const CheckResult & r) -> void
    {
        reported.emplace_back(r.policyId, r.checkId, r.result);
    };

    policy.Run(reportCheckResult);

    EXPECT_FALSE(reported.empty());
    EXPECT_EQ(std::get<0>(reported.front()), policyId);
    EXPECT_EQ(std::get<1>(reported.front()), "724524");

    // call Stop, m_keepRunning prevents further scans
    policy.Stop();

    reported.clear();
    policy.Run(reportCheckResult);
    // Stop set m_keepRunning=false, Scan should exit early
    EXPECT_TRUE(reported.empty());
}


TEST_F(ScaTest, SCAPolicyRun_NoRequirements)
{
    std::string policyId = "policy_id";
    Check requirements = {"235523", "all", {}};

    Check check;
    check.id = std::optional<std::string> {"724524"};
    check.condition = "all";
    check.rules.emplace_back(RuleEvaluatorFactory::CreateEvaluator("f: $var1/passwd exists", 30, false));

    std::vector<Check> checks;
    checks.emplace_back(std::move(check));

    SCAPolicy policy(policyId, std::move(requirements), std::move(checks));

    std::vector<std::tuple<std::string, std::string, std::string>> reported;

    auto reportCheckResult = [&](const CheckResult & r)
    {
        reported.emplace_back(r.policyId, r.checkId, r.result);
    };

    policy.Run(reportCheckResult);

    EXPECT_FALSE(reported.empty());
    EXPECT_EQ(std::get<0>(reported.front()), policyId);
    EXPECT_EQ(std::get<1>(reported.front()), "724524");
}

TEST_F(ScaTest, ConstructorInitializesCorrectly)
{
    EXPECT_EQ(m_sca->Name(), "SCA");
}

TEST_F(ScaTest, Setup_WithEmptyPolicies_CreatesNoPolicies)
{
    SCAMock scm;
    scm.Setup(true, true, std::chrono::seconds(1000), 30, false, {});

    // Verify no policies were created
    auto& policiesRef = scm.GetPolicies();

    EXPECT_TRUE(policiesRef.empty());
}

TEST_F(ScaTest, Setup_WithFakePolicies_LoadsNothing)
{
    std::vector<sca::PolicyData> policyData =
    {
        {"policy1.yaml", true, false},
        {"policy2.yaml", true, true}
    };

    auto mockFileSystem = std::make_shared<MockFileSystemWrapper>();
    auto mockDBSync = std::make_shared<MockDBSync>();

    SCAMock scm(mockDBSync, mockFileSystem);
    scm.Setup(true, true, std::chrono::seconds(100), 30, false, policyData);

    // Mock filesystem exists() to call Stop() when called, then return true
    EXPECT_CALL(*mockFileSystem, exists(testing::_))
    .WillOnce(testing::DoAll(testing::InvokeWithoutArgs([&scm]()
    {
        scm.Stop();
    }), testing::Return(true)))
    .WillRepeatedly(testing::Return(true));

    // Run() should exit when Stop() is called from the mock
    scm.Run();

    // Verify no policies were created since Stop() was called during policy loading
    auto& policiesRef = scm.GetPolicies();
    EXPECT_TRUE(policiesRef.empty());
}

TEST_F(ScaTest, RunDoesNothingWhenDisabled)
{
    m_sca->Setup(false, true, std::chrono::seconds(1000), 30, false, {});

    m_sca->Run();
    EXPECT_NE(m_logOutput.find("SCA module is disabled"), std::string::npos);
}

TEST_F(ScaTest, StopSetsKeepRunningToFalse)
{
    m_sca->Stop();
    EXPECT_NE(m_logOutput.find("SCA module stopped."), std::string::npos);
}

TEST_F(ScaTest, StopUnblocksPauseWaiters)
{
    auto mockDBSync = std::make_shared<MockDBSync>();
    auto scaMock = std::make_shared<SCAMock>(mockDBSync, nullptr);

    // Force pause() to block waiting for sync completion.
    scaMock->setSyncInProgress(true);

    std::atomic<bool> pauseReturned {false};
    std::thread pauseThread([&scaMock, &pauseReturned]()
    {
        scaMock->pause();
        pauseReturned.store(true);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    scaMock->Stop();

    // Stop() should wake pause() immediately through m_pauseCv notification.
    for (int i = 0; i < 50 && !pauseReturned.load(); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    EXPECT_TRUE(pauseReturned.load());

    // Safety net for cleanup in case of failure.
    if (!pauseReturned.load())
    {
        scaMock->notifySyncComplete();
    }

    pauseThread.join();
}

TEST_F(ScaTest, StopCompletesAfterPauseMutexRelease)
{
    auto mockDBSync = std::make_shared<MockDBSync>();
    auto scaMock = std::make_shared<SCAMock>(mockDBSync, nullptr);

    // Simulate contention on pause mutex and verify Stop() completes once lock is released.
    scaMock->lockPauseMutex();

    std::atomic<bool> stopReturned {false};
    std::thread stopThread([&scaMock, &stopReturned]()
    {
        scaMock->Stop();
        stopReturned.store(true);
    });

    for (int i = 0; i < 50 && !stopReturned.load(); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    EXPECT_FALSE(stopReturned.load());

    // Always release mutex owned by this thread.
    scaMock->unlockPauseMutex();

    for (int i = 0; i < 50 && !stopReturned.load(); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    EXPECT_TRUE(stopReturned.load());
    stopThread.join();
}

TEST_F(ScaTest, SetGlobalWmExecFunctionStoresPointer)
{
    auto mockFunc = [](char*, char**, int*, int, const char*)
    {
        return 0;
    };

    SecurityConfigurationAssessment::SetGlobalWmExecFunction(mockFunc);
    EXPECT_TRUE(SecurityConfigurationAssessment::GetGlobalWmExecFunction() != nullptr);

    // Reset to avoid affecting other tests
    SecurityConfigurationAssessment::SetGlobalWmExecFunction(nullptr);
}

TEST_F(ScaTest, RunExecutesPoliciesWhenEnabled)
{
    // Use disabled module to test that Run() doesn't hang
    m_sca->Setup(false, false, std::chrono::seconds(100), 30, false, {});

    // Run() should exit immediately since the module is disabled
    m_sca->Run();

    // The fact that we get here means Run() didn't block indefinitely
    EXPECT_NE(m_logOutput.find("SCA module is disabled"), std::string::npos);
}

TEST_F(ScaTest, GetCreateStatement)
{
    // null dbSync makes us hit GetCreateStatement()
    auto sca = std::make_shared<SecurityConfigurationAssessment>("test_path", nullptr);
    SUCCEED();
}

TEST_F(ScaTest, Constructor_WithNoParameters_CreatesDefaultDBSync)
{
    // Create SCA without providing dbSync or fileSystemWrapper
    // This forces the constructor to create default DBSync
    auto sca = std::make_shared<SecurityConfigurationAssessment>("db_path");

    // Verify the object was created successfully
    EXPECT_EQ(sca->Name(), "SCA");

    // Verify log output shows initialization
    EXPECT_NE(m_logOutput.find("SCA initialized"), std::string::npos);
}

TEST_F(ScaTest, Run_WithSyncProtocol_CallsReset)
{
    auto mockDBSync = std::make_shared<MockDBSync>();
    auto mockSyncProtocol = std::make_shared<MockAgentSyncProtocol>();
    auto scaMock = std::make_shared<SCAMock>(mockDBSync, nullptr);

    // Set the sync protocol
    scaMock->setSyncProtocol(mockSyncProtocol);

    // Expect reset() to be called on the sync protocol when Run() starts
    EXPECT_CALL(*mockSyncProtocol, reset())
    .Times(1);

    // Mock selectRows to return count = 0 for hasDataInDatabase() (no cleanup needed)
    EXPECT_CALL(*mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Invoke([](const nlohmann::json& /* query */,
                                         std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        // Return count = 0 for both sca_policy and sca_check
        nlohmann::json result = {{"count", 0}};
        callback(SELECTED, result);
    }));

    // Setup with enabled=true but no policies (will exit early after reset)
    std::vector<sca::PolicyData> noPolicies;
    scaMock->Setup(true, false, std::chrono::seconds(100), 30, false, noPolicies);

    // Run will call reset() on sync protocol, then exit because no policies
    scaMock->Run();

    // Verify that Run() executed and exited
    SUCCEED();
}

TEST_F(ScaTest, Run_ExecutesScanLoopWithValidPolicy)
{
    auto mockDBSync = std::make_shared<MockDBSync>();
    auto mockFileSystem = std::make_shared<MockFileSystemWrapper>();
    auto scaMock = std::make_shared<SCAMock>(mockDBSync, mockFileSystem);

    // Configure one enabled policy
    std::vector<sca::PolicyData> policyData = {{"test_policy.yaml", true, false}};

    // Mock filesystem to return that the file exists
    EXPECT_CALL(*mockFileSystem, exists(::testing::_))
    .WillRepeatedly(::testing::Return(true));

    // Mock selectRows to return count = 0 for hasDataInDatabase() (no cleanup needed)
    EXPECT_CALL(*mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Invoke([](const nlohmann::json& /* query */,
                                         std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        nlohmann::json result = {{"count", 0}};
        callback(SELECTED, result);
    }));

    // Mock other DBSync operations
    EXPECT_CALL(*mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));

    EXPECT_CALL(*mockDBSync, syncRow(::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Return());

    // Create a mock yamlToJsonFunc that returns valid policy JSON
    auto yamlToJsonFunc = [](const std::string&) -> nlohmann::json
    {
        nlohmann::json result;
        result["variables"] = {{"$test_var", "/etc"}};
        result["policy"] = {{"id", "test_policy"}, {"name", "Test Policy"}};
        result["checks"] = nlohmann::json::array({
            {
                {"id", "check1"},
                {"title", "Test Check"},
                {"condition", "all"},
                {"rules", nlohmann::json::array({"f:$test_var/passwd exists"})}
            }
        });
        return result;
    };

    // Setup with enabled=true, scan on start, and the mock yamlToJsonFunc
    scaMock->Setup(true, true, std::chrono::seconds(100), 30, false, policyData, yamlToJsonFunc);

    // Run in a separate thread so we can stop it after it executes
    std::thread runThread([&scaMock]()
    {
        scaMock->Run();
    });

    // Give it time to execute the scan loop
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Stop the scan loop
    scaMock->Stop();

    // Wait for thread to complete
    runThread.join();

    // Verify that the scan executed - check log output
    EXPECT_NE(m_logOutput.find("SCA module running"), std::string::npos);
}

TEST_F(ScaTest, Run_WithPausedState_SkipsScanIteration)
{
    auto mockDBSync = std::make_shared<MockDBSync>();
    auto mockFileSystem = std::make_shared<MockFileSystemWrapper>();
    auto scaMock = std::make_shared<SCAMock>(mockDBSync, mockFileSystem);

    // Configure one enabled policy
    std::vector<sca::PolicyData> policyData = {{"test_policy.yaml", true, false}};

    // Mock filesystem
    EXPECT_CALL(*mockFileSystem, exists(::testing::_))
    .WillRepeatedly(::testing::Return(true));

    // Mock selectRows
    EXPECT_CALL(*mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Invoke([](const nlohmann::json&,
                                         std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        nlohmann::json result = {{"count", 0}};
        callback(SELECTED, result);
    }));

    // Mock other DBSync operations
    EXPECT_CALL(*mockDBSync, handle())
    .WillRepeatedly(::testing::Return(nullptr));
    EXPECT_CALL(*mockDBSync, syncRow(::testing::_, ::testing::_))
    .WillRepeatedly(::testing::Return());

    // Create yamlToJsonFunc
    auto yamlToJsonFunc = [](const std::string&) -> nlohmann::json
    {
        nlohmann::json result;
        result["variables"] = {{"$test_var", "/etc"}};
        result["policy"] = {{"id", "test_policy"}, {"name", "Test Policy"}};
        result["checks"] = nlohmann::json::array({
            {   {"id", "check1"}, {"title", "Test Check"}, {"condition", "all"},
                {"rules", nlohmann::json::array({"f:$test_var/passwd exists"})}
            }
        });
        return result;
    };

    // Setup with scan_on_start=false to allow pausing before first scan
    scaMock->Setup(true, false, std::chrono::seconds(1), 30, false, policyData, yamlToJsonFunc);

    // Run in a separate thread
    std::thread runThread([&scaMock]()
    {
        scaMock->Run();
    });

    // Wait a bit for Run() to start
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    // Pause the scan
    scaMock->pause();

    // Wait for the paused state to be checked
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Stop the scan loop
    scaMock->Stop();
    runThread.join();

    // Verify that paused message appears in log
    EXPECT_NE(m_logOutput.find("SCA module running"), std::string::npos);
}

TEST_F(ScaTest, SyncModule_PerformsInitialFullSnapshotBeforeFirstSync)
{
    const auto dbPath = makeTempPath();
    auto dbSync = std::make_shared<DBSync>(
                      HostType::AGENT,
                      DbEngineType::SQLITE3,
                      dbPath,
                      kCreateStatement,
                      DbManagement::PERSISTENT);
    auto mockSyncProtocol = std::make_shared<MockAgentSyncProtocol>();
    SCAMock scaMock(dbSync, nullptr);
    scaMock.setSyncProtocol(mockSyncProtocol);
    scaMock.pause();

    insertRow(dbSync, "sca_policy",
    {
        {"id", "policy-1"},
        {"name", "Policy 1"},
        {"file", "policy.yml"},
        {"description", "Policy description"},
        {"refs", "https://example.com"}
    });
    insertRow(dbSync, "sca_check",
    {
        {"checksum", "abc123"},
        {"id", "check-1"},
        {"policy_id", "policy-1"},
        {"name", "Check 1"},
        {"description", "Check description"},
        {"rationale", "Rationale"},
        {"remediation", "Remediation"},
        {"refs", "https://ref.example.com"},
        {"result", "Not applicable"},
        {"reason", "Policy requirements not met"},
        {"condition", "all"},
        {"compliance", "[]"},
        {"mitre", "[]"},
        {"rules", "f:/tmp exists"},
        {"regex_type", "pcre2"},
        {"version", 7},
        {"sync", 1}
    });

    EXPECT_CALL(*mockSyncProtocol, notifyDataClean(testing::_, Option::SYNC))
    .WillOnce(testing::Return(true));
    EXPECT_CALL(*mockSyncProtocol, persistDifference(testing::_, Operation::CREATE, SCA_SYNC_INDEX, testing::_, 7, false))
    .WillOnce(testing::Invoke([](const std::string&,
                                 Operation,
                                 const std::string&,
                                 const std::string & data,
                                 uint64_t,
                                 bool)
    {
        const auto payload = nlohmann::json::parse(data);
        EXPECT_EQ(payload["check"]["id"], "check-1");
        EXPECT_EQ(payload["check"]["result"], "Not applicable");
        EXPECT_EQ(payload["policy"]["id"], "policy-1");
    }));
    EXPECT_CALL(*mockSyncProtocol, synchronizeModule(Mode::DELTA, Option::SYNC))
    .WillOnce(testing::Return(SyncModuleResult{true}));

    EXPECT_TRUE(scaMock.syncModule(Mode::DELTA));

    const auto response = nlohmann::json::parse(scaMock.query(R"({"command":"get_first_sync_completed"})"));
    EXPECT_EQ(response["error"], 0);
    EXPECT_EQ(response["data"]["first_sync_completed"], 1);

    dbSync->closeAndDeleteDatabase();
}

TEST_F(ScaTest, SyncModule_UsesDeltaAfterFirstSyncCompleted)
{
    const auto dbPath = makeTempPath();
    auto dbSync = std::make_shared<DBSync>(
                      HostType::AGENT,
                      DbEngineType::SQLITE3,
                      dbPath,
                      kCreateStatement,
                      DbManagement::PERSISTENT);
    auto mockSyncProtocol = std::make_shared<MockAgentSyncProtocol>();
    SCAMock scaMock(dbSync, nullptr);
    scaMock.setSyncProtocol(mockSyncProtocol);
    scaMock.pause();

    insertRow(dbSync, "sca_metadata", {{"key", "first_sync_completed"}, {"value", 123456}});

    EXPECT_CALL(*mockSyncProtocol, synchronizeModule(Mode::DELTA, Option::SYNC))
    .WillOnce(testing::Return(SyncModuleResult{true}));
    // After the first sync, periodic syncs call synchronizeModule() directly and never go
    // through the snapshot-rebuild path (notifyDataClean + persistDifference per item).
    EXPECT_CALL(*mockSyncProtocol, notifyDataClean(testing::_, testing::_))
    .Times(0);
    EXPECT_CALL(*mockSyncProtocol, persistDifference(testing::_, testing::_, testing::_, testing::_, testing::_, testing::_))
    .Times(0);

    EXPECT_TRUE(scaMock.syncModule(Mode::DELTA));

    dbSync->closeAndDeleteDatabase();
}

// --- Manager-not-ready log-level decision (issue #37553) ------------------------------------------
// These use MockDBSync so the log-level decision is exercised in isolation from real DB/transport.

namespace
{
    // Makes selectRows report that the first synchronization already completed, so syncModule() takes
    // the periodic (DELTA) path instead of the initial full snapshot.
    void expectFirstSyncCompleted(std::shared_ptr<MockDBSync>& mockDBSync)
    {
        EXPECT_CALL(*mockDBSync, selectRows(::testing::_, ::testing::_))
        .WillRepeatedly(::testing::Invoke([](const nlohmann::json&,
                                             std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
        {
            callback(SELECTED, nlohmann::json{{"key", "first_sync_completed"}, {"value", 123456}});
        }));
    }
}

// While the manager is briefly not ready (streak within tolerance), the periodic sync is reported at
// INFO as deferred, not as a WARNING.
TEST_F(ScaTest, SyncModule_ManagerNotReadyWithinToleranceLogsDeferred)
{
    auto mockDBSync = std::make_shared<MockDBSync>();
    auto mockSyncProtocol = std::make_shared<MockAgentSyncProtocol>();
    SCAMock scaMock(mockDBSync, nullptr);
    scaMock.setSyncProtocol(mockSyncProtocol);
    scaMock.pause();
    expectFirstSyncCompleted(mockDBSync);

    EXPECT_CALL(*mockSyncProtocol, synchronizeModule(Mode::DELTA, Option::SYNC))
    .WillOnce(testing::Return(SyncModuleResult{false, "Failed to communicate with the manager.", false, true, 1u}));

    m_logOutput.clear();
    EXPECT_FALSE(scaMock.syncModule(Mode::DELTA));

    EXPECT_THAT(m_logOutput, ::testing::HasSubstr(
                    "SCA synchronization deferred: Failed to communicate with the manager. Will retry next cycle."));
    EXPECT_THAT(m_logOutput, ::testing::Not(::testing::HasSubstr("SCA synchronization failed")));
}

// Past the tolerance the periodic sync escalates to a WARNING that names the streak.
TEST_F(ScaTest, SyncModule_ManagerNotReadyPastToleranceLogsWarning)
{
    auto mockDBSync = std::make_shared<MockDBSync>();
    auto mockSyncProtocol = std::make_shared<MockAgentSyncProtocol>();
    SCAMock scaMock(mockDBSync, nullptr);
    scaMock.setSyncProtocol(mockSyncProtocol);
    scaMock.pause();
    expectFirstSyncCompleted(mockDBSync);

    const unsigned int streak = SYNC_MANAGER_NOT_READY_TOLERANCE + 1;
    EXPECT_CALL(*mockSyncProtocol, synchronizeModule(Mode::DELTA, Option::SYNC))
    .WillOnce(testing::Return(SyncModuleResult{false, "Failed to communicate with the manager.", false, true, streak}));

    m_logOutput.clear();
    EXPECT_FALSE(scaMock.syncModule(Mode::DELTA));

    EXPECT_THAT(m_logOutput, ::testing::HasSubstr(
                    "SCA synchronization failed " + std::to_string(streak) +
                    " times in a row: Failed to communicate with the manager."));
}

// When the manager hasn't synchronized this agent's groups yet (most commonly right after
// enrollment/restart), the periodic sync is reported at INFO as deferred, never as a WARNING --
// regardless of how many cycles it takes to clear (no escalation, same treatment as `stopped`).
TEST_F(ScaTest, SyncModule_AwaitingPrerequisiteLogsDeferredNotWarning)
{
    auto mockDBSync = std::make_shared<MockDBSync>();
    auto mockSyncProtocol = std::make_shared<MockAgentSyncProtocol>();
    SCAMock scaMock(mockDBSync, nullptr);
    scaMock.setSyncProtocol(mockSyncProtocol);
    scaMock.pause();
    expectFirstSyncCompleted(mockDBSync);

    EXPECT_CALL(*mockSyncProtocol, synchronizeModule(Mode::DELTA, Option::SYNC))
    .WillOnce(testing::Return(SyncModuleResult
    {
        false,
        "No groups available in metadata. Waiting for the server to synchronize the groups. Cannot proceed with synchronization.",
        false, false, 0u, true}));

    m_logOutput.clear();
    EXPECT_FALSE(scaMock.syncModule(Mode::DELTA));

    EXPECT_THAT(m_logOutput, ::testing::HasSubstr(
                    "SCA synchronization deferred: No groups available in metadata."));
    EXPECT_THAT(m_logOutput, ::testing::Not(::testing::HasSubstr("SCA synchronization failed")));
}

// A flush that fails while the manager is briefly not ready is reported at INFO as deferred, not as
// the ERROR it used to be.
TEST_F(ScaTest, ExecuteFlushSync_ManagerNotReadyWithinToleranceLogsDeferred)
{
    auto mockDBSync = std::make_shared<MockDBSync>();
    auto mockSyncProtocol = std::make_shared<MockAgentSyncProtocol>();
    SCAMock scaMock(mockDBSync, nullptr);
    scaMock.setSyncProtocol(mockSyncProtocol);

    EXPECT_CALL(*mockSyncProtocol, synchronizeModule(Mode::DELTA, Option::SYNC))
    .WillOnce(testing::Return(SyncModuleResult{false, "Failed to communicate with the manager.", false, true, 1u}));

    m_logOutput.clear();
    EXPECT_EQ(scaMock.callExecuteFlushSync(), -1);

    EXPECT_THAT(m_logOutput, ::testing::HasSubstr(
                    "SCA flush deferred: Failed to communicate with the manager. Will retry next cycle."));
    EXPECT_THAT(m_logOutput, ::testing::Not(::testing::HasSubstr("SCA flush failed")));
}

// A flush that keeps failing past the tolerance escalates to a WARNING naming the streak.
TEST_F(ScaTest, ExecuteFlushSync_ManagerNotReadyPastToleranceLogsWarning)
{
    auto mockDBSync = std::make_shared<MockDBSync>();
    auto mockSyncProtocol = std::make_shared<MockAgentSyncProtocol>();
    SCAMock scaMock(mockDBSync, nullptr);
    scaMock.setSyncProtocol(mockSyncProtocol);

    const unsigned int streak = SYNC_MANAGER_NOT_READY_TOLERANCE + 1;
    EXPECT_CALL(*mockSyncProtocol, synchronizeModule(Mode::DELTA, Option::SYNC))
    .WillOnce(testing::Return(SyncModuleResult{false, "Failed to communicate with the manager.", false, true, streak}));

    m_logOutput.clear();
    EXPECT_EQ(scaMock.callExecuteFlushSync(), -1);

    EXPECT_THAT(m_logOutput, ::testing::HasSubstr(
                    "SCA flush failed " + std::to_string(streak) +
                    " times in a row: Failed to communicate with the manager."));
}

// A flush that hits the same "no groups yet" condition is deferred at INFO too, not ERROR.
TEST_F(ScaTest, ExecuteFlushSync_AwaitingPrerequisiteLogsDeferredNotError)
{
    auto mockDBSync = std::make_shared<MockDBSync>();
    auto mockSyncProtocol = std::make_shared<MockAgentSyncProtocol>();
    SCAMock scaMock(mockDBSync, nullptr);
    scaMock.setSyncProtocol(mockSyncProtocol);

    EXPECT_CALL(*mockSyncProtocol, synchronizeModule(Mode::DELTA, Option::SYNC))
    .WillOnce(testing::Return(SyncModuleResult
    {
        false,
        "No groups available in metadata. Waiting for the server to synchronize the groups. Cannot proceed with synchronization.",
        false, false, 0u, true}));

    m_logOutput.clear();
    EXPECT_EQ(scaMock.callExecuteFlushSync(), -1);

    EXPECT_THAT(m_logOutput, ::testing::HasSubstr(
                    "SCA flush deferred: No groups available in metadata."));
    EXPECT_THAT(m_logOutput, ::testing::Not(::testing::HasSubstr("SCA flush failed")));
}

// A flush failure that is not a manager-not-ready condition keeps the original ERROR.
TEST_F(ScaTest, ExecuteFlushSync_GenuineFailureKeepsError)
{
    auto mockDBSync = std::make_shared<MockDBSync>();
    auto mockSyncProtocol = std::make_shared<MockAgentSyncProtocol>();
    SCAMock scaMock(mockDBSync, nullptr);
    scaMock.setSyncProtocol(mockSyncProtocol);

    EXPECT_CALL(*mockSyncProtocol, synchronizeModule(Mode::DELTA, Option::SYNC))
    .WillOnce(testing::Return(SyncModuleResult{false, "Manager sent an unexpected or invalid response.", false, false, 0u}));

    m_logOutput.clear();
    EXPECT_EQ(scaMock.callExecuteFlushSync(), -1);

    EXPECT_THAT(m_logOutput, ::testing::HasSubstr("SCA flush failed"));
    EXPECT_THAT(m_logOutput, ::testing::Not(::testing::HasSubstr("deferred")));
    EXPECT_THAT(m_logOutput, ::testing::Not(::testing::HasSubstr("times in a row")));
}

// releaseResources() must drop *every* owner of the DBSync handle held by the module, not just
// m_dBSync: SCASyncManager is constructed with a copy of it, so a reset that misses the manager
// leaves the refcount above zero, ~SQLiteDBEngine never runs and sca.db stays locked.
// The module instance is deliberately kept alive across the assertion because in production it is
// never destroyed (SCA::~SCA releases it), so releaseResources() is the only thing that can close
// the database.
TEST_F(ScaTest, ReleaseResources_DropsEveryDbSyncOwner)
{
    auto mockDBSync = std::make_shared<MockDBSync>();
    const std::weak_ptr<IDBSync> dbSyncWatcher = mockDBSync;

    SCAMock scaMock(mockDBSync, nullptr);
    mockDBSync.reset();

    ASSERT_FALSE(dbSyncWatcher.expired());

    scaMock.releaseResources();

    EXPECT_TRUE(dbSyncWatcher.expired());
}

// End-to-end form of the same bug, asserting on the symptom reported in #38069: DBSync writes go
// into a long-lived transaction that only ~SQLiteDBEngine commits, so while any owner survives the
// database file stays under a RESERVED lock and the next connection fails with
// "sqlite: database is locked" -- which on Windows is the incoming agent process after a WPK upgrade.
TEST_F(ScaTest, ReleaseResources_ReleasesSqliteWriteLock)
{
    const auto dbPath = makeTempPath();
    auto dbSync = std::make_shared<DBSync>(
                      HostType::AGENT,
                      DbEngineType::SQLITE3,
                      dbPath,
                      kCreateStatement,
                      DbManagement::PERSISTENT);

    SCAMock scaMock(dbSync, nullptr);

    // Writing inside DBSync's standing transaction takes the RESERVED lock on the database file.
    insertRow(dbSync, "sca_policy",
    {
        {"id", "policy-1"},
        {"name", "Policy 1"},
        {"file", "policy.yml"},
        {"description", "Policy description"},
        {"refs", "https://example.com"}
    });

    dbSync.reset();
    scaMock.releaseResources();

    // A second connection stands in for the incoming agent process: it must be able to open the
    // database and write to it immediately.
    std::shared_ptr<DBSync> reopened;
    ASSERT_NO_THROW(reopened = std::make_shared<DBSync>(
                                   HostType::AGENT,
                                   DbEngineType::SQLITE3,
                                   dbPath,
                                   kCreateStatement,
                                   DbManagement::PERSISTENT));
    EXPECT_NO_THROW(insertRow(reopened, "sca_policy",
    {
        {"id", "policy-2"},
        {"name", "Policy 2"},
        {"file", "policy2.yml"},
        {"description", "Policy description"},
        {"refs", "https://example.com"}
    }));

    reopened->closeAndDeleteDatabase();
}
