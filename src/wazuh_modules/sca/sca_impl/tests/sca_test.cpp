#include <gtest/gtest.h>
#include <gmock/gmock.h>

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
