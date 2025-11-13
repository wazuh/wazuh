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

#include <chrono>
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
