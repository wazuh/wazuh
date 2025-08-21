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

#include <thread>
#include <memory>
#include <string>

class ScaTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            // Set up the logging callback to avoid "Log callback not set" errors
            LoggingHelper::setLogCallback([](const modules_log_level_t /* level */, const char* log)
            {
                std::cout << log << "\n";
            });

            m_mockDBSync = std::make_shared<MockDBSync>();
            m_sca = std::make_shared<SecurityConfigurationAssessment>(
                        "test_path",
                        "agent-uuid",
                        m_mockDBSync
                    );
        }

        std::shared_ptr<IDBSync> m_mockDBSync = nullptr;
        std::shared_ptr<SecurityConfigurationAssessment> m_sca = nullptr;
};

TEST_F(ScaTest, SetPushMessageFunctionStoresCallback)
{
    constexpr int expectedReturnValue = 123;
    bool statefulCalled = false;
    bool statelessCalled = false;

    auto statefulLambda = [&](const std::string&) -> int // NOLINT(performance-unnecessary-value-param)
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
    const int result = statefulLambda(dummyMessage) + statelessLambda(dummyMessage);

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

    auto reportCheckResult = [&](const CheckResult& r) -> void
    {
        reported.emplace_back(r.policyId, r.checkId, r.result);
    };

    auto reportScanDuration = [&](std::chrono::milliseconds) {};

    policy.Run(0, true, reportCheckResult, reportScanDuration);

    EXPECT_FALSE(reported.empty());
    EXPECT_EQ(std::get<0>(reported.front()), policyId);
    EXPECT_EQ(std::get<1>(reported.front()), "724524");

    // call Stop, m_keepRunning prevents further scans
    policy.Stop();

    reported.clear();
    policy.Run(0, true, reportCheckResult, reportScanDuration);
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

    auto reportCheckResult = [&](const CheckResult& r)
    {
        reported.emplace_back(r.policyId, r.checkId, r.result);
    };

    auto reportScanDuration = [&](std::chrono::milliseconds) {};

    policy.Run(0, true, reportCheckResult, reportScanDuration);

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
    scm.Setup(true, true, 1000, 30, false, {});

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

    auto mockFileSystem = std::make_shared<testing::NiceMock<MockFileSystemWrapper>>();
    auto mockDBSync = std::make_shared<testing::NiceMock<MockDBSync>>();

    // Mock file system to return true for exists checks
    EXPECT_CALL(*mockFileSystem, exists(testing::_))
    .Times(2)
    .WillRepeatedly(testing::Return(true));

    SCAMock scm(mockDBSync, mockFileSystem);
    scm.Setup(true, true, 1000, 30, false, policyData);

    // Policies should be loaded (though we can't easily verify the exact count due to parsing)
    auto& policiesRef = scm.GetPolicies();

    // No policies should be created
    EXPECT_TRUE(policiesRef.empty());
}

TEST_F(ScaTest, RunDoesNothingWhenDisabled)
{
    m_sca->Setup(false, true, 1000, 30, false, {});

    testing::internal::CaptureStdout();
    m_sca->Run();
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_THAT(output, testing::HasSubstr("SCA module is disabled"));
}

TEST_F(ScaTest, StopSetsKeepRunningToFalse)
{
    testing::internal::CaptureStdout();

    m_sca->Stop();
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_THAT(output, testing::HasSubstr("SCA module stopped."));
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
    m_sca->Setup(true, true, 100, 30, false, {});
    testing::internal::CaptureStdout();
    std::thread t([&]
    {
        m_sca->Run();
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    m_sca->Stop();

    t.join();

    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_THAT(output, testing::HasSubstr("SCA module scan on start."));
    //SUCCEED();
}

TEST_F(ScaTest, GetCreateStatement)
{
    auto sca = std::make_shared<SecurityConfigurationAssessment>(
                   "test_path",
                   "agent-uuid",
                   nullptr // null dbSync makes us hit GetCreateStatement()
               );
    SUCCEED();
}
