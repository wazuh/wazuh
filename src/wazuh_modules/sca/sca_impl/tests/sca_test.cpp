#include <gtest/gtest.h>

#include <sca_impl.hpp>

#include <dbsync.hpp>

#include <mock_dbsync.hpp>

#include <memory>
#include <string>

class ScaTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
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
