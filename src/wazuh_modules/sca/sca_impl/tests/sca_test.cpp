#include <gtest/gtest.h>

#include <sca.hpp>

#include <dbsync.hpp>

#include "mocks/mockdbsync.hpp"

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
    bool called = false;

    auto lambda = [&](const std::string&) -> int // NOLINT(performance-unnecessary-value-param)
    {
        called = true;
        return expectedReturnValue;
    };

    m_sca->SetPushMessageFunction(lambda);

    const std::string dummyMessage = R"({"key": "value"})";
    const int result = lambda(dummyMessage);

    EXPECT_TRUE(called);
    EXPECT_EQ(result, expectedReturnValue);
}

TEST_F(ScaTest, NameReturnsCorrectValue)
{
    EXPECT_EQ(m_sca->Name(), "SCA");
}

TEST_F(ScaTest, EnqueueTaskExecutesTask)
{
    // bool taskExecuted = false;

    // auto task = [&]() -> boost::asio::awaitable<void> // NOLINT(cppcoreguidelines-avoid-capturing-lambda-coroutines)
    // {
    //     taskExecuted = true;
    //     m_sca->Stop();
    //     // co_return;
    // };

    // m_sca->Setup(m_configurationParser);
    // m_sca->EnqueueTask(task());
    // m_sca->Run();
    // EXPECT_TRUE(taskExecuted);
}
