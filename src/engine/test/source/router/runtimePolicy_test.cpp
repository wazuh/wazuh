
#include <router/runtimePolicy.hpp>

#include <string>

#include <gtest/gtest.h>

#include "routerAuxiliarFunctions.hpp"

#include "parseEvent.hpp"
#include "register.hpp"
#include <testsCommon.hpp>

constexpr auto POLICY_1 = "policy/pol_1/0";
constexpr auto INVALID_POLICY = "policy/invalid/0";

using namespace store::mocks;

class RuntimePolicyTest
    : public ::testing::Test
    , public MockDeps
{

protected:
    void SetUp() override
    {
        initLogging();

        init();
    }

    void TearDown() override {}
};

TEST_F(RuntimePolicyTest, build_ok)
{
    auto policy = std::make_shared<router::RuntimePolicy>(POLICY_1);
    expectBuildPolicy(POLICY_1);
    auto error = policy->build(m_builder);
    ASSERT_FALSE(error.has_value()) << error.value().message;
}

TEST_F(RuntimePolicyTest, build_fail_policy)
{
    auto policy = std::make_shared<router::RuntimePolicy>(INVALID_POLICY);
    EXPECT_CALL(*m_store, readDoc(base::Name(INVALID_POLICY)))
        .WillOnce(::testing::Return(storeReadError<store::Doc>()));
    auto error = policy->build(m_builder);
    ASSERT_TRUE(error.has_value());
}

TEST_F(RuntimePolicyTest, build_fail_builder)
{
    GTEST_SKIP();
    auto policy = std::make_shared<router::RuntimePolicy>(INVALID_POLICY);
    // TODO SHOULD BE ASSERT_THROW LOGIC ERROR
    policy->build(nullptr);
}

TEST_F(RuntimePolicyTest, build_2_times)
{
    auto policy = std::make_shared<router::RuntimePolicy>(POLICY_1);
    expectBuildPolicy(POLICY_1);
    auto error = policy->build(m_builder);
    ASSERT_FALSE(error.has_value()) << error.value().message;
    error = policy->build(m_builder);
    ASSERT_TRUE(error.has_value());
    ASSERT_STREQ(error.value().message.c_str(), "Policy 'policy/pol_1/0' is already built");
}

TEST_F(RuntimePolicyTest, processEvent_not_built)
{
    auto policy = std::make_shared<router::RuntimePolicy>(POLICY_1);
    auto e = base::parseEvent::parseWazuhEvent(aux::sampleEventsStr[0]);
    auto error = policy->processEvent(e);
    ASSERT_TRUE(error.has_value());
    ASSERT_STREQ(error.value().message.c_str(), "Policy 'policy/pol_1/0' is not built");
}

TEST_F(RuntimePolicyTest, processEvent_1_event)
{
    auto policy = std::make_shared<router::RuntimePolicy>(POLICY_1);
    expectBuildPolicy(POLICY_1);
    auto error = policy->build(m_builder);
    ASSERT_FALSE(error.has_value()) << error.value().message;

    auto e = base::parseEvent::parseWazuhEvent(aux::sampleEventsStr[0]);

    // Send event
    auto decoderPath = json::Json::formatJsonPath("~decoder");
    auto result = policy->processEvent(e);
    ASSERT_FALSE(result) << result.value().message;
    ASSERT_TRUE(e->exists(decoderPath) && e->isString(decoderPath)) << e->prettyStr();
    ASSERT_EQ(e->getString(decoderPath).value(), "deco_1") << e->prettyStr();
}

// TODO add more tests
TEST_F(RuntimePolicyTest, processEvent_30_event)
{
    auto policy = std::make_shared<router::RuntimePolicy>(POLICY_1);
    expectBuildPolicy(POLICY_1);
    auto error = policy->build(m_builder);
    ASSERT_FALSE(error.has_value()) << error.value().message;
    auto decoderPath = json::Json::formatJsonPath("~decoder");

    for (std::size_t i = 0; i < 30; i += 3)
    {
        auto e = base::parseEvent::parseWazuhEvent(aux::sampleEventsStr[i % 3]);
        // Send event
        auto result = policy->processEvent(e);
        ASSERT_FALSE(result) << result.value().message;
        ASSERT_TRUE(e->exists(decoderPath) && e->isString(decoderPath)) << e->prettyStr();
        ASSERT_EQ(e->getString(decoderPath).value(), "deco_1") << e->prettyStr();

        e = base::parseEvent::parseWazuhEvent(aux::sampleEventsStr[(i + 1) % 3]);
        // Send event
        result = policy->processEvent(e);
        ASSERT_FALSE(result) << result.value().message;
        ASSERT_TRUE(e->exists(decoderPath) && e->isString(decoderPath)) << e->prettyStr();
        ASSERT_EQ(e->getString(decoderPath).value(), "deco_2") << e->prettyStr();

        e = base::parseEvent::parseWazuhEvent(aux::sampleEventsStr[(i + 2) % 3]);
        // Send event
        result = policy->processEvent(e);
        ASSERT_FALSE(result) << result.value().message;
        ASSERT_TRUE(e->exists(decoderPath) && e->isString(decoderPath)) << e->prettyStr();
        ASSERT_EQ(e->getString(decoderPath).value(), "deco_3") << e->prettyStr();
    }
}
