#include <gtest/gtest.h>

#include "buildEnvironment.hpp"
#include <store/mockStore.hpp>
#include <router/mockBuilder.hpp>
#include <builder/mockPolicy.hpp>

using namespace router;

class EnvironmentTest : public testing::TestWithParam<std::tuple<int, std::shared_ptr<json::Json>, bool>>
{
protected:
    std::shared_ptr<router::MockBuilder> mockBuilder;
    std::shared_ptr<builder::mocks::MockPolicy> mockPolicy;
    void SetUp() override
    {
        mockBuilder = std::make_shared<MockBuilder>();
        mockPolicy = std::make_shared<builder::mocks::MockPolicy>();

    }
};

TEST_P(EnvironmentTest, SucessCreate)
{
    auto [filterID, event, isAccepted] = GetParam();
    std::unordered_set<base::Name> expectedAssets;

    expectedAssets.insert("decoder/prueba/0");
    auto expresion = base::And::create("testAnd", {});
    base::RespOrError<std::shared_ptr<builder::IPolicy>> respOrError(mockPolicy);

    EXPECT_CALL(*mockBuilder, buildPolicy(testing::_)).WillOnce(testing::Return(respOrError));
    EXPECT_CALL(*mockPolicy, assets()).WillRepeatedly(testing::Return(expectedAssets));
    EXPECT_CALL(*mockPolicy, expression()).WillOnce(testing::Return(expresion));

    auto policyName = base::Name {"policy/wazuh/0"};
    auto env_ = BuildEnvironment::create(policyName, filterID, mockBuilder);

    EXPECT_EQ(env_->isAccepted(event), isAccepted);
}

INSTANTIATE_TEST_SUITE_P(TestParams, EnvironmentTest,
    testing::Values(
        std::make_tuple(1, std::make_shared<json::Json>(R"({"TestSessionID": 1})"), true),
        std::make_tuple(1, std::make_shared<json::Json>(R"({"TestSessionID": 2})"), false),
        std::make_tuple(2, std::make_shared<json::Json>(R"({"TestSessionID": 2})"), true),
        std::make_tuple(1, std::make_shared<json::Json>(R"({"TestSessionID": 2})"), false),
        std::make_tuple(3, std::make_shared<json::Json>(R"({"TestSessionID": 2})"), false),
        std::make_tuple(2, std::make_shared<json::Json>(R"({"IDSession": 2})"), false)
    )
);
