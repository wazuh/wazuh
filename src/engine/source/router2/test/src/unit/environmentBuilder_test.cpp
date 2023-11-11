#include <gtest/gtest.h>

#include "environmentBuilder.hpp"

#include <bk/rx/controller.hpp>
#include <builder/mockPolicy.hpp>
#include <router/mockBuilder.hpp>
#include <store/mockStore.hpp>

using namespace router;

class EnvironmentFilterTest : public testing::TestWithParam<std::tuple<int, std::shared_ptr<json::Json>, bool>>
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

TEST_P(EnvironmentFilterTest, FilterFunctionallity)
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
    auto envBuild = std::make_shared<EnvironmentBuilder<bk::rx::Controller>>(mockBuilder);

    auto env = envBuild->create(policyName, filterID);

    EXPECT_EQ(env.isAccepted(event), isAccepted);
}

INSTANTIATE_TEST_SUITE_P(TestParams, EnvironmentFilterTest,
    testing::Values(
        std::make_tuple(1, std::make_shared<json::Json>(R"({"TestSessionID": 1})"), true),
        std::make_tuple(1, std::make_shared<json::Json>(R"({"TestSessionID": 2})"), false),
        std::make_tuple(2, std::make_shared<json::Json>(R"({"TestSessionID": 2})"), true),
        std::make_tuple(1, std::make_shared<json::Json>(R"({"TestSessionID": 2})"), false),
        std::make_tuple(3, std::make_shared<json::Json>(R"({"TestSessionID": 2})"), false),
        std::make_tuple(2, std::make_shared<json::Json>(R"({"AnotherFilter": 2})"), false)
    )
);
