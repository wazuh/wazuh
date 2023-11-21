#include <gtest/gtest.h>

#include "environmentBuilder.hpp"

#include <bk/mockController.hpp>
#include <builder/mockPolicy.hpp>
#include <router/mockBuilder.hpp>
#include <store/mockStore.hpp>

using namespace router;
using namespace testing;

TEST(EnvironmentBuilderTest, Create_ValidPolicyAndFilter)
{
    auto builder = std::make_shared<MockBuilder>();
    auto controllerMaker = std::make_shared<bk::mocks::MockMakerController>();

    EnvironmentBuilder eBuilder(builder, controllerMaker);

    auto policyName = base::Name("policy/test/0");
    auto filterName = base::Name("filter/test/0");

    auto mockPolicy = std::make_shared<builder::mocks::MockPolicy>();

    base::RespOrError<std::shared_ptr<builder::IPolicy>> resPolicy(mockPolicy);
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));
    fakeAssets.insert(base::Name("asset/test/1"));
    fakeAssets.insert(base::Name("asset/test/2"));
    EXPECT_CALL(*builder, buildPolicy(policyName)).WillOnce(Return(resPolicy));
    EXPECT_CALL(*mockPolicy, assets()).Times(3).WillRepeatedly(Return(fakeAssets));

    auto mockController = std::make_shared<bk::mocks::MockController>();
    EXPECT_CALL(*controllerMaker, create()).WillOnce(Return(mockController));

    EXPECT_CALL(*mockPolicy, expression()).WillOnce(Return(base::Expression {}));
    EXPECT_CALL(*mockController, build(_, _)).WillOnce(Return());

    EXPECT_CALL(*builder, buildAsset(filterName)).WillOnce(Return(base::Expression {}));

    EXPECT_CALL(*mockController, stop()).WillOnce(Return());
    auto environment = eBuilder.create(policyName, filterName);

    // Assert
    EXPECT_NE(environment, nullptr);
}

TEST(EnvironmentBuilderTest, Create_inValidPolicy)
{
    auto builder = std::make_shared<MockBuilder>();
    auto controllerMaker = std::make_shared<bk::mocks::MockMakerController>();

    EnvironmentBuilder eBuilder(builder, controllerMaker);

    auto policyName = base::Name("policy/test/0");
    auto filterName = base::Name("filter/test/0");

    auto mockPolicy = std::make_shared<builder::mocks::MockPolicy>();

    base::RespOrError<std::shared_ptr<builder::IPolicy>> resPolicy(mockPolicy);

    EXPECT_CALL(*builder, buildPolicy(policyName)).WillOnce(Return(resPolicy));
    EXPECT_CALL(*mockPolicy, assets()).WillOnce(Return(std::unordered_set<base::Name> {}));

    ASSERT_THROW(eBuilder.create(policyName, filterName), std::runtime_error);
}

TEST(EnvironmentBuilderTest, Create_ValidPolicyAndInvalidFilter)
{
    auto builder = std::make_shared<MockBuilder>();
    auto controllerMaker = std::make_shared<bk::mocks::MockMakerController>();

    EnvironmentBuilder eBuilder(builder, controllerMaker);

    auto policyName = base::Name("policy/test/0");
    auto filterName = base::Name("filter/test/0");

    auto mockPolicy = std::make_shared<builder::mocks::MockPolicy>();

    base::RespOrError<std::shared_ptr<builder::IPolicy>> resPolicy(mockPolicy);
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));
    fakeAssets.insert(base::Name("asset/test/1"));
    fakeAssets.insert(base::Name("asset/test/2"));
    EXPECT_CALL(*builder, buildPolicy(policyName)).WillOnce(Return(resPolicy));
    EXPECT_CALL(*mockPolicy, assets()).Times(3).WillRepeatedly(Return(fakeAssets));

    auto mockController = std::make_shared<bk::mocks::MockController>();
    EXPECT_CALL(*controllerMaker, create()).WillOnce(Return(mockController));

    EXPECT_CALL(*mockPolicy, expression()).WillOnce(Return(base::Expression {}));
    EXPECT_CALL(*mockController, build(_, _)).WillOnce(Return());

    EXPECT_CALL(*builder, buildAsset(filterName)).WillOnce(Return(base::Error {"error"}));

    EXPECT_CALL(*mockController, stop()).WillOnce(Return());
    ASSERT_THROW(eBuilder.create(policyName, filterName), std::runtime_error);
}
