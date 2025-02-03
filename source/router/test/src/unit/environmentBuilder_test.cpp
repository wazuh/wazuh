#include <gtest/gtest.h>

#include "environmentBuilder.hpp"

#include <bk/mockController.hpp>
#include <builder/mockBuilder.hpp>
#include <builder/mockPolicy.hpp>
#include <store/mockStore.hpp>

using namespace router;
using namespace testing;

TEST(EnvironmentBuilderTest, Create_ValidPolicyAndFilter)
{
    auto builder = std::make_shared<builder::mocks::MockBuilder>();
    auto controllerMaker = std::make_shared<bk::mocks::MockMakerController>();

    EnvironmentBuilder eBuilder(builder, controllerMaker);

    auto policyName = base::Name("policy/test/0");
    auto filterName = base::Name("filter/test/0");

    auto mockPolicy = std::make_shared<builder::mocks::MockPolicy>();

    std::shared_ptr<builder::IPolicy> resPolicy(mockPolicy);
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));
    fakeAssets.insert(base::Name("asset/test/1"));
    fakeAssets.insert(base::Name("asset/test/2"));
    EXPECT_CALL(*builder, buildPolicy(policyName, testing::_, testing::_)).WillOnce(Return(resPolicy));
    EXPECT_CALL(*mockPolicy, assets()).Times(3).WillRepeatedly(ReturnRef(fakeAssets));

    auto mockController = std::make_shared<bk::mocks::MockController>();
    EXPECT_CALL(*controllerMaker, create(testing::_, testing::_, testing::_))
        .WillOnce(::testing::Return(mockController));

    auto emptyExpression = base::Expression {};
    EXPECT_CALL(*mockPolicy, expression()).WillOnce(ReturnRef(emptyExpression));
    std::string hash = "hash";
    EXPECT_CALL(*mockPolicy, hash()).WillOnce(ReturnRef(hash));

    EXPECT_CALL(*builder, buildAsset(filterName)).WillOnce(Return(emptyExpression));

    EXPECT_CALL(*mockController, stop()).WillOnce(Return());
    auto environment = eBuilder.create(policyName, filterName);

    // Assert
    EXPECT_NE(environment, nullptr);
}

TEST(EnvironmentBuilderTest, Create_inValidPolicy)
{
    auto builder = std::make_shared<builder::mocks::MockBuilder>();
    auto controllerMaker = std::make_shared<bk::mocks::MockMakerController>();

    EnvironmentBuilder eBuilder(builder, controllerMaker);

    auto policyName = base::Name("policy/test/0");
    auto filterName = base::Name("filter/test/0");

    EXPECT_CALL(*builder, buildPolicy(policyName, testing::_, testing::_))
        .WillOnce(::testing::Throw(std::runtime_error("error")));

    ASSERT_THROW(eBuilder.create(policyName, filterName), std::runtime_error);
}

TEST(EnvironmentBuilderTest, Create_ValidPolicyAndInvalidFilter)
{
    auto builder = std::make_shared<builder::mocks::MockBuilder>();
    auto controllerMaker = std::make_shared<bk::mocks::MockMakerController>();

    EnvironmentBuilder eBuilder(builder, controllerMaker);

    auto policyName = base::Name("policy/test/0");
    auto filterName = base::Name("filter/test/0");

    auto mockPolicy = std::make_shared<builder::mocks::MockPolicy>();

    std::shared_ptr<builder::IPolicy> resPolicy(mockPolicy);
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));
    fakeAssets.insert(base::Name("asset/test/1"));
    fakeAssets.insert(base::Name("asset/test/2"));
    EXPECT_CALL(*builder, buildPolicy(policyName, testing::_, testing::_)).WillOnce(Return(resPolicy));
    EXPECT_CALL(*mockPolicy, assets()).Times(3).WillRepeatedly(ReturnRef(fakeAssets));

    auto mockController = std::make_shared<bk::mocks::MockController>();
    EXPECT_CALL(*controllerMaker, create(testing::_, testing::_, testing::_))
        .WillOnce(::testing::Return(mockController));

    auto emptyExpression = base::Expression {};
    EXPECT_CALL(*mockPolicy, expression()).WillOnce(ReturnRef(emptyExpression));
    std::string hash = "hash";
    EXPECT_CALL(*mockPolicy, hash()).WillOnce(ReturnRef(hash));

    EXPECT_CALL(*builder, buildAsset(filterName)).WillOnce(::testing::Throw(std::runtime_error("error")));

    EXPECT_CALL(*mockController, stop()).WillOnce(Return());
    ASSERT_THROW(eBuilder.create(policyName, filterName), std::runtime_error);
}
