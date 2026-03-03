#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "environmentBuilder.hpp"

#include <bk/mockController.hpp>
#include <builder/mockBuilder.hpp>
#include <builder/mockPolicy.hpp>
#include <store/mockStore.hpp>

using namespace router;
using namespace testing;

class EnvironmentBuilderFixture : public ::testing::Test
{
protected:
    std::shared_ptr<builder::mocks::MockBuilder> mockBuilder;
    std::shared_ptr<bk::mocks::MockMakerController> mockControllerMaker;
    std::shared_ptr<builder::mocks::MockPolicy> mockPolicy;
    std::shared_ptr<bk::mocks::MockController> mockController;

    cm::store::NamespaceId validPolicyName {"policy_test_0"};
    cm::store::NamespaceId anotherPolicyName {"policy_test_1"};
    cm::store::NamespaceId invalidPolicyName {"policy_invalid_0"};

    std::string testHash {"abc123hash456"};
    std::string anotherHash {"xyz789hash012"};

    std::unordered_set<base::Name> fakeAssets;
    base::Expression emptyExpression {};

    void SetUp() override
    {
        mockBuilder = std::make_shared<builder::mocks::MockBuilder>();
        mockControllerMaker = std::make_shared<bk::mocks::MockMakerController>();
        mockPolicy = std::make_shared<builder::mocks::MockPolicy>();
        mockController = std::make_shared<bk::mocks::MockController>();

        fakeAssets.insert(base::Name("asset/test/0"));
        fakeAssets.insert(base::Name("asset/test/1"));
        fakeAssets.insert(base::Name("asset/test/2"));
    }

    void setupValidPolicyMocks(const cm::store::NamespaceId& policyName, const std::string& hash)
    {
        EXPECT_CALL(*mockBuilder, buildPolicy(policyName, ::testing::_, ::testing::_))
            .WillOnce(Return(std::shared_ptr<builder::IPolicy>(mockPolicy)));

        EXPECT_CALL(*mockPolicy, assets()).WillRepeatedly(ReturnRef(fakeAssets));

        EXPECT_CALL(*mockPolicy, expression()).WillOnce(ReturnRef(emptyExpression));
        EXPECT_CALL(*mockPolicy, hash()).WillOnce(ReturnRef(hash));

        EXPECT_CALL(*mockControllerMaker, create(testing::_, testing::_, testing::_)).WillOnce(Return(mockController));
    }
};

TEST_F(EnvironmentBuilderFixture, ConstructorThrowsOnNullBuilder)
{
    std::weak_ptr<builder::IBuilder> nullBuilder;
    EXPECT_THROW(EnvironmentBuilder(nullBuilder, mockControllerMaker), std::runtime_error);
}

TEST_F(EnvironmentBuilderFixture, ConstructorThrowsOnNullControllerMaker)
{
    EXPECT_THROW(EnvironmentBuilder(mockBuilder, nullptr), std::runtime_error);
}

TEST_F(EnvironmentBuilderFixture, ConstructorSucceedsWithValidParameters)
{
    EXPECT_NO_THROW(EnvironmentBuilder(mockBuilder, mockControllerMaker));
}

TEST_F(EnvironmentBuilderFixture, CreateValidEnvironment)
{
    setupValidPolicyMocks(validPolicyName, testHash);

    EnvironmentBuilder eBuilder(mockBuilder, mockControllerMaker);
    auto environment = eBuilder.create(validPolicyName);

    EXPECT_NE(environment, nullptr);
}

TEST_F(EnvironmentBuilderFixture, CreateEnvironmentWithValidPolicyButNoAssets)
{
    std::unordered_set<base::Name> emptyAssets {};

    EXPECT_CALL(*mockBuilder, buildPolicy(validPolicyName, ::testing::_, ::testing::_))
        .WillOnce(Return(std::shared_ptr<builder::IPolicy>(mockPolicy)));

    EXPECT_CALL(*mockPolicy, assets()).WillRepeatedly(ReturnRef(emptyAssets));

    EnvironmentBuilder eBuilder(mockBuilder, mockControllerMaker);

    EXPECT_THROW(eBuilder.create(validPolicyName), std::runtime_error);
}

TEST_F(EnvironmentBuilderFixture, CreateThrowsOnPolicyBuildFailure)
{
    EXPECT_CALL(*mockBuilder, buildPolicy(invalidPolicyName, ::testing::_, ::testing::_))
        .WillOnce(Throw(std::runtime_error("Failed to build policy")));

    EnvironmentBuilder eBuilder(mockBuilder, mockControllerMaker);

    EXPECT_THROW(eBuilder.create(invalidPolicyName), std::runtime_error);
}

TEST_F(EnvironmentBuilderFixture, CreateThrowsOnControllerCreationFailure)
{
    EXPECT_CALL(*mockBuilder, buildPolicy(validPolicyName, ::testing::_, ::testing::_))
        .WillOnce(Return(std::shared_ptr<builder::IPolicy>(mockPolicy)));

    EXPECT_CALL(*mockPolicy, assets()).WillRepeatedly(ReturnRef(fakeAssets));
    EXPECT_CALL(*mockPolicy, expression()).WillOnce(ReturnRef(emptyExpression));

    EXPECT_CALL(*mockControllerMaker, create(testing::_, testing::_, testing::_)).WillOnce(Return(nullptr));

    EnvironmentBuilder eBuilder(mockBuilder, mockControllerMaker);

    EXPECT_THROW(eBuilder.create(validPolicyName), std::runtime_error);
}

TEST_F(EnvironmentBuilderFixture, MakeControllerReturnsControllerAndHash)
{
    EXPECT_CALL(*mockBuilder, buildPolicy(validPolicyName, true, true))
        .WillOnce(Return(std::shared_ptr<builder::IPolicy>(mockPolicy)));

    EXPECT_CALL(*mockPolicy, assets()).WillRepeatedly(ReturnRef(fakeAssets));

    EXPECT_CALL(*mockPolicy, expression()).WillOnce(ReturnRef(emptyExpression));
    EXPECT_CALL(*mockPolicy, hash()).WillOnce(ReturnRef(testHash));

    EXPECT_CALL(*mockControllerMaker, create(testing::_, testing::_, testing::_)).WillOnce(Return(mockController));

    EnvironmentBuilder eBuilder(mockBuilder, mockControllerMaker);
    auto [controller, hash] = eBuilder.makeController(validPolicyName, true, true);

    EXPECT_NE(controller, nullptr);
    EXPECT_EQ(hash, testHash);
}

TEST_F(EnvironmentBuilderFixture, MakeControllerThrowsOnBuilderExpired)
{
    auto builder = std::make_shared<builder::mocks::MockBuilder>();
    std::weak_ptr<builder::IBuilder> weakBuilder = builder;

    EnvironmentBuilder eBuilder(weakBuilder, mockControllerMaker);

    builder.reset();

    EXPECT_THROW(eBuilder.makeController(validPolicyName), std::runtime_error);
}

TEST_F(EnvironmentBuilderFixture, CreateMultipleEnvironments)
{
    auto mockController2 = std::make_shared<bk::mocks::MockController>();

    EXPECT_CALL(*mockBuilder, buildPolicy(validPolicyName, false, false))
        .WillOnce(Return(std::shared_ptr<builder::IPolicy>(mockPolicy)));
    EXPECT_CALL(*mockPolicy, assets()).WillRepeatedly(ReturnRef(fakeAssets));
    EXPECT_CALL(*mockPolicy, expression()).WillOnce(ReturnRef(emptyExpression));
    EXPECT_CALL(*mockPolicy, hash()).WillOnce(ReturnRef(testHash));
    EXPECT_CALL(*mockControllerMaker, create(testing::_, testing::_, testing::_)).WillOnce(Return(mockController));

    EnvironmentBuilder eBuilder(mockBuilder, mockControllerMaker);
    auto env1 = eBuilder.create(validPolicyName);
    EXPECT_NE(env1, nullptr);
}
