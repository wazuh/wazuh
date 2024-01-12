#include "baseBuilders_test.hpp"

namespace filterbuildtest
{
TEST_P(FilterBuilderTest, Builds)
{
    auto [params, builder, expected] = GetParam();
    Reference targetField {"targetField"};

    if (expected)
    {
        EXPECT_CALL(*ctx, context()).WillRepeatedly(testing::ReturnRef(context));
        EXPECT_CALL(*ctx, runState()).WillRepeatedly(testing::Return(runState));
        ASSERT_NO_THROW(builder(targetField, params, ctx));
    }
    else
    {
        ASSERT_THROW(builder(targetField, params, ctx), std::exception);
    }
}
} // namespace filterbuildtest

namespace filteroperatestest
{
TEST_P(FilterOperationTest, Operates)
{
    auto [input, builder, target, opArgs, expected] = GetParam();
    auto event = std::make_shared<json::Json>(input.c_str());
    auto targetRef = Reference {target};

    EXPECT_CALL(*ctx, context()).WillRepeatedly(testing::ReturnRef(context));
    EXPECT_CALL(*ctx, runState()).WillRepeatedly(testing::Return(runState));

    if (expected)
    {
        expected.succCase()(ctx);
        auto operation = builder(targetRef, opArgs, ctx);
        auto result = operation(event);
        ASSERT_TRUE(result);
    }
    else
    {
        expected.failCase()(ctx);
        auto operation = builder(targetRef, opArgs, ctx);
        auto result = operation(event);
        ASSERT_FALSE(result);
    }
}

} // namespace filteroperatestest

namespace mapbuildtest
{
TEST_P(MapBuilderTest, Builds)
{
    auto [params, builder, expected] = GetParam();

    if (expected)
    {
        EXPECT_CALL(*ctx, context()).WillRepeatedly(testing::ReturnRef(context));
        EXPECT_CALL(*ctx, runState()).WillRepeatedly(testing::Return(runState));
        ASSERT_NO_THROW(builder(params, ctx));
    }
    else
    {
        ASSERT_THROW(builder(params, ctx), std::exception);
    }
}
} // namespace mapbuildtest

namespace mapoperatestest
{
TEST_P(MapOperationTest, Operates)
{
    auto [input, builder, opArgs, expected] = GetParam();
    auto event = std::make_shared<json::Json>(input.c_str());

    EXPECT_CALL(*ctx, context()).WillRepeatedly(testing::ReturnRef(context));
    EXPECT_CALL(*ctx, runState()).WillRepeatedly(testing::Return(runState));

    if (expected)
    {
        auto res = expected.succCase()(ctx);
        auto operation = builder(opArgs, ctx);
        auto result = operation(event);
        ASSERT_TRUE(result);
        ASSERT_EQ(result.payload(), res);
    }
    else
    {
        expected.failCase()(ctx);
        auto operation = builder(opArgs, ctx);
        auto result = operation(event);
        ASSERT_FALSE(result);
    }
}

} // namespace mapoperatestest

namespace transformbuildtest
{
TEST_P(TransformBuilderTest, Builds)
{
    auto [params, builder, expected] = GetParam();
    Reference targetField {"targetField"};

    if (expected)
    {
        EXPECT_CALL(*ctx, context()).WillRepeatedly(testing::ReturnRef(context));
        EXPECT_CALL(*ctx, runState()).WillRepeatedly(testing::Return(runState));
        ASSERT_NO_THROW(builder(targetField, params, ctx));
    }
    else
    {
        ASSERT_THROW(builder(targetField, params, ctx), std::exception);
    }
}
} // namespace transformbuildtest

namespace transformoperatestest
{
TEST_P(TransformOperationTest, Operates)
{
    auto [input, builder, target, opArgs, expected] = GetParam();
    auto event = std::make_shared<json::Json>(input.c_str());
    auto targetRef = Reference {target};

    EXPECT_CALL(*ctx, context()).WillRepeatedly(testing::ReturnRef(context));
    EXPECT_CALL(*ctx, runState()).WillRepeatedly(testing::Return(runState));

    if (expected)
    {
        auto expectedEvent = expected.succCase()(ctx);
        auto operation = builder(targetRef, opArgs, ctx);
        auto result = operation(event);
        ASSERT_TRUE(result);
        ASSERT_EQ(*result.payload(), *expectedEvent);
    }
    else
    {
        expected.failCase()(ctx);
        auto operation = builder(targetRef, opArgs, ctx);
        auto result = operation(event);
        ASSERT_FALSE(result);
    }
}

} // namespace transformoperatestest
