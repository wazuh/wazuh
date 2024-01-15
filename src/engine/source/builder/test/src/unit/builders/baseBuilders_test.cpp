#include "baseBuilders_test.hpp"

namespace filterbuildtest
{
TEST_P(FilterBuilderTest, Builds)
{
    auto [params, builder, expected] = GetParam();
    Reference targetField {"targetField"};

    if (expected)
    {
        expected.succCase()(*mocks);
        expectBuildSuccess();
        ASSERT_NO_THROW(builder(targetField, params, mocks->ctx));
    }
    else
    {
        expected.failCase()(*mocks);
        ASSERT_THROW(builder(targetField, params, mocks->ctx), std::exception);
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

    expectBuildSuccess();

    if (expected)
    {
        expected.succCase()(*mocks);
        auto operation = builder(targetRef, opArgs, mocks->ctx);
        auto result = operation(event);
        ASSERT_TRUE(result);
    }
    else
    {
        expected.failCase()(*mocks);
        auto operation = builder(targetRef, opArgs, mocks->ctx);
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
        expected.succCase()(*mocks);
        expectBuildSuccess();
        ASSERT_NO_THROW(builder(params, mocks->ctx));
    }
    else
    {
        expected.failCase()(*mocks);
        ASSERT_THROW(builder(params, mocks->ctx), std::exception);
    }
}
} // namespace mapbuildtest

namespace mapoperatestest
{
TEST_P(MapOperationTest, Operates)
{
    auto [input, builder, opArgs, expected] = GetParam();
    auto event = std::make_shared<json::Json>(input.c_str());

    expectBuildSuccess();

    if (expected)
    {
        auto res = expected.succCase()(*mocks);
        auto operation = builder(opArgs, mocks->ctx);
        auto result = operation(event);
        ASSERT_TRUE(result);
        ASSERT_EQ(result.payload(), res);
    }
    else
    {
        expected.failCase()(*mocks);
        auto operation = builder(opArgs, mocks->ctx);
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
        expected.succCase()(*mocks);
        expectBuildSuccess();
        ASSERT_NO_THROW(builder(targetField, params, mocks->ctx));
    }
    else
    {
        expected.failCase()(*mocks);
        ASSERT_THROW(builder(targetField, params, mocks->ctx), std::exception);
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

    expectBuildSuccess();

    if (expected)
    {
        auto expectedEvent = expected.succCase()(*mocks);
        auto operation = builder(targetRef, opArgs, mocks->ctx);
        auto result = operation(event);
        ASSERT_TRUE(result);
        ASSERT_EQ(*result.payload(), *expectedEvent);
    }
    else
    {
        expected.failCase()(*mocks);
        auto operation = builder(targetRef, opArgs, mocks->ctx);
        auto result = operation(event);
        ASSERT_FALSE(result);
    }
}

} // namespace transformoperatestest
