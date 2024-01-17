#include "builders/baseBuilders_test.hpp"

#include "builders/opfilter/opBuilderHelperFilter.hpp"

namespace
{
auto customRef()
{
    return [](const Mocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, schema()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks.schema, hasField(testing::_)).WillRepeatedly(testing::Return(false));
        return None {};
    };
}

auto typeRefExpected(schemf::Type sType, json::Json::Type jType, bool success = true)
{
    return [=](const Mocks& mocks)
    {
        if (!success)
        {
            EXPECT_CALL(*mocks.ctx, context());
        }
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.ctx, schema()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks.schema, hasField(DotPath("ref"))).WillOnce(testing::Return(true));
        EXPECT_CALL(*mocks.schema, getType(DotPath("ref"))).WillRepeatedly(testing::Return(sType));
        EXPECT_CALL(*mocks.validator, getJsonType(sType)).WillOnce(testing::Return(jType));
        return None {};
    };
}
} // namespace

namespace filterbuildtest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    FilterBuilderTest,
    testing::Values(
        /*** Array Contains ***/
        FilterT({}, opfilter::opBuilderHelperContainsString, FAILURE()),
        FilterT({makeValue(R"("str")")}, opfilter::opBuilderHelperContainsString, SUCCESS()),
        FilterT({makeValue(R"("str")"), makeValue(R"("str")")}, opfilter::opBuilderHelperContainsString, SUCCESS()),
        FilterT({makeValue(R"(2)")}, opfilter::opBuilderHelperContainsString, FAILURE()),
        FilterT({makeValue(R"("str")"), makeValue(R"(2)")}, opfilter::opBuilderHelperContainsString, FAILURE()),
        FilterT({makeRef("ref")}, opfilter::opBuilderHelperContainsString, SUCCESS(customRef())),
        FilterT({makeRef("ref"), makeValue(R"("str")")}, opfilter::opBuilderHelperContainsString, SUCCESS(customRef())),
        FilterT({makeRef("ref"), makeValue(R"(2)")}, opfilter::opBuilderHelperContainsString, FAILURE(customRef())),
        FilterT({makeRef("ref"), makeValue(R"("str")"), makeValue("2")},
                opfilter::opBuilderHelperContainsString,
                FAILURE(customRef())),
        FilterT({makeRef("ref")},
                opfilter::opBuilderHelperContainsString,
                SUCCESS(typeRefExpected(schemf::Type::TEXT, json::Json::Type::String))),
        FilterT({makeRef("ref")},
                opfilter::opBuilderHelperContainsString,
                FAILURE(typeRefExpected(schemf::Type::DOUBLE, json::Json::Type::Number))),
        /*** Array Not Contains ***/
        FilterT({}, opfilter::opBuilderHelperNotContainsString, FAILURE()),
        FilterT({makeValue(R"("str")")}, opfilter::opBuilderHelperNotContainsString, SUCCESS()),
        FilterT({makeValue(R"("str")"), makeValue(R"("str")")}, opfilter::opBuilderHelperNotContainsString, SUCCESS()),
        FilterT({makeValue(R"(2)")}, opfilter::opBuilderHelperNotContainsString, FAILURE()),
        FilterT({makeValue(R"("str")"), makeValue(R"(2)")}, opfilter::opBuilderHelperNotContainsString, FAILURE()),
        FilterT({makeRef("ref")}, opfilter::opBuilderHelperNotContainsString, SUCCESS(customRef())),
        FilterT({makeRef("ref"), makeValue(R"("str")")},
                opfilter::opBuilderHelperNotContainsString,
                SUCCESS(customRef())),
        FilterT({makeRef("ref"), makeValue(R"(2)")}, opfilter::opBuilderHelperNotContainsString, FAILURE(customRef())),
        FilterT({makeRef("ref"), makeValue(R"("str")"), makeValue("2")},
                opfilter::opBuilderHelperNotContainsString,
                FAILURE(customRef())),
        FilterT({makeRef("ref")},
                opfilter::opBuilderHelperNotContainsString,
                SUCCESS(typeRefExpected(schemf::Type::TEXT, json::Json::Type::String))),
        FilterT({makeRef("ref")},
                opfilter::opBuilderHelperNotContainsString,
                FAILURE(typeRefExpected(schemf::Type::DOUBLE, json::Json::Type::Number)))),
    testNameFormatter<FilterBuilderTest>("ArrayContains"));
} // namespace filterbuildtest

namespace filteroperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    FilterOperationTest,
    testing::Values(
        /*** Array Contains ***/
        FilterT(R"({"target": ["value"]})",
                opfilter::opBuilderHelperContainsString,
                "target",
                {makeValue(R"("value")")},
                SUCCESS()),
        FilterT(R"({"target": ["value"]})",
                opfilter::opBuilderHelperContainsString,
                "target",
                {makeValue(R"("value2")")},
                FAILURE()),
        FilterT(R"({"target": ["value"]})",
                opfilter::opBuilderHelperContainsString,
                "notTarget",
                {makeValue(R"("value")")},
                FAILURE()),
        FilterT(R"({"target": "value"})",
                opfilter::opBuilderHelperContainsString,
                "target",
                {makeValue(R"("value")")},
                FAILURE()),
        FilterT(R"({"target": ["value"]})",
                opfilter::opBuilderHelperContainsString,
                "target",
                {makeValue(R"("value")"), makeValue(R"("value2")")},
                SUCCESS()),
        FilterT(R"({"target": ["value"]})",
                opfilter::opBuilderHelperContainsString,
                "target",
                {makeValue(R"("value2")"), makeValue(R"("value")")},
                SUCCESS()),
        FilterT(R"({"target": ["value", "value2", "value3"]})",
                opfilter::opBuilderHelperContainsString,
                "target",
                {makeValue(R"("value2")"), makeValue(R"("value")"), makeValue(R"("value4")")},
                SUCCESS()),
        FilterT(R"({"target": ["value"], "ref": "value"})",
                opfilter::opBuilderHelperContainsString,
                "target",
                {makeRef("ref")},
                SUCCESS(customRef())),
        FilterT(R"({"target": ["value"], "ref": "value2"})",
                opfilter::opBuilderHelperContainsString,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": ["value"], "notRef": "value"})",
                opfilter::opBuilderHelperContainsString,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": ["value", "value2", "value3"], "ref": "value2"})",
                opfilter::opBuilderHelperContainsString,
                "target",
                {makeRef("ref"), makeRef("notRef"), makeValue(R"("value")"), makeValue(R"("value4")")},
                SUCCESS(customRef())),
        /*** Array Not Contains ***/
        FilterT(R"({"target": ["value"]})",
                opfilter::opBuilderHelperNotContainsString,
                "target",
                {makeValue(R"("value")")},
                FAILURE()),
        FilterT(R"({"target": ["value"]})",
                opfilter::opBuilderHelperNotContainsString,
                "target",
                {makeValue(R"("value2")")},
                SUCCESS()),
        FilterT(R"({"target": ["value"]})",
                opfilter::opBuilderHelperNotContainsString,
                "notTarget",
                {makeValue(R"("value")")},
                FAILURE()),
        FilterT(R"({"target": "value"})",
                opfilter::opBuilderHelperNotContainsString,
                "target",
                {makeValue(R"("value")")},
                FAILURE()),
        FilterT(R"({"target": ["value"]})",
                opfilter::opBuilderHelperNotContainsString,
                "target",
                {makeValue(R"("value")"), makeValue(R"("value2")")},
                FAILURE()),
        FilterT(R"({"target": ["value"]})",
                opfilter::opBuilderHelperNotContainsString,
                "target",
                {makeValue(R"("value2")"), makeValue(R"("value")")},
                FAILURE()),
        FilterT(R"({"target": ["value", "value2", "value3"]})",
                opfilter::opBuilderHelperNotContainsString,
                "target",
                {makeValue(R"("value2")"), makeValue(R"("value")"), makeValue(R"("value4")")},
                FAILURE()),
        FilterT(R"({"target": ["value"], "ref": "value"})",
                opfilter::opBuilderHelperNotContainsString,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": ["value"], "ref": "value2"})",
                opfilter::opBuilderHelperNotContainsString,
                "target",
                {makeRef("ref")},
                SUCCESS(customRef())),
        FilterT(R"({"target": ["value"], "notRef": "value"})",
                opfilter::opBuilderHelperNotContainsString,
                "target",
                {makeRef("ref")},
                SUCCESS(customRef())),
        FilterT(R"({"target": ["value", "value2", "value3"], "ref": "value2"})",
                opfilter::opBuilderHelperNotContainsString,
                "target",
                {makeRef("ref"), makeRef("notRef"), makeValue(R"("value")"), makeValue(R"("value4")")},
                FAILURE(customRef()))),
    testNameFormatter<FilterOperationTest>("ArrayContains"));
} // namespace filteroperatestest
