#include "builders/baseBuilders_test.hpp"

#include "builders/opfilter/opBuilderHelperFilter.hpp"

namespace
{
auto customRef()
{
    return [](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillRepeatedly(testing::Return(false));
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
        // Wrong arguments number
        FilterT({}, opfilter::opBuilderHelperEndsWith, FAILURE()),
        FilterT({makeValue(R"("string")"), makeValue(R"("string")")}, opfilter::opBuilderHelperEndsWith, FAILURE()),
        // Value
        FilterT({makeValue(R"("string")")}, opfilter::opBuilderHelperEndsWith, SUCCESS()),
        FilterT({makeValue(R"(2)")}, opfilter::opBuilderHelperEndsWith, FAILURE()),
        FilterT({makeValue(R"(1.2)")}, opfilter::opBuilderHelperEndsWith, FAILURE()),
        FilterT({makeValue(R"(true)")}, opfilter::opBuilderHelperEndsWith, FAILURE()),
        FilterT({makeValue(R"(false)")}, opfilter::opBuilderHelperEndsWith, FAILURE()),
        FilterT({makeValue(R"([1, 2, 3])")}, opfilter::opBuilderHelperEndsWith, FAILURE()),
        FilterT({makeValue(R"({"a": 1, "b": 2})")}, opfilter::opBuilderHelperEndsWith, FAILURE()),
        FilterT({makeValue(R"(null)")}, opfilter::opBuilderHelperEndsWith, FAILURE()),
        // Reference
        FilterT({makeRef("ref")},
                opfilter::opBuilderHelperEndsWith,
                SUCCESS(
                    [](const BuildersMocks& mocks)
                    {
                        EXPECT_CALL(*mocks.ctx, validator());
                        EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillRepeatedly(testing::Return(false));
                        return None {};
                    })),
        FilterT({makeRef("ref")},
                opfilter::opBuilderHelperEndsWith,
                SUCCESS(
                    [](const BuildersMocks& mocks)
                    {
                        EXPECT_CALL(*mocks.ctx, validator());
                        EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillRepeatedly(testing::Return(true));
                        EXPECT_CALL(*mocks.validator, getType(DotPath("ref")))
                            .WillRepeatedly(testing::Return(schemf::Type::KEYWORD));
                        return None {};
                    })),
        FilterT({makeRef("ref")},
                opfilter::opBuilderHelperEndsWith,
                SUCCESS(
                    [](const BuildersMocks& mocks)
                    {
                        EXPECT_CALL(*mocks.ctx, validator());
                        EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillRepeatedly(testing::Return(true));
                        EXPECT_CALL(*mocks.validator, getType(DotPath("ref")))
                            .WillRepeatedly(testing::Return(schemf::Type::TEXT));
                        return None {};
                    })),
        FilterT({makeRef("ref")},
                opfilter::opBuilderHelperEndsWith,
                FAILURE(
                    [](const BuildersMocks& mocks)
                    {
                        EXPECT_CALL(*mocks.ctx, validator());
                        EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillRepeatedly(testing::Return(true));
                        EXPECT_CALL(*mocks.validator, getType(DotPath("ref")))
                            .WillRepeatedly(testing::Return(schemf::Type::DOUBLE));
                        return None {};
                    }))),
    testNameFormatter<FilterBuilderTest>("EndsWith"));
} // namespace filterbuildtest

namespace filteroperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    FilterOperationTest,
    testing::Values(
        // Value cases
        FilterT(
            R"({"target": "value"})", opfilter::opBuilderHelperEndsWith, "target", {makeValue(R"("e")")}, SUCCESS()),
        FilterT(
            R"({"target": "value"})", opfilter::opBuilderHelperEndsWith, "target", {makeValue(R"("lue")")}, SUCCESS()),
        FilterT(R"({"target": "value"})",
                opfilter::opBuilderHelperEndsWith,
                "target",
                {makeValue(R"("value")")},
                SUCCESS()),
        FilterT(
            R"({"target": "value"})", opfilter::opBuilderHelperEndsWith, "target", {makeValue(R"("v")")}, FAILURE()),
        FilterT(
            R"({"target": "value"})", opfilter::opBuilderHelperEndsWith, "target", {makeValue(R"("alu")")}, FAILURE()),
        FilterT(
            R"({"target": "value"})", opfilter::opBuilderHelperEndsWith, "target", {makeValue(R"("valu")")}, FAILURE()),
        FilterT(
            R"({"target": "value"})", opfilter::opBuilderHelperEndsWith, "target", {makeValue(R"("o")")}, FAILURE()),
        FilterT(
            R"({"target": "value"})", opfilter::opBuilderHelperEndsWith, "target", {makeValue(R"("van")")}, FAILURE()),
        FilterT(R"({"target": "value"})",
                opfilter::opBuilderHelperEndsWith,
                "target",
                {makeValue(R"("value2")")},
                FAILURE()),
        FilterT(
            R"({"target": "value"})", opfilter::opBuilderHelperEndsWith, "notTarget", {makeValue(R"("v")")}, FAILURE()),
        FilterT(R"({"target": 1})", opfilter::opBuilderHelperEndsWith, "target", {makeValue(R"("1")")}, FAILURE()),
        FilterT(R"({"target": 1.2})", opfilter::opBuilderHelperEndsWith, "target", {makeValue(R"("1.2")")}, FAILURE()),
        FilterT(
            R"({"target": true})", opfilter::opBuilderHelperEndsWith, "target", {makeValue(R"("true")")}, FAILURE()),
        FilterT(R"({"target": [1, 2, 3]})",
                opfilter::opBuilderHelperEndsWith,
                "target",
                {makeValue(R"("[1, 2, 3]")")},
                FAILURE()),
        FilterT(R"({"target": {"a": 1, "b": 2}})",
                opfilter::opBuilderHelperEndsWith,
                "target",
                {makeValue(R"("{\"a\": 1, \"b\": 2}")")},
                FAILURE()),
        // Reference cases
        FilterT(R"({"target": "value", "ref": "e"})",
                opfilter::opBuilderHelperEndsWith,
                "target",
                {makeRef("ref")},
                SUCCESS(customRef())),
        FilterT(R"({"target": "value", "ref": "lue"})",
                opfilter::opBuilderHelperEndsWith,
                "target",
                {makeRef("ref")},
                SUCCESS(customRef())),
        FilterT(R"({"target": "value", "ref": "value"})",
                opfilter::opBuilderHelperEndsWith,
                "target",
                {makeRef("ref")},
                SUCCESS(customRef())),
        FilterT(R"({"target": "value", "ref": "v"})",
                opfilter::opBuilderHelperEndsWith,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": "value", "ref": "alu"})",
                opfilter::opBuilderHelperEndsWith,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": "value", "ref": "valu"})",
                opfilter::opBuilderHelperEndsWith,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": "value", "ref": "o"})",
                opfilter::opBuilderHelperEndsWith,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": "value", "ref": "van"})",
                opfilter::opBuilderHelperEndsWith,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": "value", "ref": "value2"})",
                opfilter::opBuilderHelperEndsWith,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": "value", "ref": "v"})",
                opfilter::opBuilderHelperEndsWith,
                "notTarget",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": 1, "ref": "1"})",
                opfilter::opBuilderHelperEndsWith,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": 1.2, "ref": "1.2"})",
                opfilter::opBuilderHelperEndsWith,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": true, "ref": "true"})",
                opfilter::opBuilderHelperEndsWith,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": [1, 2, 3], "ref": "[1, 2, 3]"})",
                opfilter::opBuilderHelperEndsWith,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": {"a": 1, "b": 2}, "ref": "{\"a\": 1, \"b\": 2}"})",
                opfilter::opBuilderHelperEndsWith,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": "value", "ref": 1})",
                opfilter::opBuilderHelperEndsWith,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": "value", "ref": 1.2})",
                opfilter::opBuilderHelperEndsWith,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": "value", "ref": true})",
                opfilter::opBuilderHelperEndsWith,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": "value", "ref": [1, 2, 3]})",
                opfilter::opBuilderHelperEndsWith,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": "value", "ref": {"a": 1, "b": 2}})",
                opfilter::opBuilderHelperEndsWith,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": "value", "notRef": "v"})",
                opfilter::opBuilderHelperEndsWith,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        // Missing target field
        FilterT(R"({"other": "value"})", opfilter::opBuilderHelperEndsWith, "target", {makeValue(R"("v")")}, FAILURE()),
        FilterT(R"({"ref": "value"})",
                opfilter::opBuilderHelperEndsWith,
                "target",
                {makeRef("ref")},
                FAILURE(customRef()))),
    testNameFormatter<FilterOperationTest>("EndsWith"));

} // namespace filteroperatestest
