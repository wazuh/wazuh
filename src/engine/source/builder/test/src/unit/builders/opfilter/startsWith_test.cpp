#include "builders/baseBuilders_test.hpp"

#include "builders/opfilter/startsWith.hpp"

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
        FilterT({}, opfilter::startsWithBuilder, FAILURE()),
        FilterT({makeValue(R"("string")"), makeValue(R"("string")")}, opfilter::startsWithBuilder, FAILURE()),
        // Value
        FilterT({makeValue(R"("string")")}, opfilter::startsWithBuilder, SUCCESS()),
        FilterT({makeValue(R"(2)")}, opfilter::startsWithBuilder, FAILURE()),
        FilterT({makeValue(R"(1.2)")}, opfilter::startsWithBuilder, FAILURE()),
        FilterT({makeValue(R"(true)")}, opfilter::startsWithBuilder, FAILURE()),
        FilterT({makeValue(R"(false)")}, opfilter::startsWithBuilder, FAILURE()),
        FilterT({makeValue(R"([1, 2, 3])")}, opfilter::startsWithBuilder, FAILURE()),
        FilterT({makeValue(R"({"a": 1, "b": 2})")}, opfilter::startsWithBuilder, FAILURE()),
        FilterT({makeValue(R"(null)")}, opfilter::startsWithBuilder, FAILURE()),
        // Reference
        FilterT({makeRef("ref")},
                opfilter::startsWithBuilder,
                SUCCESS(
                    [](const BuildersMocks& mocks)
                    {
                        EXPECT_CALL(*mocks.ctx, validator());
                        EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillRepeatedly(testing::Return(false));
                        return None {};
                    })),
        FilterT({makeRef("ref")},
                opfilter::startsWithBuilder,
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
                opfilter::startsWithBuilder,
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
                opfilter::startsWithBuilder,
                FAILURE(
                    [](const BuildersMocks& mocks)
                    {
                        EXPECT_CALL(*mocks.ctx, validator());
                        EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillRepeatedly(testing::Return(true));
                        EXPECT_CALL(*mocks.validator, getType(DotPath("ref")))
                            .WillRepeatedly(testing::Return(schemf::Type::DOUBLE));
                        return None {};
                    }))),
    testNameFormatter<FilterBuilderTest>("StartsWith"));
} // namespace filterbuildtest

namespace filteroperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    FilterOperationTest,
    testing::Values(
        // Value cases
        FilterT(R"({"target": "value"})", opfilter::startsWithBuilder, "target", {makeValue(R"("v")")}, SUCCESS()),
        FilterT(R"({"target": "value"})", opfilter::startsWithBuilder, "target", {makeValue(R"("val")")}, SUCCESS()),
        FilterT(R"({"target": "value"})", opfilter::startsWithBuilder, "target", {makeValue(R"("value")")}, SUCCESS()),
        FilterT(R"({"target": "value"})", opfilter::startsWithBuilder, "target", {makeValue(R"("a")")}, FAILURE()),
        FilterT(R"({"target": "value"})", opfilter::startsWithBuilder, "target", {makeValue(R"("alu")")}, FAILURE()),
        FilterT(R"({"target": "value"})", opfilter::startsWithBuilder, "target", {makeValue(R"("alue")")}, FAILURE()),
        FilterT(R"({"target": "value"})", opfilter::startsWithBuilder, "target", {makeValue(R"("o")")}, FAILURE()),
        FilterT(R"({"target": "value"})", opfilter::startsWithBuilder, "target", {makeValue(R"("van")")}, FAILURE()),
        FilterT(R"({"target": "value"})", opfilter::startsWithBuilder, "target", {makeValue(R"("value2")")}, FAILURE()),
        FilterT(R"({"target": "value"})", opfilter::startsWithBuilder, "notTarget", {makeValue(R"("v")")}, FAILURE()),
        FilterT(R"({"target": 1})", opfilter::startsWithBuilder, "target", {makeValue(R"("1")")}, FAILURE()),
        FilterT(R"({"target": 1.2})", opfilter::startsWithBuilder, "target", {makeValue(R"("1.2")")}, FAILURE()),
        FilterT(R"({"target": true})", opfilter::startsWithBuilder, "target", {makeValue(R"("true")")}, FAILURE()),
        FilterT(R"({"target": [1, 2, 3]})",
                opfilter::startsWithBuilder,
                "target",
                {makeValue(R"("[1, 2, 3]")")},
                FAILURE()),
        FilterT(R"({"target": {"a": 1, "b": 2}})",
                opfilter::startsWithBuilder,
                "target",
                {makeValue(R"("{\"a\": 1, \"b\": 2}")")},
                FAILURE()),
        // Reference cases
        FilterT(R"({"target": "value", "ref": "v"})",
                opfilter::startsWithBuilder,
                "target",
                {makeRef("ref")},
                SUCCESS(customRef())),
        FilterT(R"({"target": "value", "ref": "val"})",
                opfilter::startsWithBuilder,
                "target",
                {makeRef("ref")},
                SUCCESS(customRef())),
        FilterT(R"({"target": "value", "ref": "value"})",
                opfilter::startsWithBuilder,
                "target",
                {makeRef("ref")},
                SUCCESS(customRef())),
        FilterT(R"({"target": "value", "ref": "a"})",
                opfilter::startsWithBuilder,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": "value", "ref": "alu"})",
                opfilter::startsWithBuilder,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": "value", "ref": "alue"})",
                opfilter::startsWithBuilder,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": "value", "ref": "o"})",
                opfilter::startsWithBuilder,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": "value", "ref": "van"})",
                opfilter::startsWithBuilder,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": "value", "ref": "value2"})",
                opfilter::startsWithBuilder,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": "value", "ref": "v"})",
                opfilter::startsWithBuilder,
                "notTarget",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": 1, "ref": "1"})",
                opfilter::startsWithBuilder,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": 1.2, "ref": "1.2"})",
                opfilter::startsWithBuilder,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": true, "ref": "true"})",
                opfilter::startsWithBuilder,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": [1, 2, 3], "ref": "[1, 2, 3]"})",
                opfilter::startsWithBuilder,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": {"a": 1, "b": 2}, "ref": "{\"a\": 1, \"b\": 2}"})",
                opfilter::startsWithBuilder,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": "value", "ref": 1})",
                opfilter::startsWithBuilder,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": "value", "ref": 1.2})",
                opfilter::startsWithBuilder,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": "value", "ref": true})",
                opfilter::startsWithBuilder,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": "value", "ref": [1, 2, 3]})",
                opfilter::startsWithBuilder,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": "value", "ref": {"a": 1, "b": 2}})",
                opfilter::startsWithBuilder,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        FilterT(R"({"target": "value", "notRef": "v"})",
                opfilter::startsWithBuilder,
                "target",
                {makeRef("ref")},
                FAILURE(customRef())),
        // Missing target field
        FilterT(R"({"other": "value"})", opfilter::startsWithBuilder, "target", {makeValue(R"("v")")}, FAILURE()),
        FilterT(R"({"ref": "value"})", opfilter::startsWithBuilder, "target", {makeRef("ref")}, FAILURE(customRef()))),
    testNameFormatter<FilterOperationTest>("StartsWith"));

} // namespace filteroperatestest
