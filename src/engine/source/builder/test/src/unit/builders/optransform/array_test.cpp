#include "builders/baseBuilders_test.hpp"

#include "builders/opmap/opBuilderHelperMap.hpp"
#include "builders/optransform/array.hpp"

using namespace builder::builders;

namespace
{
auto customRefExpected()
{
    return [](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillOnce(testing::Return(false));
        return None {};
    };
}

auto customRefExpected(base::Event value)
{
    return [value](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillOnce(testing::Return(false));
        return value;
    };
}

auto jTypeRefExpected(json::Json::Type jType)
{
    return [jType](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillOnce(testing::Return(true));
        EXPECT_CALL(*mocks.validator, getJsonType(DotPath("ref"))).WillOnce(testing::Return(jType));

        return None {};
    };
}

auto customTargetExpected(bool hasField = true, schemf::Type type = schemf::Type::KEYWORD)
{
    return [hasField, type](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks.validator, validate(DotPath("targetField"), testing::_))
            .WillOnce(testing::Return(schemf::ValidationResult()));
        EXPECT_CALL(*mocks.validator, hasField(DotPath("targetField"))).WillOnce(testing::Return(hasField));
        if (hasField)
        {
            EXPECT_CALL(*mocks.validator, getType(DotPath("targetField"))).WillOnce(testing::Return(type));
        }
        return None {};
    };
}

auto arrayTargetExpected(bool hasField = true, schemf::Type type = schemf::Type::KEYWORD)
{
    return [hasField, type](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks.validator, validate(DotPath("targetField"), testing::_))
            .WillOnce(testing::Return(schemf::ValidationResult(
                [](const json::Json& json) -> base::OptError
                {
                    if (json.isArray())
                    {
                        return base::noError();
                    }
                    return base::Error {"Not an array"};
                })));
        EXPECT_CALL(*mocks.validator, hasField(DotPath("targetField"))).WillOnce(testing::Return(hasField));
        if (hasField)
        {
            EXPECT_CALL(*mocks.validator, getType(DotPath("targetField"))).WillOnce(testing::Return(type));
        }
        return None {};
    };
}

} // namespace
namespace transformbuildtest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    TransformBuilderTest,
    testing::Values(
        /*** Append Split ***/
        TransformT({}, opBuilderHelperAppendSplitString, FAILURE()),
        TransformT({makeRef("ref")}, opBuilderHelperAppendSplitString, FAILURE()),
        TransformT({makeValue(R"("a")")}, opBuilderHelperAppendSplitString, FAILURE()),
        TransformT({makeRef("ref"), makeValue(R"("a")")},
                   opBuilderHelperAppendSplitString,
                   SUCCESS(customRefExpected())),
        TransformT({makeRef("ref"), makeValue(R"("aa")")}, opBuilderHelperAppendSplitString, FAILURE()),
        TransformT({makeValue(R"("a")"), makeRef("ref")}, opBuilderHelperAppendSplitString, FAILURE()),
        TransformT({makeRef("ref"), makeValue(R"("a")"), makeValue(R"("b")")},
                   opBuilderHelperAppendSplitString,
                   FAILURE()),
        TransformT({makeRef("ref"), makeValue(R"(1)")}, opBuilderHelperAppendSplitString, FAILURE()),
        TransformT({makeRef("ref"), makeValue(R"("a")")},
                   opBuilderHelperAppendSplitString,
                   SUCCESS(jTypeRefExpected(json::Json::Type::String))),
        TransformT({makeRef("ref"), makeValue(R"("a")")},
                   opBuilderHelperAppendSplitString,
                   FAILURE(jTypeRefExpected(json::Json::Type::Number))),
        TransformT({makeRef("ref"), makeValue(R"("a")")},
                   opBuilderHelperAppendSplitString,
                   FAILURE(
                       [](const auto& mocks)
                       {
                           EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("targetField")))
                               .WillOnce(testing::Return(false));
                           return None {};
                       })),
        /*** Append ***/
        TransformT({}, optransform::getArrayAppendBuilder(), FAILURE()),
        TransformT({makeRef("ref")}, optransform::getArrayAppendBuilder(), SUCCESS(customTargetExpected())),
        TransformT({makeValue(R"("a")")}, optransform::getArrayAppendBuilder(), SUCCESS(customTargetExpected())),
        TransformT({makeValue(R"(1)")},
                   optransform::getArrayAppendBuilder(),
                   SUCCESS(customTargetExpected(true, schemf::Type::INTEGER))),
        TransformT({makeValue(R"(1.1)")},
                   optransform::getArrayAppendBuilder(),
                   SUCCESS(customTargetExpected(true, schemf::Type::DOUBLE))),
        TransformT({makeValue(R"(true)")},
                   optransform::getArrayAppendBuilder(),
                   SUCCESS(customTargetExpected(true, schemf::Type::BOOLEAN))),
        TransformT({makeValue(R"(null)")}, optransform::getArrayAppendBuilder(), FAILURE(customTargetExpected())),
        TransformT({makeValue(R"([])")}, optransform::getArrayAppendBuilder(), FAILURE(customTargetExpected())),
        TransformT({makeValue(R"({})")}, optransform::getArrayAppendBuilder(), FAILURE(customTargetExpected())),
        TransformT({makeRef("ref"), makeValue(R"("a")")},
                   optransform::getArrayAppendBuilder(),
                   SUCCESS(customTargetExpected())),
        TransformT({makeRef("ref")}, optransform::getArrayAppendBuilder(), SUCCESS(arrayTargetExpected())),
        TransformT({makeValue(R"("a")")}, optransform::getArrayAppendBuilder(), SUCCESS(arrayTargetExpected())),
        TransformT({makeValue(R"(1)")},
                   optransform::getArrayAppendBuilder(),
                   SUCCESS(arrayTargetExpected(true, schemf::Type::INTEGER))),
        TransformT({makeValue(R"(1.1)")},
                   optransform::getArrayAppendBuilder(),
                   SUCCESS(arrayTargetExpected(true, schemf::Type::DOUBLE))),
        TransformT({makeValue(R"(true)")},
                   optransform::getArrayAppendBuilder(),
                   SUCCESS(arrayTargetExpected(true, schemf::Type::BOOLEAN))),
        TransformT({makeValue(R"(null)")}, optransform::getArrayAppendBuilder(), FAILURE(arrayTargetExpected())),
        TransformT({makeValue(R"([])")}, optransform::getArrayAppendBuilder(), FAILURE(arrayTargetExpected())),
        TransformT({makeValue(R"({})")}, optransform::getArrayAppendBuilder(), FAILURE(arrayTargetExpected())),
        TransformT({makeRef("ref"), makeValue(R"("a")")},
                   optransform::getArrayAppendBuilder(),
                   SUCCESS(arrayTargetExpected())),
        TransformT({makeValue(R"(1)")},
                   optransform::getArrayAppendBuilder(),
                   FAILURE(
                       [](const auto& mocks)
                       {
                           EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("targetField")))
                               .WillOnce(testing::Return(false));
                           return None {};
                       })),
        /*** Append Unique ***/
        TransformT({}, optransform::getArrayAppendBuilder(true), FAILURE()),
        TransformT({makeRef("ref")}, optransform::getArrayAppendBuilder(true), SUCCESS(customTargetExpected())),
        TransformT({makeValue(R"("a")")}, optransform::getArrayAppendBuilder(true), SUCCESS(customTargetExpected())),
        TransformT({makeValue(R"(1)")},
                   optransform::getArrayAppendBuilder(true),
                   SUCCESS(customTargetExpected(true, schemf::Type::INTEGER))),
        TransformT({makeValue(R"(1.1)")},
                   optransform::getArrayAppendBuilder(true),
                   SUCCESS(customTargetExpected(true, schemf::Type::DOUBLE))),
        TransformT({makeValue(R"(true)")},
                   optransform::getArrayAppendBuilder(true),
                   SUCCESS(customTargetExpected(true, schemf::Type::BOOLEAN))),
        TransformT({makeValue(R"(null)")}, optransform::getArrayAppendBuilder(true), FAILURE(customTargetExpected())),
        TransformT({makeValue(R"([])")}, optransform::getArrayAppendBuilder(true), FAILURE(customTargetExpected())),
        TransformT({makeValue(R"({})")}, optransform::getArrayAppendBuilder(true), FAILURE(customTargetExpected())),
        TransformT({makeRef("ref"), makeValue(R"("a")")},
                   optransform::getArrayAppendBuilder(true),
                   SUCCESS(customTargetExpected())),
        TransformT({makeRef("ref")}, optransform::getArrayAppendBuilder(true), SUCCESS(arrayTargetExpected())),
        TransformT({makeValue(R"("a")")}, optransform::getArrayAppendBuilder(true), SUCCESS(arrayTargetExpected())),
        TransformT({makeValue(R"(1)")},
                   optransform::getArrayAppendBuilder(true),
                   SUCCESS(arrayTargetExpected(true, schemf::Type::INTEGER))),
        TransformT({makeValue(R"(1.1)")},
                   optransform::getArrayAppendBuilder(true),
                   SUCCESS(arrayTargetExpected(true, schemf::Type::DOUBLE))),
        TransformT({makeValue(R"(true)")},
                   optransform::getArrayAppendBuilder(true),
                   SUCCESS(arrayTargetExpected(true, schemf::Type::BOOLEAN))),
        TransformT({makeValue(R"(null)")}, optransform::getArrayAppendBuilder(true), FAILURE(arrayTargetExpected())),
        TransformT({makeValue(R"([])")}, optransform::getArrayAppendBuilder(true), FAILURE(arrayTargetExpected())),
        TransformT({makeValue(R"({})")}, optransform::getArrayAppendBuilder(true), FAILURE(arrayTargetExpected())),
        TransformT({makeRef("ref"), makeValue(R"("a")")},
                   optransform::getArrayAppendBuilder(true),
                   SUCCESS(arrayTargetExpected())),
        TransformT({makeValue(R"(1)")},
                   optransform::getArrayAppendBuilder(true),
                   FAILURE(
                       [](const auto& mocks)
                       {
                           EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("targetField")))
                               .WillOnce(testing::Return(false));
                           return None {};
                       }))),
    testNameFormatter<TransformBuilderTest>("ArrayAppend"));
} // namespace transformbuildtest

namespace transformoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    TransformOperationTest,
    testing::Values(
        /*** Append Split ***/
        TransformT(R"({"ref": "a b c"})",
                   opBuilderHelperAppendSplitString,
                   "target",
                   {makeRef("ref"), makeValue(R"(" ")")},
                   SUCCESS(customRefExpected(makeEvent(R"({"ref": "a b c", "target": ["a", "b", "c"]})")))),
        TransformT(R"({"ref": "a b c"})",
                   opBuilderHelperAppendSplitString,
                   "target",
                   {makeRef("ref"), makeValue(R"("-")")},
                   SUCCESS(customRefExpected(makeEvent(R"({"ref": "a b c", "target": ["a b c"]})")))),
        TransformT(R"({"ref": " b "})",
                   opBuilderHelperAppendSplitString,
                   "target",
                   {makeRef("ref"), makeValue(R"(" ")")},
                   SUCCESS(customRefExpected(makeEvent(R"({"ref": " b ", "target": ["b"]})")))),
        TransformT(R"({"notRef": "a b c"})",
                   opBuilderHelperAppendSplitString,
                   "target",
                   {makeRef("ref"), makeValue(R"(" ")")},
                   FAILURE(customRefExpected())),
        TransformT(R"({"ref": 1})",
                   opBuilderHelperAppendSplitString,
                   "target",
                   {makeRef("ref"), makeValue(R"(" ")")},
                   FAILURE(customRefExpected())),
        TransformT(R"({"ref": 1.1})",
                   opBuilderHelperAppendSplitString,
                   "target",
                   {makeRef("ref"), makeValue(R"(" ")")},
                   FAILURE(customRefExpected())),
        TransformT(R"({"ref": true})",
                   opBuilderHelperAppendSplitString,
                   "target",
                   {makeRef("ref"), makeValue(R"(" ")")},
                   FAILURE(customRefExpected())),
        TransformT(R"({"ref": null})",
                   opBuilderHelperAppendSplitString,
                   "target",
                   {makeRef("ref"), makeValue(R"(" ")")},
                   FAILURE(customRefExpected())),
        TransformT(R"({"ref": []})",
                   opBuilderHelperAppendSplitString,
                   "target",
                   {makeRef("ref"), makeValue(R"(" ")")},
                   FAILURE(customRefExpected())),
        TransformT(R"({"ref": {}})",
                   opBuilderHelperAppendSplitString,
                   "target",
                   {makeRef("ref"), makeValue(R"(" ")")},
                   FAILURE(customRefExpected())),
        TransformT(R"({"ref": ""})",
                   opBuilderHelperAppendSplitString,
                   "target",
                   {makeRef("ref"), makeValue(R"(" ")")},
                   SUCCESS(customRefExpected(makeEvent(R"({"ref": ""})")))),
        /*** Append ***/
        TransformT(R"({"ref": "a"})",
                   optransform::getArrayAppendBuilder(),
                   "targetField",
                   {makeRef("ref")},
                   SUCCESS(
                       [](const auto& mocks)
                       {
                           customTargetExpected(false)(mocks);
                           return makeEvent(R"({"ref": "a", "targetField": ["a"]})");
                       })),
        TransformT(R"({"ref": "a", "targetField": ["b"]})",
                   optransform::getArrayAppendBuilder(),
                   "targetField",
                   {makeRef("ref")},
                   SUCCESS(
                       [](const auto& mocks)
                       {
                           customTargetExpected()(mocks);
                           return makeEvent(R"({"ref": "a", "targetField": ["b", "a"]})");
                       })),
        TransformT(R"({"ref": "a"})",
                   optransform::getArrayAppendBuilder(),
                   "targetField",
                   {makeRef("ref")},
                   SUCCESS(
                       [](const auto& mocks)
                       {
                           arrayTargetExpected()(mocks);
                           return makeEvent(R"({"ref": "a", "targetField": ["a"]})");
                       })),
        TransformT(R"({"ref": "a", "targetField": ["b"]})",
                   optransform::getArrayAppendBuilder(),
                   "targetField",
                   {makeRef("ref")},
                   SUCCESS(
                       [](const auto& mocks)
                       {
                           arrayTargetExpected()(mocks);
                           return makeEvent(R"({"ref": "a", "targetField": ["b", "a"]})");
                       })),
        TransformT(R"({"ref": "a", "targetField": "not array"})",
                   optransform::getArrayAppendBuilder(),
                   "targetField",
                   {makeRef("ref")},
                   FAILURE(customTargetExpected())),
        TransformT(R"({})",
                   optransform::getArrayAppendBuilder(),
                   "targetField",
                   {makeRef("ref")},
                   FAILURE(customTargetExpected())),
        TransformT(R"({})",
                   optransform::getArrayAppendBuilder(false, true),
                   "targetField",
                   {makeRef("ref"), makeValue(R"("a")")},
                   SUCCESS(
                       [](const auto& mocks)
                       {
                           customTargetExpected()(mocks);
                           return makeEvent(R"({"targetField": ["a"]})");
                       })),
        TransformT(R"({})",
                   optransform::getArrayAppendBuilder(),
                   "targetField",
                   {makeValue(R"("a")"), makeValue(R"("a")")},
                   SUCCESS(
                       [](const auto& mocks)
                       {
                           customTargetExpected()(mocks);
                           return makeEvent(R"({"targetField": ["a", "a"]})");
                       })),
        TransformT(R"({})",
                   optransform::getArrayAppendBuilder(),
                   "targetField",
                   {makeValue(R"("a")"), makeValue(R"("b")")},
                   SUCCESS(
                       [](const auto& mocks)
                       {
                           customTargetExpected()(mocks);
                           return makeEvent(R"({"targetField": ["a", "b"]})");
                       })),
        TransformT(R"({})",
                   optransform::getArrayAppendBuilder(),
                   "targetField",
                   {makeValue(R"("a")"), makeValue(R"("a")")},
                   SUCCESS(
                       [](const auto& mocks)
                       {
                           arrayTargetExpected()(mocks);
                           return makeEvent(R"({"targetField": ["a", "a"]})");
                       })),
        TransformT(R"({})",
                   optransform::getArrayAppendBuilder(),
                   "targetField",
                   {makeValue(R"("a")"), makeValue(R"("b")")},
                   SUCCESS(
                       [](const auto& mocks)
                       {
                           arrayTargetExpected()(mocks);
                           return makeEvent(R"({"targetField": ["a", "b"]})");
                       })),
        /*** Append Unique ***/
        TransformT(R"({"ref": "a"})",
                   optransform::getArrayAppendBuilder(true),
                   "targetField",
                   {makeRef("ref")},
                   SUCCESS(
                       [](const auto& mocks)
                       {
                           customTargetExpected()(mocks);
                           return makeEvent(R"({"ref": "a", "targetField": ["a"]})");
                       })),
        TransformT(R"({"ref": "a", "targetField": ["b"]})",
                   optransform::getArrayAppendBuilder(true),
                   "targetField",
                   {makeRef("ref")},
                   SUCCESS(
                       [](const auto& mocks)
                       {
                           customTargetExpected()(mocks);
                           return makeEvent(R"({"ref": "a", "targetField": ["b", "a"]})");
                       })),
        TransformT(R"({"ref": "a"})",
                   optransform::getArrayAppendBuilder(true),
                   "targetField",
                   {makeRef("ref")},
                   SUCCESS(
                       [](const auto& mocks)
                       {
                           arrayTargetExpected()(mocks);
                           return makeEvent(R"({"ref": "a", "targetField": ["a"]})");
                       })),
        TransformT(R"({"ref": "a", "targetField": ["b"]})",
                   optransform::getArrayAppendBuilder(true),
                   "targetField",
                   {makeRef("ref")},
                   SUCCESS(
                       [](const auto& mocks)
                       {
                           arrayTargetExpected()(mocks);
                           return makeEvent(R"({"ref": "a", "targetField": ["b", "a"]})");
                       })),
        TransformT(R"({"ref": "a", "targetField": "not array"})",
                   optransform::getArrayAppendBuilder(true),
                   "targetField",
                   {makeRef("ref")},
                   FAILURE(customTargetExpected())),
        TransformT(R"({})",
                   optransform::getArrayAppendBuilder(true),
                   "targetField",
                   {makeRef("ref")},
                   FAILURE(customTargetExpected())),
        TransformT(R"({})",
                   optransform::getArrayAppendBuilder(true, true),
                   "targetField",
                   {makeRef("ref"), makeValue(R"("a")")},
                   SUCCESS(
                       [](const auto& mocks)
                       {
                           customTargetExpected()(mocks);
                           return makeEvent(R"({"targetField": ["a"]})");
                       })),
        TransformT(R"({})",
                   optransform::getArrayAppendBuilder(true),
                   "targetField",
                   {makeValue(R"("a")"), makeValue(R"("a")")},
                   SUCCESS(
                       [](const auto& mocks)
                       {
                           customTargetExpected()(mocks);
                           return makeEvent(R"({"targetField": ["a"]})");
                       })),
        TransformT(R"({})",
                   optransform::getArrayAppendBuilder(true),
                   "targetField",
                   {makeValue(R"("a")"), makeValue(R"("b")")},
                   SUCCESS(
                       [](const auto& mocks)
                       {
                           customTargetExpected()(mocks);
                           return makeEvent(R"({"targetField": ["a", "b"]})");
                       })),
        TransformT(R"({})",
                   optransform::getArrayAppendBuilder(true),
                   "targetField",
                   {makeValue(R"("a")"), makeValue(R"("a")")},
                   SUCCESS(
                       [](const auto& mocks)
                       {
                           arrayTargetExpected()(mocks);
                           return makeEvent(R"({"targetField": ["a"]})");
                       })),
        TransformT(R"({})",
                   optransform::getArrayAppendBuilder(true),
                   "targetField",
                   {makeValue(R"("a")"), makeValue(R"("b")")},
                   SUCCESS(
                       [](const auto& mocks)
                       {
                           arrayTargetExpected()(mocks);
                           return makeEvent(R"({"targetField": ["a", "b"]})");
                       }))),
    testNameFormatter<TransformOperationTest>("ArrayAppend"));
} // namespace transformoperatestest
