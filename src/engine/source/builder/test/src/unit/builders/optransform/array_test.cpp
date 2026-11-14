// SPDX-License-Identifier: AGPL-3.0-or-later
#include "builders/baseBuilders_test.hpp"

#include "builders/opmap/opBuilderHelperMap.hpp"
#include "builders/optransform/array.hpp"

using namespace builder::builders;

namespace
{
OpArg makeStringOnlyValue(std::string value)
{
    return std::make_shared<Value>(std::move(value));
}

auto customTargetExpected(bool hasField = true, schemf::Type type = schemf::Type::KEYWORD)
{
    return [hasField, type](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks.validator,
                    validate(DotPath("targetField"), testing::Matcher<const schemf::ValidationToken&>(testing::_)))
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
        EXPECT_CALL(*mocks.validator,
                    validate(DotPath("targetField"), testing::Matcher<const schemf::ValidationToken&>(testing::_)))
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
INSTANTIATE_TEST_SUITE_P(Builders,
                         TransformOperationTest,
                         testing::Values(
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
                             TransformT(R"({"ref": "a", "targetField": []})",
                                        optransform::getArrayAppendBuilder(),
                                        "targetField",
                                        {makeRef("ref")},
                                        SUCCESS(
                                            [](const auto& mocks)
                                            {
                                                customTargetExpected()(mocks);
                                                return makeEvent(R"({"ref": "a", "targetField": ["a"]})");
                                            })),
                             TransformT(R"({"targetField": []})",
                                        optransform::getArrayAppendBuilder(),
                                        "targetField",
                                        {makeStringOnlyValue("a")},
                                        SUCCESS(
                                            [](const auto& mocks)
                                            {
                                                customTargetExpected()(mocks);
                                                return makeEvent(R"({"targetField": ["a"]})");
                                            })),
                             TransformT(R"({"targetField": []})",
                                        optransform::getArrayAppendBuilder(),
                                        "targetField",
                                        {makeRef("ref")},
                                        FAILURE(customTargetExpected())),
                             TransformT(R"({"targetField": []})",
                                        optransform::getArrayAppendBuilder(false, true),
                                        "targetField",
                                        {makeRef("ref")},
                                        FAILURE(customTargetExpected())),
                             TransformT(R"({"targetField": [1]})",
                                        optransform::getArrayAppendBuilder(),
                                        "targetField",
                                        {makeStringOnlyValue("a")},
                                        FAILURE(customTargetExpected(false))),
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
