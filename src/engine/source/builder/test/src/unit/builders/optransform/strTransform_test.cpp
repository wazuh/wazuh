#include "builders/baseBuilders_test.hpp"

#include "builders/opmap/opBuilderHelperMap.hpp"

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

auto customRefExpected(json::Json jValue)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillOnce(testing::Return(false));
        return jValue;
    };
}

auto jTypeRefExpected(json::Json::Type jType)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillOnce(testing::Return(true));
        EXPECT_CALL(*mocks.validator, getJsonType(DotPath("ref"))).WillOnce(testing::Return(jType));
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
        /*** Trim ***/
        TransformT({}, opBuilderHelperStringTrim, FAILURE()),
        TransformT({makeValue(R"("begin")")}, opBuilderHelperStringTrim, FAILURE()),
        TransformT({makeValue(R"("begin")"), makeValue(R"("c")")}, opBuilderHelperStringTrim, SUCCESS()),
        TransformT({makeValue(R"("begin")"), makeValue(R"("chars")")}, opBuilderHelperStringTrim, FAILURE()),
        TransformT({makeValue(R"("end")"), makeValue(R"("c")")}, opBuilderHelperStringTrim, SUCCESS()),
        TransformT({makeValue(R"("end")"), makeValue(R"("chars")")}, opBuilderHelperStringTrim, FAILURE()),
        TransformT({makeValue(R"("both")"), makeValue(R"("c")")}, opBuilderHelperStringTrim, SUCCESS()),
        TransformT({makeValue(R"("both")"), makeValue(R"("chars")")}, opBuilderHelperStringTrim, FAILURE()),
        TransformT({makeValue(R"("begin")"), makeValue(R"("c")"), makeValue(R"("other")")},
                   opBuilderHelperStringTrim,
                   FAILURE()),
        TransformT({makeRef("ref")}, opBuilderHelperStringTrim, FAILURE()),
        TransformT({makeRef("ref"), makeRef("ref")}, opBuilderHelperStringTrim, FAILURE()),
        TransformT({makeRef("ref"), makeValue(R"("c")")}, opBuilderHelperStringTrim, FAILURE()),
        TransformT({makeValue(R"("begin")"), makeRef("ref")}, opBuilderHelperStringTrim, FAILURE()),
        TransformT({makeValue(R"("begin")"), makeValue(R"("c")")},
                   opBuilderHelperStringTrim,
                   FAILURE(
                       [](const auto& mocks)
                       {
                           EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("targetField")))
                               .WillOnce(testing::Return(false));
                           return None {};
                       })),
        /*** Replace ***/
        TransformT({}, opBuilderHelperStringReplace, FAILURE()),
        TransformT({makeValue(R"("a")")}, opBuilderHelperStringReplace, FAILURE()),
        TransformT({makeValue(R"("a")"), makeValue(R"("b")")}, opBuilderHelperStringReplace, SUCCESS()),
        TransformT({makeValue(R"("a")"), makeValue(R"("b")"), makeValue(R"("c")")},
                   opBuilderHelperStringReplace,
                   FAILURE()),
        TransformT({makeRef("ref")}, opBuilderHelperStringReplace, FAILURE()),
        TransformT({makeRef("ref"), makeRef("ref")}, opBuilderHelperStringReplace, FAILURE()),
        TransformT({makeRef("ref"), makeValue(R"("b")")}, opBuilderHelperStringReplace, FAILURE()),
        TransformT({makeValue(R"("a")"), makeRef("ref")}, opBuilderHelperStringReplace, FAILURE()),
        TransformT({makeValue(R"("")"), makeValue(R"("b")")}, opBuilderHelperStringReplace, FAILURE()),
        TransformT({makeValue(R"("a")"), makeValue(R"("")")}, opBuilderHelperStringReplace, SUCCESS()),
        TransformT({makeValue(R"("begin")"), makeValue(R"("c")")},
                   opBuilderHelperStringReplace,
                   FAILURE(
                       [](const auto& mocks)
                       {
                           EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("targetField")))
                               .WillOnce(testing::Return(false));
                           return None {};
                       }))),
    testNameFormatter<TransformBuilderTest>("StrTransform"));
} // namespace transformbuildtest

namespace transformoperatestest
{
INSTANTIATE_TEST_SUITE_P(Builders,
                         TransformOperationTest,
                         testing::Values(
                             /*** Trim ***/
                             TransformT(R"({"target": "--value--"})",
                                        opBuilderHelperStringTrim,
                                        "target",
                                        {makeValue(R"("begin")"), makeValue(R"("-")")},
                                        SUCCESS(makeEvent(R"({"target": "value--"})"))),
                             TransformT(R"({"target": "--value--"})",
                                        opBuilderHelperStringTrim,
                                        "target",
                                        {makeValue(R"("end")"), makeValue(R"("-")")},
                                        SUCCESS(makeEvent(R"({"target": "--value"})"))),
                             TransformT(R"({"target": "--value--"})",
                                        opBuilderHelperStringTrim,
                                        "target",
                                        {makeValue(R"("both")"), makeValue(R"("-")")},
                                        SUCCESS(makeEvent(R"({"target": "value"})"))),
                             TransformT(R"({"target": "--value--"})",
                                        opBuilderHelperStringTrim,
                                        "notTarget",
                                        {makeValue(R"("begin")"), makeValue(R"("-")")},
                                        FAILURE()),
                             TransformT(R"({"target": "--value--"})",
                                        opBuilderHelperStringTrim,
                                        "target",
                                        {makeValue(R"("begin")"), makeValue(R"("/")")},
                                        SUCCESS(makeEvent(R"({"target": "--value--"})"))),
                             /*** Replace ***/
                             TransformT(R"({"target": "--value--"})",
                                        opBuilderHelperStringReplace,
                                        "target",
                                        {makeValue(R"("-")"), makeValue(R"("+")")},
                                        SUCCESS(makeEvent(R"({"target": "++value++"})"))),
                             TransformT(R"({"target": "--value--"})",
                                        opBuilderHelperStringReplace,
                                        "target",
                                        {makeValue(R"("l")"), makeValue(R"("")")},
                                        SUCCESS(makeEvent(R"({"target": "--vaue--"})"))),
                             TransformT(R"({"target": "--value--"})",
                                        opBuilderHelperStringReplace,
                                        "target",
                                        {makeValue(R"("--")"), makeValue(R"("+")")},
                                        SUCCESS(makeEvent(R"({"target": "+value+"})"))),
                             TransformT(R"({"target": "--value--"})",
                                        opBuilderHelperStringReplace,
                                        "target",
                                        {makeValue(R"("-")"), makeValue(R"("++")")},
                                        SUCCESS(makeEvent(R"({"target": "++++value++++"})"))),
                             TransformT(R"({"target": "--value--"})",
                                        opBuilderHelperStringReplace,
                                        "target",
                                        {makeValue(R"("x")"), makeValue(R"("y")")},
                                        SUCCESS(makeEvent(R"({"target": "--value--"})"))),
                             TransformT(R"({"target": "--value--"})",
                                        opBuilderHelperStringReplace,
                                        "notTarget",
                                        {makeValue(R"("-")"), makeValue(R"("+")")},
                                        FAILURE()),
                             TransformT(R"({"target": 1})",
                                        opBuilderHelperStringReplace,
                                        "target",
                                        {makeValue(R"("-")"), makeValue(R"("+")")},
                                        FAILURE()),
                             TransformT(R"({"target": 1.1})",
                                        opBuilderHelperStringReplace,
                                        "target",
                                        {makeValue(R"("-")"), makeValue(R"("+")")},
                                        FAILURE()),
                             TransformT(R"({"target": true})",
                                        opBuilderHelperStringReplace,
                                        "target",
                                        {makeValue(R"("-")"), makeValue(R"("+")")},
                                        FAILURE()),
                             TransformT(R"({"target": null})",
                                        opBuilderHelperStringReplace,
                                        "target",
                                        {makeValue(R"("-")"), makeValue(R"("+")")},
                                        FAILURE()),
                             TransformT(R"({"target": []})",
                                        opBuilderHelperStringReplace,
                                        "target",
                                        {makeValue(R"("-")"), makeValue(R"("+")")},
                                        FAILURE()),
                             TransformT(R"({"target": {}})",
                                        opBuilderHelperStringReplace,
                                        "target",
                                        {makeValue(R"("-")"), makeValue(R"("+")")},
                                        FAILURE())),
                         testNameFormatter<TransformOperationTest>("StrTransform"));

}
