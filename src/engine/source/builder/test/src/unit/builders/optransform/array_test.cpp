#include "builders/baseBuilders_test.hpp"

#include "builders/opmap/opBuilderHelperMap.hpp"

using namespace builder::builders;

namespace
{
auto customRefExpected()
{
    return [](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, schema());
        EXPECT_CALL(*mocks.schema, hasField(DotPath("ref"))).WillOnce(testing::Return(false));
        return None {};
    };
}

auto customRefExpected(base::Event value)
{
    return [value](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, schema());
        EXPECT_CALL(*mocks.schema, hasField(DotPath("ref"))).WillOnce(testing::Return(false));
        return value;
    };
}

auto jTypeRefExpected(json::Json::Type jType)
{
    return [jType](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, schema()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks.schema, hasField(DotPath("ref"))).WillOnce(testing::Return(true));
        EXPECT_CALL(*mocks.ctx, validator());
        auto sType = schemf::Type::BINARY;
        EXPECT_CALL(*mocks.schema, getType(DotPath("ref"))).WillOnce(testing::Return(sType));
        EXPECT_CALL(*mocks.validator, getJsonType(sType)).WillOnce(testing::Return(jType));

        return None {};
    };
}

} // namespace
namespace transformbuildtest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    TransformBuilderTest,
    testing::Values(TransformT({}, opBuilderHelperAppendSplitString, FAILURE()),
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
                               FAILURE(jTypeRefExpected(json::Json::Type::Number)))),
    testNameFormatter<TransformBuilderTest>("ArrayAppendSplit"));
} // namespace transformbuildtest

namespace transformoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    TransformOperationTest,
    testing::Values(TransformT(R"({"ref": "a b c"})",
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
                               SUCCESS(customRefExpected(makeEvent(R"({"ref": ""})"))))),
    testNameFormatter<TransformOperationTest>("ArrayAppendSplit"));
} // namespace transformoperatestest
