#include "builders/baseBuilders_test.hpp"
#include "builders/optransform/hlp.hpp"

using namespace builder::builders::optransform;

/* We test the common builder called by all hlp builders */
/* Using a dummy parser and parser builder to explore all paths of the helper */
namespace
{
auto dummyParserSuccess(const std::string_view& text)
{
    return hlp::abs::makeSuccess(hlp::parsers::SemToken {text, hlp::parsers::noSemParser()}, text.substr(text.size()));
}

auto dummyParserFailure(const std::string_view& text)
{
    return hlp::abs::makeFailure<hlp::parsers::ResultT>(text, "dummy");
}

auto dummyParserEofError(const std::string_view& text)
{
    return hlp::abs::makeSuccess(hlp::parsers::SemToken {text, hlp::parsers::noSemParser()}, text);
}

auto getBuilder(bool parserSuccess = true)
{
    auto parser = parserSuccess ? dummyParserSuccess : dummyParserFailure;

    return [=](const Reference& targetField,
               const std::vector<OpArg>& opArgs,
               const std::shared_ptr<const IBuildCtx>& buildCtx) -> TransformOp
    {
        return detail::specificHLPBuilder(
            targetField, opArgs, buildCtx, [parser](const hlp::Params& params) { return parser; });
    };
}

auto getBuilderEofError()
{
    return [=](const Reference& targetField,
               const std::vector<OpArg>& opArgs,
               const std::shared_ptr<const IBuildCtx>& buildCtx) -> TransformOp
    {
        return detail::specificHLPBuilder(
            targetField, opArgs, buildCtx, [](const hlp::Params& params) { return dummyParserEofError; });
    };
}

auto getBuilderParserBuilderThrows()
{
    return [=](const Reference& targetField,
               const std::vector<OpArg>& opArgs,
               const std::shared_ptr<const IBuildCtx>& buildCtx) -> TransformOp
    {
        return detail::specificHLPBuilder(targetField,
                                          opArgs,
                                          buildCtx,
                                          [](const hlp::Params& params) -> hlp::parser::Parser
                                          { throw std::runtime_error("error"); });
    };
}

auto expectCustomRef(const std::string& ref)
{
    return [ref](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.validator, hasField(DotPath(ref))).WillOnce(testing::Return(false));
        return None {};
    };
}

auto expectCustomRef(const std::string& ref, base::Event result)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.validator, hasField(DotPath(ref))).WillOnce(testing::Return(false));
        return result;
    };
}

auto expectJTypeRef(const std::string& ref, json::Json::Type jType)
{
    return [ref, jType](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks.validator, hasField(DotPath(ref))).WillOnce(testing::Return(true));
        EXPECT_CALL(*mocks.validator, getJsonType(DotPath(ref))).WillOnce(testing::Return(jType));

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
        TransformT({}, getBuilder(), FAILURE()),
        TransformT({makeRef("ref")}, getBuilder(), SUCCESS(expectCustomRef("ref"))),
        TransformT({makeRef("ref")}, getBuilder(), SUCCESS(expectJTypeRef("ref", json::Json::Type::String))),
        TransformT({makeValue(R"("value")")}, getBuilder(), FAILURE()),
        TransformT({makeRef("ref"), makeValue(R"("value")")}, getBuilder(), SUCCESS(expectCustomRef("ref"))),
        TransformT({makeRef("ref"), makeValue(R"(1)")}, getBuilder(), FAILURE()),
        TransformT({makeRef("ref"), makeRef("ref")}, getBuilder(), FAILURE()),
        TransformT({makeRef("ref"), makeValue(R"("value")"), makeValue(R"("value")")},
                   getBuilder(),
                   SUCCESS(expectCustomRef("ref"))),
        TransformT({makeRef("ref")}, getBuilderParserBuilderThrows(), FAILURE()),
        TransformT({makeRef("ref"), makeValue(R"("value")"), makeValue(R"("value")")},
                   getBuilder(),
                   FAILURE(
                       [](const auto& mocks)
                       {
                           EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("targetField")))
                               .WillOnce(testing::Return(false));
                           return None {};
                       }))),
    testNameFormatter<TransformBuilderTest>("HLP"));
} // namespace transformbuildtest

/* Mapping the target field is done by the parser, our dummy parser does not map*/
/* We only test succes and failure results, not the actual parser and mapping */
namespace transformoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    TransformOperationTest,
    testing::Values(
        TransformT(R"({"ref": "text"})",
                   getBuilder(),
                   "target",
                   {makeRef("ref")},
                   SUCCESS(expectCustomRef("ref", makeEvent(R"({"ref": "text"})")))),
        TransformT(
            R"({"ref": "text"})", getBuilder(false), "target", {makeRef("ref")}, FAILURE(expectCustomRef("ref"))),
        TransformT(
            R"({"ref": "text"})", getBuilderEofError(), "target", {makeRef("ref")}, FAILURE(expectCustomRef("ref"))),
        TransformT(R"({})", getBuilder(), "target", {makeRef("ref")}, FAILURE(expectCustomRef("ref"))),
        TransformT(R"({"ref": 1})", getBuilder(), "target", {makeRef("ref")}, FAILURE(expectCustomRef("ref")))),
    testNameFormatter<TransformOperationTest>("HLP"));
} // namespace transformoperatestest
