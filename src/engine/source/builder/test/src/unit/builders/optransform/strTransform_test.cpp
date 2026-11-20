// SPDX-License-Identifier: AGPL-3.0-or-later
#include "builders/baseBuilders_test.hpp"

#include "builders/opmap/opBuilderHelperMap.hpp"

#include <string>
#include <vector>

using namespace builder::builders;

namespace
{
// Mocks of a split source reference that is not a schema field
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

// Mocks of a split source reference that is a schema field of the given JSON type
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

// Mocks of a target field that is not allowed for the asset
auto targetNotAllowed()
{
    return [](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.allowedFields, check(testing::_, DotPath("targetField"))).WillOnce(testing::Return(false));
        return None {};
    };
}

// Verbatim copy of the replacement loop of opBuilderHelperStringReplace at 0dfa50613c, used as an oracle; do not modify
std::string legacyReplace(std::string newString, const std::string& oldSubstr, const std::string& newSubstr)
{
    size_t start_pos = 0;
    while ((start_pos = newString.find(oldSubstr, start_pos)) != std::string::npos)
    {
        newString.replace(start_pos, oldSubstr.length(), newSubstr);
        start_pos += newSubstr.length();
    }
    return newString;
}

} // namespace

namespace transformbuildtest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    TransformBuilderTest,
    testing::Values(
        /*** trim([chars]): 0 or 1 literal string, the set of characters to remove ***/
        TransformT({}, opBuilderHelperStringTrim, SUCCESS()),
        TransformT({makeValue(R"("-")")}, opBuilderHelperStringTrim, SUCCESS()),
        TransformT({makeValue(R"("-_ ")")}, opBuilderHelperStringTrim, SUCCESS()),
        TransformT({makeValue(R"("")")}, opBuilderHelperStringTrim, FAILURE()),
        TransformT({makeValue("1")}, opBuilderHelperStringTrim, FAILURE()),
        TransformT({makeValue("1.5")}, opBuilderHelperStringTrim, FAILURE()),
        TransformT({makeValue("true")}, opBuilderHelperStringTrim, FAILURE()),
        TransformT({makeValue("null")}, opBuilderHelperStringTrim, FAILURE()),
        TransformT({makeValue(R"(["-"])")}, opBuilderHelperStringTrim, FAILURE()),
        TransformT({makeValue(R"({"chars": "-"})")}, opBuilderHelperStringTrim, FAILURE()),
        TransformT({makeRef("ref")}, opBuilderHelperStringTrim, FAILURE()),
        /*** The pre-5.0.0 form trim('begin'|'end'|'both', 'c') has two arguments ***/
        TransformT({makeValue(R"("begin")"), makeValue(R"("c")")}, opBuilderHelperStringTrim, FAILURE()),
        TransformT({makeValue(R"("end")"), makeValue(R"("c")")}, opBuilderHelperStringTrim, FAILURE()),
        TransformT({makeValue(R"("both")"), makeValue(R"("c")")}, opBuilderHelperStringTrim, FAILURE()),
        TransformT({makeValue(R"("-")"), makeValue(R"("-")")}, opBuilderHelperStringTrim, FAILURE()),
        TransformT({makeValue(R"("-")"), makeRef("ref")}, opBuilderHelperStringTrim, FAILURE()),
        TransformT({makeRef("ref"), makeRef("ref")}, opBuilderHelperStringTrim, FAILURE()),
        TransformT({makeValue(R"("-")"), makeValue(R"("-")"), makeValue(R"("-")")},
                   opBuilderHelperStringTrim,
                   FAILURE()),
        TransformT({}, opBuilderHelperStringTrim, FAILURE(targetNotAllowed())),
        TransformT({makeValue(R"("-")")}, opBuilderHelperStringTrim, FAILURE(targetNotAllowed())),
        /*** trim_start([chars]) ***/
        TransformT({}, opBuilderHelperStringTrimStart, SUCCESS()),
        TransformT({makeValue(R"("-")")}, opBuilderHelperStringTrimStart, SUCCESS()),
        TransformT({makeValue(R"("-_ ")")}, opBuilderHelperStringTrimStart, SUCCESS()),
        TransformT({makeValue(R"("")")}, opBuilderHelperStringTrimStart, FAILURE()),
        TransformT({makeValue("1")}, opBuilderHelperStringTrimStart, FAILURE()),
        TransformT({makeValue("true")}, opBuilderHelperStringTrimStart, FAILURE()),
        TransformT({makeValue("null")}, opBuilderHelperStringTrimStart, FAILURE()),
        TransformT({makeValue(R"(["-"])")}, opBuilderHelperStringTrimStart, FAILURE()),
        TransformT({makeRef("ref")}, opBuilderHelperStringTrimStart, FAILURE()),
        TransformT({makeValue(R"("begin")"), makeValue(R"("c")")}, opBuilderHelperStringTrimStart, FAILURE()),
        TransformT({makeValue(R"("-")"), makeValue(R"("-")")}, opBuilderHelperStringTrimStart, FAILURE()),
        TransformT({makeValue(R"("-")"), makeRef("ref")}, opBuilderHelperStringTrimStart, FAILURE()),
        TransformT({}, opBuilderHelperStringTrimStart, FAILURE(targetNotAllowed())),
        TransformT({makeValue(R"("-")")}, opBuilderHelperStringTrimStart, FAILURE(targetNotAllowed())),
        /*** trim_end([chars]) ***/
        TransformT({}, opBuilderHelperStringTrimEnd, SUCCESS()),
        TransformT({makeValue(R"("-")")}, opBuilderHelperStringTrimEnd, SUCCESS()),
        TransformT({makeValue(R"("-_ ")")}, opBuilderHelperStringTrimEnd, SUCCESS()),
        TransformT({makeValue(R"("")")}, opBuilderHelperStringTrimEnd, FAILURE()),
        TransformT({makeValue("1")}, opBuilderHelperStringTrimEnd, FAILURE()),
        TransformT({makeValue("true")}, opBuilderHelperStringTrimEnd, FAILURE()),
        TransformT({makeValue("null")}, opBuilderHelperStringTrimEnd, FAILURE()),
        TransformT({makeValue(R"(["-"])")}, opBuilderHelperStringTrimEnd, FAILURE()),
        TransformT({makeRef("ref")}, opBuilderHelperStringTrimEnd, FAILURE()),
        TransformT({makeValue(R"("end")"), makeValue(R"("c")")}, opBuilderHelperStringTrimEnd, FAILURE()),
        TransformT({makeValue(R"("-")"), makeValue(R"("-")")}, opBuilderHelperStringTrimEnd, FAILURE()),
        TransformT({makeValue(R"("-")"), makeRef("ref")}, opBuilderHelperStringTrimEnd, FAILURE()),
        TransformT({}, opBuilderHelperStringTrimEnd, FAILURE(targetNotAllowed())),
        TransformT({makeValue(R"("-")")}, opBuilderHelperStringTrimEnd, FAILURE(targetNotAllowed())),
        /*** replace ***/
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
        TransformT({makeValue(R"("a")"), makeValue(R"("b")")},
                   opBuilderHelperStringReplace,
                   FAILURE(targetNotAllowed())),
        /*** split($input, 'separator') ***/
        TransformT({}, opBuilderHelperAppendSplitString, FAILURE()),
        TransformT({makeRef("ref")}, opBuilderHelperAppendSplitString, FAILURE()),
        TransformT({makeValue(R"(",")")}, opBuilderHelperAppendSplitString, FAILURE()),
        TransformT({makeRef("ref"), makeValue(R"(",")")},
                   opBuilderHelperAppendSplitString,
                   SUCCESS(customRefExpected())),
        /*** The separator may be longer than one character, but not empty ***/
        TransformT({makeRef("ref"), makeValue(R"("::")")},
                   opBuilderHelperAppendSplitString,
                   SUCCESS(customRefExpected())),
        TransformT({makeRef("ref"), makeValue(R"(", ")")},
                   opBuilderHelperAppendSplitString,
                   SUCCESS(customRefExpected())),
        TransformT({makeRef("ref"), makeValue(R"("")")}, opBuilderHelperAppendSplitString, FAILURE()),
        TransformT({makeRef("ref"), makeValue("1")}, opBuilderHelperAppendSplitString, FAILURE()),
        TransformT({makeRef("ref"), makeValue("true")}, opBuilderHelperAppendSplitString, FAILURE()),
        TransformT({makeRef("ref"), makeValue("null")}, opBuilderHelperAppendSplitString, FAILURE()),
        TransformT({makeRef("ref"), makeValue(R"([","])")}, opBuilderHelperAppendSplitString, FAILURE()),
        TransformT({makeRef("ref"), makeRef("ref")}, opBuilderHelperAppendSplitString, FAILURE()),
        TransformT({makeValue(R"(",")"), makeRef("ref")}, opBuilderHelperAppendSplitString, FAILURE()),
        TransformT({makeRef("ref"), makeValue(R"(",")"), makeValue(R"(",")")},
                   opBuilderHelperAppendSplitString,
                   FAILURE()),
        TransformT({makeRef("ref"), makeValue(R"(",")")},
                   opBuilderHelperAppendSplitString,
                   SUCCESS(jTypeRefExpected(json::Json::Type::String))),
        TransformT({makeRef("ref"), makeValue(R"(",")")},
                   opBuilderHelperAppendSplitString,
                   FAILURE(jTypeRefExpected(json::Json::Type::Number))),
        TransformT({makeRef("ref"), makeValue(R"(",")")},
                   opBuilderHelperAppendSplitString,
                   FAILURE(jTypeRefExpected(json::Json::Type::Boolean))),
        TransformT({makeRef("ref"), makeValue(R"(",")")},
                   opBuilderHelperAppendSplitString,
                   FAILURE(jTypeRefExpected(json::Json::Type::Object))),
        TransformT({makeRef("ref"), makeValue(R"(",")")},
                   opBuilderHelperAppendSplitString,
                   FAILURE(jTypeRefExpected(json::Json::Type::Array))),
        TransformT({makeRef("ref"), makeValue(R"(",")")},
                   opBuilderHelperAppendSplitString,
                   FAILURE(jTypeRefExpected(json::Json::Type::Null))),
        TransformT({makeRef("ref"), makeValue(R"(",")")},
                   opBuilderHelperAppendSplitString,
                   FAILURE(targetNotAllowed()))),
    testNameFormatter<TransformBuilderTest>("StrTransform"));
} // namespace transformbuildtest

namespace transformoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    TransformOperationTest,
    testing::Values(
        /*** trim([chars]) ***/
        // The default set is the whitespace: space, \t, \n, \r, \f and \v
        TransformT(R"({"target": " \t\n\r\f\u000bvalue\u000b\f\r\n\t "})",
                   opBuilderHelperStringTrim,
                   "target",
                   {},
                   SUCCESS(makeEvent(R"({"target": "value"})"))),
        TransformT(R"({"target": "--value--"})",
                   opBuilderHelperStringTrim,
                   "target",
                   {},
                   SUCCESS(makeEvent(R"({"target": "--value--"})"))),
        TransformT(
            R"({"target": "  "})", opBuilderHelperStringTrim, "target", {}, SUCCESS(makeEvent(R"({"target": ""})"))),
        TransformT(R"({"target": "--value--"})",
                   opBuilderHelperStringTrim,
                   "target",
                   {makeValue(R"("-")")},
                   SUCCESS(makeEvent(R"({"target": "value"})"))),
        // Every character of the set is removed, whatever its order
        TransformT(R"({"target": "-_-value_-_"})",
                   opBuilderHelperStringTrim,
                   "target",
                   {makeValue(R"("-_")")},
                   SUCCESS(makeEvent(R"({"target": "value"})"))),
        TransformT(R"({"target": "xy-value-yx"})",
                   opBuilderHelperStringTrim,
                   "target",
                   {makeValue(R"("xy-")")},
                   SUCCESS(makeEvent(R"({"target": "value"})"))),
        // Only the ends are trimmed
        TransformT(R"({"target": "-va-lue-"})",
                   opBuilderHelperStringTrim,
                   "target",
                   {makeValue(R"("-")")},
                   SUCCESS(makeEvent(R"({"target": "va-lue"})"))),
        TransformT(R"({"target": "value"})",
                   opBuilderHelperStringTrim,
                   "target",
                   {makeValue(R"("-")")},
                   SUCCESS(makeEvent(R"({"target": "value"})"))),
        TransformT(R"({"target": "--value--"})",
                   opBuilderHelperStringTrim,
                   "target",
                   {makeValue(R"("/")")},
                   SUCCESS(makeEvent(R"({"target": "--value--"})"))),
        // A string made only of trimmed characters becomes empty
        TransformT(R"({"target": "---"})",
                   opBuilderHelperStringTrim,
                   "target",
                   {makeValue(R"("-")")},
                   SUCCESS(makeEvent(R"({"target": ""})"))),
        TransformT(R"({"target": ""})",
                   opBuilderHelperStringTrim,
                   "target",
                   {makeValue(R"("-")")},
                   SUCCESS(makeEvent(R"({"target": ""})"))),
        TransformT(
            R"({"target": "--value--"})", opBuilderHelperStringTrim, "notTarget", {makeValue(R"("-")")}, FAILURE()),
        TransformT(R"({"target": 1})", opBuilderHelperStringTrim, "target", {makeValue(R"("-")")}, FAILURE()),
        TransformT(R"({"target": 1.1})", opBuilderHelperStringTrim, "target", {makeValue(R"("-")")}, FAILURE()),
        TransformT(R"({"target": true})", opBuilderHelperStringTrim, "target", {makeValue(R"("-")")}, FAILURE()),
        TransformT(R"({"target": null})", opBuilderHelperStringTrim, "target", {makeValue(R"("-")")}, FAILURE()),
        TransformT(
            R"({"target": ["--value--"]})", opBuilderHelperStringTrim, "target", {makeValue(R"("-")")}, FAILURE()),
        TransformT(
            R"({"target": {"a": "--value--"}})", opBuilderHelperStringTrim, "target", {makeValue(R"("-")")}, FAILURE()),
        /*** trim_start([chars]) ***/
        TransformT(R"({"target": " \t\n\r\f\u000bvalue\u000b\f\r\n\t "})",
                   opBuilderHelperStringTrimStart,
                   "target",
                   {},
                   SUCCESS(makeEvent(R"({"target": "value\u000b\f\r\n\t "})"))),
        TransformT(R"({"target": "--value--"})",
                   opBuilderHelperStringTrimStart,
                   "target",
                   {makeValue(R"("-")")},
                   SUCCESS(makeEvent(R"({"target": "value--"})"))),
        TransformT(R"({"target": "xy-value-yx"})",
                   opBuilderHelperStringTrimStart,
                   "target",
                   {makeValue(R"("xy-")")},
                   SUCCESS(makeEvent(R"({"target": "value-yx"})"))),
        TransformT(R"({"target": "---"})",
                   opBuilderHelperStringTrimStart,
                   "target",
                   {makeValue(R"("-")")},
                   SUCCESS(makeEvent(R"({"target": ""})"))),
        TransformT(R"({"target": "value--"})",
                   opBuilderHelperStringTrimStart,
                   "target",
                   {makeValue(R"("-")")},
                   SUCCESS(makeEvent(R"({"target": "value--"})"))),
        TransformT(R"({"target": "--value--"})",
                   opBuilderHelperStringTrimStart,
                   "notTarget",
                   {makeValue(R"("-")")},
                   FAILURE()),
        TransformT(R"({"target": 1})", opBuilderHelperStringTrimStart, "target", {makeValue(R"("-")")}, FAILURE()),
        TransformT(R"({"target": null})", opBuilderHelperStringTrimStart, "target", {makeValue(R"("-")")}, FAILURE()),
        /*** trim_end([chars]) ***/
        TransformT(R"({"target": " \t\n\r\f\u000bvalue\u000b\f\r\n\t "})",
                   opBuilderHelperStringTrimEnd,
                   "target",
                   {},
                   SUCCESS(makeEvent(R"({"target": " \t\n\r\f\u000bvalue"})"))),
        TransformT(R"({"target": "--value--"})",
                   opBuilderHelperStringTrimEnd,
                   "target",
                   {makeValue(R"("-")")},
                   SUCCESS(makeEvent(R"({"target": "--value"})"))),
        TransformT(R"({"target": "xy-value-yx"})",
                   opBuilderHelperStringTrimEnd,
                   "target",
                   {makeValue(R"("xy-")")},
                   SUCCESS(makeEvent(R"({"target": "xy-value"})"))),
        TransformT(R"({"target": "---"})",
                   opBuilderHelperStringTrimEnd,
                   "target",
                   {makeValue(R"("-")")},
                   SUCCESS(makeEvent(R"({"target": ""})"))),
        TransformT(R"({"target": "--value"})",
                   opBuilderHelperStringTrimEnd,
                   "target",
                   {makeValue(R"("-")")},
                   SUCCESS(makeEvent(R"({"target": "--value"})"))),
        TransformT(
            R"({"target": "--value--"})", opBuilderHelperStringTrimEnd, "notTarget", {makeValue(R"("-")")}, FAILURE()),
        TransformT(R"({"target": 1})", opBuilderHelperStringTrimEnd, "target", {makeValue(R"("-")")}, FAILURE()),
        TransformT(R"({"target": null})", opBuilderHelperStringTrimEnd, "target", {makeValue(R"("-")")}, FAILURE()),
        /*** replace ***/
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
                   FAILURE()),
        // Non-overlapping matches, left to right; the inserted text is not scanned again
        TransformT(R"({"target": "banana"})",
                   opBuilderHelperStringReplace,
                   "target",
                   {makeValue(R"("a")"), makeValue(R"("aa")")},
                   SUCCESS(makeEvent(R"({"target": "baanaanaa"})"))),
        TransformT(R"({"target": "aaaa"})",
                   opBuilderHelperStringReplace,
                   "target",
                   {makeValue(R"("aa")"), makeValue(R"("b")")},
                   SUCCESS(makeEvent(R"({"target": "bb"})"))),
        TransformT(R"({"target": "aaa"})",
                   opBuilderHelperStringReplace,
                   "target",
                   {makeValue(R"("aa")"), makeValue(R"("b")")},
                   SUCCESS(makeEvent(R"({"target": "ba"})"))),
        TransformT(R"({"target": "-mid-"})",
                   opBuilderHelperStringReplace,
                   "target",
                   {makeValue(R"("-")"), makeValue(R"("<>")")},
                   SUCCESS(makeEvent(R"({"target": "<>mid<>"})"))),
        TransformT(R"({"target": "value"})",
                   opBuilderHelperStringReplace,
                   "target",
                   {makeValue(R"("value")"), makeValue(R"("x")")},
                   SUCCESS(makeEvent(R"({"target": "x"})"))),
        TransformT(R"({"target": "ab"})",
                   opBuilderHelperStringReplace,
                   "target",
                   {makeValue(R"("b")"), makeValue(R"("ab")")},
                   SUCCESS(makeEvent(R"({"target": "aab"})"))),
        TransformT(R"({"target": "a-b"})",
                   opBuilderHelperStringReplace,
                   "target",
                   {makeValue(R"("-")"), makeValue(R"("++")")},
                   SUCCESS(makeEvent(R"({"target": "a++b"})"))),
        TransformT(R"({"target": ""})",
                   opBuilderHelperStringReplace,
                   "target",
                   {makeValue(R"("a")"), makeValue(R"("b")")},
                   SUCCESS(makeEvent(R"({"target": ""})"))),
        /*** split($input, 'separator'): the target is set to the array of parts ***/
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
        // A multi-character separator
        TransformT(R"({"ref": "a::b::c"})",
                   opBuilderHelperAppendSplitString,
                   "target",
                   {makeRef("ref"), makeValue(R"("::")")},
                   SUCCESS(customRefExpected(makeEvent(R"({"ref": "a::b::c", "target": ["a", "b", "c"]})")))),
        TransformT(R"({"ref": "a:b::c:::d"})",
                   opBuilderHelperAppendSplitString,
                   "target",
                   {makeRef("ref"), makeValue(R"("::")")},
                   SUCCESS(customRefExpected(makeEvent(R"({"ref": "a:b::c:::d", "target": ["a:b", "c", ":d"]})")))),
        TransformT(R"({"ref": "a, b, c"})",
                   opBuilderHelperAppendSplitString,
                   "target",
                   {makeRef("ref"), makeValue(R"(", ")")},
                   SUCCESS(customRefExpected(makeEvent(R"({"ref": "a, b, c", "target": ["a", "b", "c"]})")))),
        TransformT(R"({"ref": "a"})",
                   opBuilderHelperAppendSplitString,
                   "target",
                   {makeRef("ref"), makeValue(R"("::")")},
                   SUCCESS(customRefExpected(makeEvent(R"({"ref": "a", "target": ["a"]})")))),
        // Token rules: one leading separator is dropped, empty middle parts are kept and one trailing empty part is
        // dropped
        TransformT(R"({"ref": " b "})",
                   opBuilderHelperAppendSplitString,
                   "target",
                   {makeRef("ref"), makeValue(R"(" ")")},
                   SUCCESS(customRefExpected(makeEvent(R"({"ref": " b ", "target": ["b"]})")))),
        TransformT(R"({"ref": ",,a"})",
                   opBuilderHelperAppendSplitString,
                   "target",
                   {makeRef("ref"), makeValue(R"(",")")},
                   SUCCESS(customRefExpected(makeEvent(R"({"ref": ",,a", "target": ["", "a"]})")))),
        TransformT(R"({"ref": "a,,b"})",
                   opBuilderHelperAppendSplitString,
                   "target",
                   {makeRef("ref"), makeValue(R"(",")")},
                   SUCCESS(customRefExpected(makeEvent(R"({"ref": "a,,b", "target": ["a", "", "b"]})")))),
        TransformT(R"({"ref": "a,b,,"})",
                   opBuilderHelperAppendSplitString,
                   "target",
                   {makeRef("ref"), makeValue(R"(",")")},
                   SUCCESS(customRefExpected(makeEvent(R"({"ref": "a,b,,", "target": ["a", "b", ""]})")))),
        TransformT(R"({"ref": "::a::"})",
                   opBuilderHelperAppendSplitString,
                   "target",
                   {makeRef("ref"), makeValue(R"("::")")},
                   SUCCESS(customRefExpected(makeEvent(R"({"ref": "::a::", "target": ["a"]})")))),
        TransformT(R"({"ref": "::"})",
                   opBuilderHelperAppendSplitString,
                   "target",
                   {makeRef("ref"), makeValue(R"("::")")},
                   SUCCESS(customRefExpected(makeEvent(R"({"ref": "::", "target": []})")))),
        TransformT(R"({"ref": ""})",
                   opBuilderHelperAppendSplitString,
                   "target",
                   {makeRef("ref"), makeValue(R"(",")")},
                   SUCCESS(customRefExpected(makeEvent(R"({"ref": "", "target": []})")))),
        // An existing target is replaced, whatever its type: the parts are not appended to an array
        TransformT(R"({"ref": "a,b", "target": ["x", "y"]})",
                   opBuilderHelperAppendSplitString,
                   "target",
                   {makeRef("ref"), makeValue(R"(",")")},
                   SUCCESS(customRefExpected(makeEvent(R"({"ref": "a,b", "target": ["a", "b"]})")))),
        TransformT(R"({"ref": "a,b", "target": "old"})",
                   opBuilderHelperAppendSplitString,
                   "target",
                   {makeRef("ref"), makeValue(R"(",")")},
                   SUCCESS(customRefExpected(makeEvent(R"({"ref": "a,b", "target": ["a", "b"]})")))),
        TransformT(R"({"ref": "a,b", "target": {"k": "v"}})",
                   opBuilderHelperAppendSplitString,
                   "target",
                   {makeRef("ref"), makeValue(R"(",")")},
                   SUCCESS(customRefExpected(makeEvent(R"({"ref": "a,b", "target": ["a", "b"]})")))),
        TransformT(R"({"ref": "a,b", "target": {"k": "v"}})",
                   opBuilderHelperAppendSplitString,
                   "target.k",
                   {makeRef("ref"), makeValue(R"(",")")},
                   SUCCESS(customRefExpected(makeEvent(R"({"ref": "a,b", "target": {"k": ["a", "b"]}})")))),
        // A missing or non-string source fails and leaves the event untouched
        TransformT(R"({"notRef": "a b c"})",
                   opBuilderHelperAppendSplitString,
                   "target",
                   {makeRef("ref"), makeValue(R"(" ")")},
                   FAILURE(customRefExpected())),
        TransformT(R"({"ref": 1, "target": ["x"]})",
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
        TransformT(R"({"ref": ["a b"]})",
                   opBuilderHelperAppendSplitString,
                   "target",
                   {makeRef("ref"), makeValue(R"(" ")")},
                   FAILURE(customRefExpected())),
        TransformT(R"({"ref": {"a": "b"}})",
                   opBuilderHelperAppendSplitString,
                   "target",
                   {makeRef("ref"), makeValue(R"(" ")")},
                   FAILURE(customRefExpected()))),
    testNameFormatter<TransformOperationTest>("StrTransform"));

} // namespace transformoperatestest

namespace replacelegacytest
{
class StringReplaceLegacyTest : public BaseBuilderTest
{
protected:
    // Builds the replace operation for target "target"
    TransformOp buildReplace(const std::string& oldSubstr, const std::string& newSubstr)
    {
        return opBuilderHelperStringReplace(
            Reference {"target"}, {makeValue("\"" + oldSubstr + "\""), makeValue("\"" + newSubstr + "\"")}, mocks->ctx);
    }

    // Applies the operation to an event holding the given string; returns false if the operation fails
    static bool apply(const TransformOp& op, const std::string& input, std::string& output)
    {
        auto event = std::make_shared<json::Json>();
        event->setString(input, "/target");
        const auto result = op(event);
        if (!result)
        {
            return false;
        }
        return result.payload()->getString(output, json::PointerPath {"/target"}) == json::RetGet::Success;
    }
};

TEST_F(StringReplaceLegacyTest, MatchesLegacyExhaustive)
{
    expectBuildSuccess();

    // Every string over {a, b} of length 0..8 (511 strings)
    std::vector<std::string> inputs {""};
    for (size_t len = 1; len <= 8; ++len)
    {
        for (size_t bits = 0; bits < (size_t {1} << len); ++bits)
        {
            std::string s;
            for (size_t i = 0; i < len; ++i)
            {
                s.push_back(((bits >> i) & 1U) ? 'b' : 'a');
            }
            inputs.push_back(std::move(s));
        }
    }
    ASSERT_EQ(inputs.size(), 511U);

    const std::vector<std::string> olds {"a", "aa", "ab", "b", "aaa"};
    const std::vector<std::string> news {"", "a", "aa", "b", "ba", "ab", "bbb"};

    size_t cases = 0;
    size_t diffs = 0;
    for (const auto& oldSubstr : olds)
    {
        for (const auto& newSubstr : news)
        {
            const auto op = buildReplace(oldSubstr, newSubstr);
            for (const auto& input : inputs)
            {
                ++cases;
                const auto expected = legacyReplace(input, oldSubstr, newSubstr);
                std::string obtained;
                const bool ok = apply(op, input, obtained);
                if (!ok || obtained != expected)
                {
                    ++diffs;
                    if (diffs <= 5)
                    {
                        ADD_FAILURE() << "input='" << input << "' old='" << oldSubstr << "' new='" << newSubstr
                                      << "' expected='" << expected << "' obtained='" << obtained << "' success=" << ok;
                    }
                }
            }
        }
    }
    ASSERT_EQ(cases, 17885U);
    EXPECT_EQ(diffs, 0U);
}

TEST_F(StringReplaceLegacyTest, LargeInputsMatchLegacy)
{
    expectBuildSuccess();

    const size_t n = 65536;
    struct Case
    {
        std::string input;
        std::string oldSubstr;
        std::string newSubstr;
        size_t expectedSize;
    };
    std::string ab;
    for (size_t i = 0; i < n / 2; ++i)
    {
        ab += "ab";
    }
    const std::vector<Case> cases {{std::string(n, '-'), "-", "", 0},
                                   {std::string(n, '-'), "-", "++", 2 * n},
                                   {ab, "ab", "b", n / 2},
                                   {std::string(n, 'a'), "-", "+", n}};

    for (const auto& c : cases)
    {
        const auto op = buildReplace(c.oldSubstr, c.newSubstr);
        std::string obtained;
        ASSERT_TRUE(apply(op, c.input, obtained));
        EXPECT_EQ(obtained.size(), c.expectedSize);
        EXPECT_TRUE(obtained == legacyReplace(c.input, c.oldSubstr, c.newSubstr));
    }
}

TEST_F(StringReplaceLegacyTest, EmbeddedNul)
{
    expectBuildSuccess();

    const std::string input("a\0b\0", 4);
    const auto op = opBuilderHelperStringReplace(
        Reference {"target"}, {makeValue(R"("\u0000")"), makeValue(R"("--")")}, mocks->ctx);

    std::string obtained;
    ASSERT_TRUE(apply(op, input, obtained));
    EXPECT_EQ(obtained, "a--b--");
    EXPECT_EQ(obtained, legacyReplace(input, std::string(1, '\0'), "--"));
}
} // namespace replacelegacytest
