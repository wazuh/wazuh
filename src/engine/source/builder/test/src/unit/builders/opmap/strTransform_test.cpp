// SPDX-License-Identifier: AGPL-3.0-or-later
#include "builders/baseBuilders_test.hpp"

#include "builders/baseHelper.hpp"
#include "builders/opmap/opBuilderHelperMap.hpp"
#include "valueValidators.hpp"

using namespace builder::builders;

namespace
{
auto customRefExpected(bool times = false)
{
    return [=](const BuildersMocks& mocks)
    {
        if (times)
        {
            EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AtLeast(1));
            EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillRepeatedly(testing::Return(false));
        }
        else
        {
            EXPECT_CALL(*mocks.ctx, validator());
            EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillOnce(testing::Return(false));
        }
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
        EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillOnce(testing::Return(true));
        EXPECT_CALL(*mocks.validator, getJsonType(DotPath("ref"))).WillOnce(testing::Return(jType));
        return None {};
    };
}

auto jTypeArrayRefExpected(json::Json::Type jType, bool isArray)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillOnce(testing::Return(true));
        if (isArray)
        {
            EXPECT_CALL(*mocks.validator, getJsonType(DotPath("ref"))).WillOnce(testing::Return(jType));
        }
        return None {};
    };
}

} // namespace

namespace mapbuildtest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    MapBuilderTest,
    testing::Values(
        /*** To String ***/
        MapT({makeRef("ref")}, opBuilderHelperNumberToString, SUCCESS()),
        MapT({makeRef("ref"), makeRef("ref")}, opBuilderHelperNumberToString, FAILURE()),
        MapT({makeValue(R"("value")")}, opBuilderHelperNumberToString, FAILURE()),
        /*** To Upper ***/
        MapT({}, opBuilderHelperStringUP, FAILURE()),
        MapT({makeValue(R"("value")")}, opBuilderHelperStringUP, SUCCESS()),
        MapT({makeValue(R"(1)")}, opBuilderHelperStringUP, FAILURE()),
        MapT({makeValue(R"(1.2)")}, opBuilderHelperStringUP, FAILURE()),
        MapT({makeValue(R"(true)")}, opBuilderHelperStringUP, FAILURE()),
        MapT({makeValue(R"([1, 2, 3])")}, opBuilderHelperStringUP, FAILURE()),
        MapT({makeValue(R"({"a": 1, "b": 2})")}, opBuilderHelperStringUP, FAILURE()),
        MapT({makeValue(R"(null)")}, opBuilderHelperStringUP, FAILURE()),
        MapT({makeValue(R"("value")"), makeValue(R"("value")")}, opBuilderHelperStringUP, FAILURE()),
        MapT({makeRef("ref")}, opBuilderHelperStringUP, SUCCESS(customRefExpected())),
        MapT({makeRef("ref")}, opBuilderHelperStringUP, FAILURE(jTypeRefExpected(json::Json::Type::Number))),
        MapT({makeRef("ref")}, opBuilderHelperStringUP, FAILURE(jTypeRefExpected(json::Json::Type::Boolean))),
        MapT({makeRef("ref")}, opBuilderHelperStringUP, FAILURE(jTypeRefExpected(json::Json::Type::Array))),
        MapT({makeRef("ref")}, opBuilderHelperStringUP, FAILURE(jTypeRefExpected(json::Json::Type::Object))),
        MapT({makeRef("ref")}, opBuilderHelperStringUP, FAILURE(jTypeRefExpected(json::Json::Type::Null))),
        MapT({makeRef("ref")}, opBuilderHelperStringUP, SUCCESS(jTypeRefExpected(json::Json::Type::String))),
        MapT({makeRef("ref"), makeRef("ref")}, opBuilderHelperStringUP, FAILURE()),
        /*** To Lower ***/
        MapT({}, opBuilderHelperStringLO, FAILURE()),
        MapT({makeValue(R"("value")")}, opBuilderHelperStringLO, SUCCESS()),
        MapT({makeValue(R"(1)")}, opBuilderHelperStringLO, FAILURE()),
        MapT({makeValue(R"(1.2)")}, opBuilderHelperStringLO, FAILURE()),
        MapT({makeValue(R"(true)")}, opBuilderHelperStringLO, FAILURE()),
        MapT({makeValue(R"([1, 2, 3])")}, opBuilderHelperStringLO, FAILURE()),
        MapT({makeValue(R"({"a": 1, "b": 2})")}, opBuilderHelperStringLO, FAILURE()),
        MapT({makeValue(R"(null)")}, opBuilderHelperStringLO, FAILURE()),
        MapT({makeValue(R"("value")"), makeValue(R"("value")")}, opBuilderHelperStringLO, FAILURE()),
        MapT({makeRef("ref")}, opBuilderHelperStringLO, SUCCESS(customRefExpected())),
        MapT({makeRef("ref")}, opBuilderHelperStringLO, FAILURE(jTypeRefExpected(json::Json::Type::Number))),
        MapT({makeRef("ref")}, opBuilderHelperStringLO, FAILURE(jTypeRefExpected(json::Json::Type::Boolean))),
        MapT({makeRef("ref")}, opBuilderHelperStringLO, FAILURE(jTypeRefExpected(json::Json::Type::Array))),
        MapT({makeRef("ref")}, opBuilderHelperStringLO, FAILURE(jTypeRefExpected(json::Json::Type::Object))),
        MapT({makeRef("ref")}, opBuilderHelperStringLO, FAILURE(jTypeRefExpected(json::Json::Type::Null))),
        MapT({makeRef("ref")}, opBuilderHelperStringLO, SUCCESS(jTypeRefExpected(json::Json::Type::String))),
        MapT({makeRef("ref"), makeRef("ref")}, opBuilderHelperStringLO, FAILURE()),
        /*** Concat ***/
        MapT({}, opBuilderHelperStringConcat(), FAILURE()),
        MapT({makeValue(R"("value")")}, opBuilderHelperStringConcat(), FAILURE()),
        MapT({makeValue(R"("value")"), makeValue(R"("value")")}, opBuilderHelperStringConcat(), SUCCESS()),
        MapT({makeValue(R"("value")"), makeValue(R"("value")"), makeValue(R"("value")")},
             opBuilderHelperStringConcat(),
             SUCCESS()),
        MapT({makeValue(R"("value")"), makeValue(R"(1)")}, opBuilderHelperStringConcat(), SUCCESS()),
        MapT({makeValue(R"("value")"), makeValue(R"(1.2)")}, opBuilderHelperStringConcat(), SUCCESS()),
        MapT({makeValue(R"("value")"), makeValue(R"(true)")}, opBuilderHelperStringConcat(), FAILURE()),
        MapT({makeValue(R"("value")"), makeValue(R"([1, 2, 3])")}, opBuilderHelperStringConcat(), FAILURE()),
        MapT({makeValue(R"("value")"), makeValue(R"({"a": 1, "b": 2})")}, opBuilderHelperStringConcat(), SUCCESS()),
        MapT({makeValue(R"("value")"), makeValue(R"(null)")}, opBuilderHelperStringConcat(), FAILURE()),
        MapT({makeRef("ref"), makeValue(R"("value")")}, opBuilderHelperStringConcat(), SUCCESS(customRefExpected())),
        MapT({makeRef("ref"), makeRef("ref")}, opBuilderHelperStringConcat(), SUCCESS(customRefExpected(true))),
        MapT({makeRef("ref"), makeValue(R"("value")")},
             opBuilderHelperStringConcat(),
             SUCCESS(jTypeRefExpected(json::Json::Type::Number))),
        MapT({makeRef("ref"), makeValue(R"("value")")},
             opBuilderHelperStringConcat(),
             FAILURE(jTypeRefExpected(json::Json::Type::Boolean))),
        MapT({makeRef("ref"), makeValue(R"("value")")},
             opBuilderHelperStringConcat(),
             FAILURE(jTypeRefExpected(json::Json::Type::Array))),
        MapT({makeRef("ref"), makeValue(R"("value")")},
             opBuilderHelperStringConcat(),
             SUCCESS(jTypeRefExpected(json::Json::Type::Object))),
        MapT({makeRef("ref"), makeValue(R"("value")")},
             opBuilderHelperStringConcat(),
             FAILURE(jTypeRefExpected(json::Json::Type::Null))),
        MapT({makeRef("ref"), makeValue(R"("value")")},
             opBuilderHelperStringConcat(),
             SUCCESS(jTypeRefExpected(json::Json::Type::String))),
        /*** Concat Array ***/
        MapT({}, opBuilderHelperStringFromArray, FAILURE()),
        MapT({makeRef("ref"), makeValue(R"(1)")}, opBuilderHelperStringFromArray, FAILURE()),
        MapT({makeRef("ref"), makeValue(R"(1.2)")}, opBuilderHelperStringFromArray, FAILURE()),
        MapT({makeRef("ref"), makeValue(R"(true)")}, opBuilderHelperStringFromArray, FAILURE()),
        MapT({makeRef("ref"), makeValue(R"([1, 2, 3])")}, opBuilderHelperStringFromArray, FAILURE()),
        MapT({makeRef("ref"), makeValue(R"({"a": 1, "b": 2})")}, opBuilderHelperStringFromArray, FAILURE()),
        MapT({makeRef("ref"), makeValue(R"(null)")}, opBuilderHelperStringFromArray, FAILURE()),
        MapT({makeRef("ref")}, opBuilderHelperStringFromArray, FAILURE()),
        MapT({makeRef("ref"), makeRef("ref")}, opBuilderHelperStringFromArray, FAILURE()),
        MapT({makeRef("ref"), makeValue(R"("separator")")},
             opBuilderHelperStringFromArray,
             SUCCESS(customRefExpected())),
        MapT({makeRef("ref"), makeValue(R"("separator")"), makeValue(R"("value")")},
             opBuilderHelperStringFromArray,
             FAILURE()),
        MapT({makeRef("ref"), makeValue(R"("separator")")},
             opBuilderHelperStringFromArray,
             SUCCESS(jTypeArrayRefExpected(json::Json::Type::String, true))),
        MapT({makeRef("ref"), makeValue(R"("separator")")},
             opBuilderHelperStringFromArray,
             FAILURE(jTypeArrayRefExpected(json::Json::Type::String, false))),
        MapT({makeRef("ref"), makeValue(R"("separator")")},
             opBuilderHelperStringFromArray,
             FAILURE(jTypeArrayRefExpected(json::Json::Type::Number, true))),
        MapT({makeRef("ref"), makeValue(R"("separator")")},
             opBuilderHelperStringFromArray,
             FAILURE(jTypeArrayRefExpected(json::Json::Type::Boolean, true))),
        MapT({makeRef("ref"), makeValue(R"("separator")")},
             opBuilderHelperStringFromArray,
             FAILURE(jTypeArrayRefExpected(json::Json::Type::Null, true))),
        /*** String from Hexa ***/
        MapT({}, opBuilderHelperStringFromHexa, FAILURE()),
        MapT({makeValue(R"("48656C6C6F20776F726C6421")")}, opBuilderHelperStringFromHexa, FAILURE()),
        MapT({makeRef("ref")}, opBuilderHelperStringFromHexa, SUCCESS(customRefExpected())),
        MapT({makeRef("ref"), makeRef("ref")}, opBuilderHelperStringFromHexa, FAILURE()),
        MapT({makeRef("ref"), makeValue(R"("quoted")")}, opBuilderHelperStringFromHexa, SUCCESS(customRefExpected())),
        MapT({makeRef("ref"), makeValue(R"("QUOTED")")}, opBuilderHelperStringFromHexa, FAILURE()),
        MapT({makeRef("ref"), makeValue(R"("auditd")")}, opBuilderHelperStringFromHexa, FAILURE()),
        MapT({makeRef("ref"), makeValue(R"(1)")}, opBuilderHelperStringFromHexa, FAILURE()),
        MapT({makeRef("ref"), makeValue(R"("quoted")"), makeValue(R"("quoted")")},
             opBuilderHelperStringFromHexa,
             FAILURE()),
        MapT({makeRef("ref")}, opBuilderHelperStringFromHexa, SUCCESS(jTypeRefExpected(json::Json::Type::String))),
        MapT({makeRef("ref")}, opBuilderHelperStringFromHexa, FAILURE(jTypeRefExpected(json::Json::Type::Number))),
        MapT({makeRef("ref")}, opBuilderHelperStringFromHexa, FAILURE(jTypeRefExpected(json::Json::Type::Boolean))),
        MapT({makeRef("ref")}, opBuilderHelperStringFromHexa, FAILURE(jTypeRefExpected(json::Json::Type::Array))),
        MapT({makeRef("ref")}, opBuilderHelperStringFromHexa, FAILURE(jTypeRefExpected(json::Json::Type::Object))),
        MapT({makeRef("ref")}, opBuilderHelperStringFromHexa, FAILURE(jTypeRefExpected(json::Json::Type::Null))),
        /*** Hex to Number*/
        MapT({}, opBuilderHelperHexToNumber, FAILURE()),
        MapT({makeValue(R"("begin")")}, opBuilderHelperHexToNumber, FAILURE()),
        MapT({makeValue(R"("48656C6C6F20776F726C6421")")}, opBuilderHelperHexToNumber, FAILURE()),
        MapT({makeRef("ref")}, opBuilderHelperHexToNumber, SUCCESS(customRefExpected())),
        MapT({makeRef("ref"), makeRef("ref")}, opBuilderHelperHexToNumber, FAILURE()),
        MapT({makeRef("ref")}, opBuilderHelperHexToNumber, SUCCESS(jTypeRefExpected(json::Json::Type::String))),
        MapT({makeRef("ref")}, opBuilderHelperHexToNumber, FAILURE(jTypeRefExpected(json::Json::Type::Number))),
        MapT({makeRef("ref")}, opBuilderHelperHexToNumber, FAILURE(jTypeRefExpected(json::Json::Type::Boolean))),
        MapT({makeRef("ref")}, opBuilderHelperHexToNumber, FAILURE(jTypeRefExpected(json::Json::Type::Array))),
        MapT({makeRef("ref")}, opBuilderHelperHexToNumber, FAILURE(jTypeRefExpected(json::Json::Type::Object))),
        MapT({makeRef("ref")}, opBuilderHelperHexToNumber, FAILURE(jTypeRefExpected(json::Json::Type::Null)))),
    testNameFormatter<MapBuilderTest>("StrTransform"));
} // namespace mapbuildtest

namespace mapoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    MapOperationTest,
    testing::Values(
        /*** To String ***/
        MapT(R"({})", opBuilderHelperNumberToString, {makeRef("ref")}, FAILURE()),
        MapT(R"({"notRef": "value"})", opBuilderHelperNumberToString, {makeRef("ref")}, FAILURE()),
        MapT(R"({"ref": 1})", opBuilderHelperNumberToString, {makeRef("ref")}, SUCCESS(json::Json(R"("1")"))),
        MapT(R"({"ref": 2.33875648})",
             opBuilderHelperNumberToString,
             {makeRef("ref")},
             SUCCESS(json::Json(R"("2.338756")"))),
        MapT(R"({"ref": 2.35})", opBuilderHelperNumberToString, {makeRef("ref")}, SUCCESS(json::Json(R"("2.350000")"))),
        MapT(R"({"ref": "hello"})", opBuilderHelperNumberToString, {makeRef("ref")}, FAILURE()),
        MapT(R"({"ref": true})", opBuilderHelperNumberToString, {makeRef("ref")}, FAILURE()),
        MapT(R"({"ref": [1, 2, 3]})", opBuilderHelperNumberToString, {makeRef("ref")}, FAILURE()),
        MapT(R"({"ref": {"a": 1, "b": 2}})", opBuilderHelperNumberToString, {makeRef("ref")}, FAILURE()),
        MapT(R"({"ref": null})", opBuilderHelperNumberToString, {makeRef("ref")}, FAILURE()),
        /*** To Upper ***/
        MapT("{}", opBuilderHelperStringUP, {makeValue(R"("value")")}, SUCCESS(json::Json(R"("VALUE")"))),
        MapT("{}", opBuilderHelperStringUP, {makeValue(R"("VALUE")")}, SUCCESS(json::Json(R"("VALUE")"))),
        MapT(R"({"ref": "value"})",
             opBuilderHelperStringUP,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("VALUE")")))),
        MapT(R"({"ref": "VALUE"})",
             opBuilderHelperStringUP,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("VALUE")")))),
        MapT("{}", opBuilderHelperStringUP, {makeValue(R"("0val1ue2")")}, SUCCESS(json::Json(R"("0VAL1UE2")"))),
        MapT(R"({"notRef": "value"})", opBuilderHelperStringUP, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": 1})", opBuilderHelperStringUP, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": 1.2})", opBuilderHelperStringUP, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": true})", opBuilderHelperStringUP, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": [1, 2, 3]})", opBuilderHelperStringUP, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": {"a": 1, "b": 2}})", opBuilderHelperStringUP, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": null})", opBuilderHelperStringUP, {makeRef("ref")}, FAILURE(customRefExpected())),
        /*** To Lower ***/
        MapT("{}", opBuilderHelperStringLO, {makeValue(R"("VALUE")")}, SUCCESS(json::Json(R"("value")"))),
        MapT("{}", opBuilderHelperStringLO, {makeValue(R"("value")")}, SUCCESS(json::Json(R"("value")"))),
        MapT(R"({"ref": "VALUE"})",
             opBuilderHelperStringLO,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("value")")))),
        MapT(R"({"ref": "value"})",
             opBuilderHelperStringLO,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("value")")))),
        MapT(R"({"notRef": "VALUE"})", opBuilderHelperStringLO, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": 1})", opBuilderHelperStringLO, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": 1.2})", opBuilderHelperStringLO, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": true})", opBuilderHelperStringLO, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": [1, 2, 3]})", opBuilderHelperStringLO, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": {"a": 1, "b": 2}})", opBuilderHelperStringLO, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": null})", opBuilderHelperStringLO, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref":"0VAL1UE2"})",
             opBuilderHelperStringLO,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("0val1ue2")")))),
        /*** Concat ***/
        MapT("{}",
             opBuilderHelperStringConcat(),
             {makeValue(R"("v")"), makeValue(R"("alue")")},
             SUCCESS(json::Json(R"("value")"))),
        MapT("{}",
             opBuilderHelperStringConcat(),
             {makeValue(R"("va")"), makeValue(R"("l")"), makeValue(R"("ue")")},
             SUCCESS(json::Json(R"("value")"))),
        MapT(R"({"ref": "v"})",
             opBuilderHelperStringConcat(),
             {makeRef("ref"), makeValue(R"("alue")")},
             SUCCESS(customRefExpected(json::Json(R"("value")")))),
        MapT(R"({"ref": "e"})",
             opBuilderHelperStringConcat(),
             {makeValue(R"("va")"), makeValue(R"("lu")"), makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("value")")))),
        MapT("{}",
             opBuilderHelperStringConcat(),
             {makeRef("ref"), makeValue(R"("alue")")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": 1})",
             opBuilderHelperStringConcat(),
             {makeRef("ref"), makeValue(R"("alue")")},
             SUCCESS(customRefExpected(json::Json(R"("1alue")")))),
        MapT(R"({"ref": 1.2})",
             opBuilderHelperStringConcat(),
             {makeRef("ref"), makeValue(R"("alue")")},
             SUCCESS(customRefExpected(json::Json(R"("1.200000alue")")))),
        MapT(R"({"ref": true})",
             opBuilderHelperStringConcat(),
             {makeRef("ref"), makeValue(R"("alue")")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": [1, 2, 3]})",
             opBuilderHelperStringConcat(),
             {makeRef("ref"), makeValue(R"("alue")")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": {"a": 1, "b": 2}})",
             opBuilderHelperStringConcat(),
             {makeRef("ref"), makeValue(R"("alue")")},
             SUCCESS(customRefExpected(json::Json(R"("{\"a\":1,\"b\":2}alue")")))),
        MapT(R"({"ref": null})",
             opBuilderHelperStringConcat(),
             {makeRef("ref"), makeValue(R"("alue")")},
             FAILURE(customRefExpected())),
        /*** Concat Array ***/
        MapT(R"({"ref": ["v", "a", "l", "u", "e"]})",
             opBuilderHelperStringFromArray,
             {makeRef("ref"), makeValue(R"("")")},
             SUCCESS(customRefExpected(json::Json(R"("value")")))),
        MapT(R"({"ref": ["v", "a", "l", "u", "e"]})",
             opBuilderHelperStringFromArray,
             {makeRef("ref"), makeValue(R"("-")")},
             SUCCESS(customRefExpected(json::Json(R"("v-a-l-u-e")")))),
        MapT(R"({"ref": ["v", "a", "l", "u", "e"]})",
             opBuilderHelperStringFromArray,
             {makeRef("ref"), makeValue(R"(", ")")},
             SUCCESS(customRefExpected(json::Json(R"("v, a, l, u, e")")))),
        MapT("{}", opBuilderHelperStringFromArray, {makeRef("ref"), makeValue(R"("-")")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": 1})",
             opBuilderHelperStringFromArray,
             {makeRef("ref"), makeValue(R"("-")")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": 1.2})",
             opBuilderHelperStringFromArray,
             {makeRef("ref"), makeValue(R"("-")")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": true})",
             opBuilderHelperStringFromArray,
             {makeRef("ref"), makeValue(R"("-")")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": [1, 2, 3]})",
             opBuilderHelperStringFromArray,
             {makeRef("ref"), makeValue(R"("-")")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": {"a": 1, "b": 2}})",
             opBuilderHelperStringFromArray,
             {makeRef("ref"), makeValue(R"("-")")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": null})",
             opBuilderHelperStringFromArray,
             {makeRef("ref"), makeValue(R"("-")")},
             FAILURE(customRefExpected())),
        /*** String from Hexa ***/
        MapT(R"({"ref": "48656C6C6F20776F726C6421"})",
             opBuilderHelperStringFromHexa,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("Hello world!")")))),
        MapT(R"({"ref": "48656C6C6U20776F726C6421"})",
             opBuilderHelperStringFromHexa,
             {makeRef("ref")},
             FAILURE(customRefExpected())),
        MapT(R"({"notRef": "48656C6C6F20776F726C6421"})",
             opBuilderHelperStringFromHexa,
             {makeRef("ref")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": 1})", opBuilderHelperStringFromHexa, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": 1.2})", opBuilderHelperStringFromHexa, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": true})", opBuilderHelperStringFromHexa, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": {"a": 1, "b": 2}})",
             opBuilderHelperStringFromHexa,
             {makeRef("ref")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": null})", opBuilderHelperStringFromHexa, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": "FF"})", opBuilderHelperStringFromHexa, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": "414"})", opBuilderHelperStringFromHexa, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": "41 A"})", opBuilderHelperStringFromHexa, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": "41+A"})", opBuilderHelperStringFromHexa, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": "4a4B"})",
             opBuilderHelperStringFromHexa,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("JK")")))),
        MapT(R"({"ref": ""})",
             opBuilderHelperStringFromHexa,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("")")))),
        /*** String from Hexa: an array needs the 'quoted' mode ***/
        MapT(R"({"ref": ["48656C6C6F", "776F726C6421"]})",
             opBuilderHelperStringFromHexa,
             {makeRef("ref")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": []})", opBuilderHelperStringFromHexa, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": [1, 2, 3]})", opBuilderHelperStringFromHexa, {makeRef("ref")}, FAILURE(customRefExpected())),
        /*** String from Hexa: 'quoted' mode, array reference ***/
        // auditd EXECVE arguments of the issue: quoted values are text, the unquoted one is hexadecimal
        MapT(
            R"({"ref": ["\"/usr/bin/sudo\"", "\"grep\"", "6B65793D226172742D7465737422", "\"/var/log/audit/audit.log\""]})",
            opBuilderHelperStringFromHexa,
            {makeRef("ref"), makeValue(R"("quoted")")},
            SUCCESS(customRefExpected(
                json::Json(R"(["/usr/bin/sudo", "grep", "key=\"art-test\"", "/var/log/audit/audit.log"])")))),
        // Quoted values that are also valid hexadecimal stay text (review H-1)
        MapT(R"({"ref": ["\"sleep\"", "\"10\""]})",
             opBuilderHelperStringFromHexa,
             {makeRef("ref"), makeValue(R"("quoted")")},
             SUCCESS(customRefExpected(json::Json(R"(["sleep", "10"])")))),
        MapT(R"({"ref": ["\"chmod\"", "\"0755\"", "\"/tmp/f\""]})",
             opBuilderHelperStringFromHexa,
             {makeRef("ref"), makeValue(R"("quoted")")},
             SUCCESS(customRefExpected(json::Json(R"(["chmod", "0755", "/tmp/f"])")))),
        MapT(R"({"ref": ["\"kill\"", "\"-9\"", "\"1234\""]})",
             opBuilderHelperStringFromHexa,
             {makeRef("ref"), makeValue(R"("quoted")")},
             SUCCESS(customRefExpected(json::Json(R"(["kill", "-9", "1234"])")))),
        MapT(R"({"ref": ["\"3c3e\"", "\"00\"", "\"\"", "\"\"\""]})",
             opBuilderHelperStringFromHexa,
             {makeRef("ref"), makeValue(R"("quoted")")},
             SUCCESS(customRefExpected(json::Json(R"(["3c3e", "00", "", "\""])")))),
        // UTF-8 argument (review M-1): "café" is written as hexadecimal by auditd
        MapT(R"({"ref": ["\"touch\"", "636166C3A9"]})",
             opBuilderHelperStringFromHexa,
             {makeRef("ref"), makeValue(R"("quoted")")},
             SUCCESS(customRefExpected(json::Json(R"(["touch", "café"])")))),
        // Unquoted values decoded only when they are upper-case hexadecimal that decodes to valid UTF-8
        MapT(
            R"j({"ref": ["2F746D702F612062", "0A", "3c3e", "636166c3a9", "CAFE", "C0AF", "414", "41G2", "", "\"", "(null)"]})j",
            opBuilderHelperStringFromHexa,
            {makeRef("ref"), makeValue(R"("quoted")")},
            SUCCESS(customRefExpected(json::Json(
                R"j(["/tmp/a b", "\n", "3c3e", "636166c3a9", "CAFE", "C0AF", "414", "41G2", "", "\"", "(null)"])j")))),
        MapT(R"({"ref": []})",
             opBuilderHelperStringFromHexa,
             {makeRef("ref"), makeValue(R"("quoted")")},
             SUCCESS(customRefExpected(json::Json(R"([])")))),
        MapT(R"({"ref": [1, "\"4142\"", "4142", true, null, {"a": "4142"}, ["4142"], 2.5]})",
             opBuilderHelperStringFromHexa,
             {makeRef("ref"), makeValue(R"("quoted")")},
             SUCCESS(customRefExpected(json::Json(R"([1, "4142", "AB", true, null, {"a": "4142"}, ["4142"], 2.5])")))),
        /*** String from Hexa: 'quoted' mode, string reference ***/
        MapT(R"({"ref": "\"1234\""})",
             opBuilderHelperStringFromHexa,
             {makeRef("ref"), makeValue(R"("quoted")")},
             SUCCESS(customRefExpected(json::Json(R"("1234")")))),
        MapT(R"({"ref": "636166C3A9"})",
             opBuilderHelperStringFromHexa,
             {makeRef("ref"), makeValue(R"("quoted")")},
             SUCCESS(customRefExpected(json::Json(R"("café")")))),
        MapT(R"({"ref": "CAFE"})",
             opBuilderHelperStringFromHexa,
             {makeRef("ref"), makeValue(R"("quoted")")},
             SUCCESS(customRefExpected(json::Json(R"("CAFE")")))),
        MapT(R"({"ref": 1})",
             opBuilderHelperStringFromHexa,
             {makeRef("ref"), makeValue(R"("quoted")")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": {"a": "41"}})",
             opBuilderHelperStringFromHexa,
             {makeRef("ref"), makeValue(R"("quoted")")},
             FAILURE(customRefExpected())),
        MapT(R"({"other": "41"})",
             opBuilderHelperStringFromHexa,
             {makeRef("ref"), makeValue(R"("quoted")")},
             FAILURE(customRefExpected())),
        /*** Hex to Number*/
        MapT(R"({"ref": "48656C"})",
             opBuilderHelperHexToNumber,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json("4744556")))),
        MapT(R"({"ref": "0xBC763516"})",
             opBuilderHelperHexToNumber,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json("3161863446")))),
        MapT(R"({"ref": "48656P"})", opBuilderHelperHexToNumber, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"notRef": "48656C"})", opBuilderHelperHexToNumber, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": 1})", opBuilderHelperHexToNumber, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": 1.1})", opBuilderHelperHexToNumber, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": true})", opBuilderHelperHexToNumber, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": []})", opBuilderHelperHexToNumber, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": {}})", opBuilderHelperHexToNumber, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": null})", opBuilderHelperHexToNumber, {makeRef("ref")}, FAILURE(customRefExpected()))),
    testNameFormatter<MapOperationTest>("StrTransform"));
} // namespace mapoperatestest

namespace decodebase16test
{
// decode_base16 run in test mode, to check the trace of every outcome
class DecodeBase16Test : public BaseBuilderTest
{
protected:
    void SetUp() override
    {
        BaseBuilderTest::SetUp();
        mocks->context.opName = "decode_base16";
        ON_CALL(*mocks->ctx, isTestMode()).WillByDefault(testing::Return(true));
        ON_CALL(*mocks->validator, hasField(testing::_)).WillByDefault(testing::Return(false));
    }

    MapResult run(const std::string& input, bool quoted)
    {
        auto op = opBuilderHelperStringFromHexa(args(quoted), mocks->ctx);
        return op(std::make_shared<json::Json>(input.c_str()));
    }

    static std::vector<OpArg> args(bool quoted)
    {
        if (quoted)
        {
            return {makeRef("ref"), makeValue(R"("quoted")")};
        }
        return {makeRef("ref")};
    }
};

TEST_F(DecodeBase16Test, Traces)
{
    struct Case
    {
        std::string input;
        bool quoted;
        bool success;
        std::string trace;
    };
    const std::vector<Case> cases {
        {R"({"ref": "4142"})", false, true, "[decode_base16] -> Success"},
        {R"({"other": "4142"})", false, false, "[decode_base16] -> Failure: Parameter 'ref' reference not found"},
        {R"({"ref": ["4142"]})", false, false, "[decode_base16] -> Failure: Parameter 'ref' type is not string"},
        {R"({"ref": 1})", false, false, "[decode_base16] -> Failure: Parameter 'ref' type is not string"},
        {R"({"ref": "414"})",
         false,
         false,
         "[decode_base16] -> Failure: Hexa string has not an even quantity of digits"},
        {R"({"ref": "41G2"})",
         false,
         false,
         "[decode_base16] -> Failure: Hexa string has a non hexadecimal digit or a non ASCII byte"},
        {R"({"ref": "CAFE"})",
         false,
         false,
         "[decode_base16] -> Failure: Hexa string has a non hexadecimal digit or a non ASCII byte"},
        {R"({"ref": ["\"a\"", "CAFE"]})", true, true, "[decode_base16] -> Success"},
        {R"({"ref": "CAFE"})", true, true, "[decode_base16] -> Success"},
        {R"({"other": []})", true, false, "[decode_base16] -> Failure: Parameter 'ref' reference not found"},
        {R"({"ref": 1})", true, false, "[decode_base16] -> Failure: Parameter 'ref' type is neither string nor array"},
        {R"({"ref": {"a": "41"}})",
         true,
         false,
         "[decode_base16] -> Failure: Parameter 'ref' type is neither string nor array"},
    };

    for (const auto& c : cases)
    {
        SCOPED_TRACE(c.input + (c.quoted ? " (quoted)" : ""));
        auto result = run(c.input, c.quoted);
        EXPECT_EQ(result.success(), c.success);
        EXPECT_EQ(result.trace(), c.trace);
    }
}

TEST_F(DecodeBase16Test, QuotedModeOnKeywordTarget)
{
    // A keyword target such as process.args gets the string validator wrapped with asArray() at runtime: an array
    // result with a non-string element fails the whole operation and the target is not set
    Reference target("process.args");
    schemf::ValidationResult valResult(schemf::asArray(schemf::validators::getStringValidator()));
    auto wrapped = runType(MapBuilder(opBuilderHelperStringFromHexa), target, valResult);
    auto transform = mapToTransform(std::get<MapBuilder>(wrapped), target);
    auto op = transform(target, args(true), mocks->ctx);

    auto event = std::make_shared<json::Json>(R"({"ref": ["\"sleep\"", "\"10\"", "636166C3A9"]})");
    auto result = op(event);
    ASSERT_TRUE(result.success()) << result.trace();
    EXPECT_EQ(event->getJson("/process/args").value(), json::Json(R"(["sleep", "10", "café"])"));

    event = std::make_shared<json::Json>(R"({"ref": ["\"kill\"", 9]})");
    result = op(event);
    ASSERT_FALSE(result.success());
    EXPECT_THAT(result.trace(), testing::HasSubstr("schema validation failed"));
    EXPECT_FALSE(event->exists("/process/args"));
}
} // namespace decodebase16test
