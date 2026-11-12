// SPDX-License-Identifier: AGPL-3.0-or-later
#include "builders/baseBuilders_test.hpp"

#include "builders/opmap/opBuilderHelperMap.hpp"

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

auto schemaRefExpected(schemf::Type sType)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillOnce(testing::Return(true));
        EXPECT_CALL(*mocks.validator, getType(DotPath("ref"))).WillOnce(testing::Return(sType));
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
        /*** to_int ***/
        MapT({}, opBuilderHelperToInt, FAILURE()),
        // The value must be a reference: a literal, even a numeric one, is a build error
        MapT({makeValue(R"("true")")}, opBuilderHelperToInt, FAILURE()),
        MapT({makeValue(R"("42")")}, opBuilderHelperToInt, FAILURE()),
        MapT({makeValue(R"(42)")}, opBuilderHelperToInt, FAILURE()),
        MapT({makeRef("ref")}, opBuilderHelperToInt, SUCCESS()),
        MapT({makeRef("ref"), makeRef("ref")}, opBuilderHelperToInt, FAILURE()),
        MapT({makeRef("ref"), makeValue(R"(1)")}, opBuilderHelperToInt, FAILURE()),
        MapT({makeRef("ref"), makeValue(R"(1.1)")}, opBuilderHelperToInt, FAILURE()),
        MapT({makeRef("ref"), makeValue(R"(true)")}, opBuilderHelperToInt, FAILURE()),
        MapT({makeRef("ref"), makeValue(R"(null)")}, opBuilderHelperToInt, FAILURE()),
        MapT({makeRef("ref"), makeValue(R"([1,2,3,4])")}, opBuilderHelperToInt, FAILURE()),
        MapT({makeRef("ref"), makeValue(R"("c")")}, opBuilderHelperToInt, FAILURE()),
        MapT({makeRef("ref"), makeRef(R"("truncate")")}, opBuilderHelperToInt, FAILURE()),
        MapT({makeRef("ref"), makeRef(R"("round")")}, opBuilderHelperToInt, FAILURE()),
        MapT({makeRef("ref"), makeValue(R"("truncate")")}, opBuilderHelperToInt, SUCCESS()),
        MapT({makeRef("ref"), makeValue(R"("round")")}, opBuilderHelperToInt, SUCCESS()),
        MapT({makeRef("ref"), makeValue(R"("truncate")"), makeValue(R"("round")")}, opBuilderHelperToInt, FAILURE()),
        /*** Schema type validation (getType -> typeToJType -> Number or String) ***/
        MapT({makeRef("ref")}, opBuilderHelperToInt, SUCCESS(schemaRefExpected(schemf::Type::INTEGER))),
        MapT({makeRef("ref")}, opBuilderHelperToInt, SUCCESS(schemaRefExpected(schemf::Type::SHORT))),
        MapT({makeRef("ref")}, opBuilderHelperToInt, SUCCESS(schemaRefExpected(schemf::Type::LONG))),
        MapT({makeRef("ref")}, opBuilderHelperToInt, SUCCESS(schemaRefExpected(schemf::Type::FLOAT))),
        MapT({makeRef("ref")}, opBuilderHelperToInt, SUCCESS(schemaRefExpected(schemf::Type::DOUBLE))),
        MapT({makeRef("ref")}, opBuilderHelperToInt, SUCCESS(schemaRefExpected(schemf::Type::SCALED_FLOAT))),
        // A string field may hold a numeric string, so keyword/text references are accepted
        MapT({makeRef("ref")}, opBuilderHelperToInt, SUCCESS(schemaRefExpected(schemf::Type::KEYWORD))),
        MapT({makeRef("ref")}, opBuilderHelperToInt, SUCCESS(schemaRefExpected(schemf::Type::TEXT))),
        // DATE and IP map to the JSON string type, so the build-time check accepts them too
        MapT({makeRef("ref")}, opBuilderHelperToInt, SUCCESS(schemaRefExpected(schemf::Type::DATE))),
        MapT({makeRef("ref")}, opBuilderHelperToInt, SUCCESS(schemaRefExpected(schemf::Type::IP))),
        MapT({makeRef("ref")}, opBuilderHelperToInt, FAILURE(schemaRefExpected(schemf::Type::BOOLEAN))),
        MapT({makeRef("ref")}, opBuilderHelperToInt, FAILURE(schemaRefExpected(schemf::Type::OBJECT))),
        MapT({makeRef("ref")}, opBuilderHelperToInt, FAILURE(schemaRefExpected(schemf::Type::NESTED)))),
    testNameFormatter<MapBuilderTest>("ToInt"));
} // namespace mapbuildtest

namespace mapoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    MapOperationTest,
    testing::Values(
        /*** to_int ***/
        /*** reference not found ***/
        MapT(R"({"notRef": 1})", opBuilderHelperToInt, {makeRef("ref")}, FAILURE(customRefExpected())),
        /*** invalid type reference field ***/
        MapT(R"({"ref": true})", opBuilderHelperToInt, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": null})", opBuilderHelperToInt, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": [1, 2, 3, 4]})", opBuilderHelperToInt, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": {"key": "value"}})", opBuilderHelperToInt, {makeRef("ref")}, FAILURE(customRefExpected())),
        /*** strings that do not hold a number ***/
        MapT(R"({"ref": "some"})", opBuilderHelperToInt, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": "[1,2,3,4]"})", opBuilderHelperToInt, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": ""})", opBuilderHelperToInt, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": " 42"})", opBuilderHelperToInt, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": "42 "})", opBuilderHelperToInt, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": "42abc"})", opBuilderHelperToInt, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": "4.6.1"})", opBuilderHelperToInt, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": "inf"})", opBuilderHelperToInt, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": "nan"})", opBuilderHelperToInt, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": "1e999"})", opBuilderHelperToInt, {makeRef("ref")}, FAILURE(customRefExpected())),
        /*** strings holding an integer ***/
        MapT(R"({"ref": "42"})",
             opBuilderHelperToInt,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"(42)")))),
        MapT(R"({"ref": "-7"})",
             opBuilderHelperToInt,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"(-7)")))),
        MapT(R"({"ref": "+42"})",
             opBuilderHelperToInt,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"(42)")))),
        MapT(R"({"ref": "007"})",
             opBuilderHelperToInt,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"(7)")))),
        MapT(R"({"ref": "0"})", opBuilderHelperToInt, {makeRef("ref")}, SUCCESS(customRefExpected(json::Json(R"(0)")))),
        MapT(R"({"ref": "9223372036854775807"})",
             opBuilderHelperToInt,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"(9223372036854775807)")))),
        MapT(R"({"ref": "+9223372036854775807"})",
             opBuilderHelperToInt,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"(9223372036854775807)")))),
        MapT(R"({"ref": "-9223372036854775808"})",
             opBuilderHelperToInt,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"(-9223372036854775808)")))),
        // Integer syntax above 2^53 keeps its precision (it never goes through a double)
        MapT(R"({"ref": "+9007199254740993"})",
             opBuilderHelperToInt,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"(9007199254740993)")))),
        MapT(
            R"({"ref": "-0"})", opBuilderHelperToInt, {makeRef("ref")}, SUCCESS(customRefExpected(json::Json(R"(0)")))),
        // Integer syntax outside the int64 range fails instead of being rounded through a double
        MapT(R"({"ref": "9223372036854775808"})", opBuilderHelperToInt, {makeRef("ref")}, FAILURE(customRefExpected())),
        // JSON numbers outside the int64 range: an unsigned 64-bit integer and a double beyond 2^63
        MapT(R"({"ref": 18446744073709551615})", opBuilderHelperToInt, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": 1e19})", opBuilderHelperToInt, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(
            R"({"ref": "-9223372036854775809"})", opBuilderHelperToInt, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": "++42"})", opBuilderHelperToInt, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": "+-5"})", opBuilderHelperToInt, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": "+-4.6"})", opBuilderHelperToInt, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": "+"})", opBuilderHelperToInt, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": "0x10"})", opBuilderHelperToInt, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(
            R"({"ref": ".5"})", opBuilderHelperToInt, {makeRef("ref")}, SUCCESS(customRefExpected(json::Json(R"(0)")))),
        MapT(
            R"({"ref": "5."})", opBuilderHelperToInt, {makeRef("ref")}, SUCCESS(customRefExpected(json::Json(R"(5)")))),
        MapT(R"({"ref": "42"})",
             opBuilderHelperToInt,
             {makeRef("ref"), makeValue(R"("round")")},
             SUCCESS(customRefExpected(json::Json(R"(42)")))),
        /*** strings holding a floating point number: truncated by default, rounded half away from zero ***/
        MapT(R"({"ref": "4.6"})",
             opBuilderHelperToInt,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"(4)")))),
        MapT(R"({"ref": "4.6"})",
             opBuilderHelperToInt,
             {makeRef("ref"), makeValue(R"("truncate")")},
             SUCCESS(customRefExpected(json::Json(R"(4)")))),
        MapT(R"({"ref": "4.6"})",
             opBuilderHelperToInt,
             {makeRef("ref"), makeValue(R"("round")")},
             SUCCESS(customRefExpected(json::Json(R"(5)")))),
        MapT(R"({"ref": "-3.5"})",
             opBuilderHelperToInt,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"(-3)")))),
        MapT(R"({"ref": "-3.5"})",
             opBuilderHelperToInt,
             {makeRef("ref"), makeValue(R"("round")")},
             SUCCESS(customRefExpected(json::Json(R"(-4)")))),
        MapT(R"({"ref": "2.5"})",
             opBuilderHelperToInt,
             {makeRef("ref"), makeValue(R"("round")")},
             SUCCESS(customRefExpected(json::Json(R"(3)")))),
        MapT(R"({"ref": "1e3"})",
             opBuilderHelperToInt,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"(1000)")))),
        MapT(R"({"ref": "-1.5e1"})",
             opBuilderHelperToInt,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"(-15)")))),
        /*** integer values ***/
        MapT(R"({"ref": 42})", opBuilderHelperToInt, {makeRef("ref")}, SUCCESS(customRefExpected(json::Json(R"(42)")))),
        MapT(R"({"ref": -42})",
             opBuilderHelperToInt,
             {makeRef("ref"), makeValue(R"("round")")},
             SUCCESS(customRefExpected(json::Json(R"(-42)")))),
        MapT(R"({"ref": 3000000000})",
             opBuilderHelperToInt,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"(3000000000)")))),
        /*** floating point values are read as double: no float narrowing ***/
        MapT(R"({"ref": 1000.0})",
             opBuilderHelperToInt,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"(1000)")))),
        // 16777217 is not representable as a float (it would narrow to 16777216)
        MapT(R"({"ref": 16777217.0})",
             opBuilderHelperToInt,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"(16777217)")))),
        MapT(R"({"ref": 16777217.4})",
             opBuilderHelperToInt,
             {makeRef("ref"), makeValue(R"("round")")},
             SUCCESS(customRefExpected(json::Json(R"(16777217)")))),
        MapT(R"({"ref": -4.176666736602783})",
             opBuilderHelperToInt,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"(-4)")))),
        MapT(R"({"ref": -4.766667366027831})",
             opBuilderHelperToInt,
             {makeRef("ref"), makeValue(R"("round")")},
             SUCCESS(customRefExpected(json::Json(R"(-5)")))),
        MapT(R"({"ref": -4.176666736602783})",
             opBuilderHelperToInt,
             {makeRef("ref"), makeValue(R"("round")")},
             SUCCESS(customRefExpected(json::Json(R"(-4)")))),
        MapT(R"({"ref": 0.7124601006507874})",
             opBuilderHelperToInt,
             {makeRef("ref"), makeValue(R"("round")")},
             SUCCESS(customRefExpected(json::Json(R"(1)")))),
        MapT(R"({"ref": 0.7124601006507874})",
             opBuilderHelperToInt,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"(0)")))),
        MapT(
            R"({"ref": 1.50})", opBuilderHelperToInt, {makeRef("ref")}, SUCCESS(customRefExpected(json::Json(R"(1)")))),
        // 1.49999999 narrowed to 1.5 as a float (and rounded to 2); as a double it rounds to 1
        MapT(R"({"ref": 1.49999999})",
             opBuilderHelperToInt,
             {makeRef("ref"), makeValue(R"("round")")},
             SUCCESS(customRefExpected(json::Json(R"(1)")))),
        MapT(R"({"ref": 1.49999999})",
             opBuilderHelperToInt,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"(1)")))),
        MapT(R"({"ref": 1.50})",
             opBuilderHelperToInt,
             {makeRef("ref"), makeValue(R"("round")")},
             SUCCESS(customRefExpected(json::Json(R"(2)")))),
        MapT(R"({"ref": 2.5})",
             opBuilderHelperToInt,
             {makeRef("ref"), makeValue(R"("round")")},
             SUCCESS(customRefExpected(json::Json(R"(3)")))),
        MapT(R"({"ref": -2.5})",
             opBuilderHelperToInt,
             {makeRef("ref"), makeValue(R"("round")")},
             SUCCESS(customRefExpected(json::Json(R"(-3)"))))),
    testNameFormatter<MapOperationTest>("ToInt"));
}
