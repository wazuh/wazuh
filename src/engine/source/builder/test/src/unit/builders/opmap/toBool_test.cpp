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
        /*** to_bool ***/
        MapT({}, opBuilderHelperToBool, FAILURE()),
        // The value must be a reference: a literal, even "true", is a build error
        MapT({makeValue(R"("true")")}, opBuilderHelperToBool, FAILURE()),
        MapT({makeValue(R"(1)")}, opBuilderHelperToBool, FAILURE()),
        MapT({makeRef("ref")}, opBuilderHelperToBool, SUCCESS()),
        MapT({makeRef("ref"), makeRef("ref")}, opBuilderHelperToBool, FAILURE()),
        MapT({makeRef("ref"), makeValue(R"("true")")}, opBuilderHelperToBool, FAILURE()),
        /*** Schema type validation (getType -> typeToJType -> Number or String) ***/
        MapT({makeRef("ref")}, opBuilderHelperToBool, SUCCESS(schemaRefExpected(schemf::Type::INTEGER))),
        MapT({makeRef("ref")}, opBuilderHelperToBool, SUCCESS(schemaRefExpected(schemf::Type::SHORT))),
        MapT({makeRef("ref")}, opBuilderHelperToBool, SUCCESS(schemaRefExpected(schemf::Type::LONG))),
        MapT({makeRef("ref")}, opBuilderHelperToBool, SUCCESS(schemaRefExpected(schemf::Type::FLOAT))),
        MapT({makeRef("ref")}, opBuilderHelperToBool, SUCCESS(schemaRefExpected(schemf::Type::DOUBLE))),
        MapT({makeRef("ref")}, opBuilderHelperToBool, SUCCESS(schemaRefExpected(schemf::Type::SCALED_FLOAT))),
        // A string field may hold "true"/"false", so keyword/text references are accepted
        MapT({makeRef("ref")}, opBuilderHelperToBool, SUCCESS(schemaRefExpected(schemf::Type::KEYWORD))),
        MapT({makeRef("ref")}, opBuilderHelperToBool, SUCCESS(schemaRefExpected(schemf::Type::TEXT))),
        // DATE and IP map to the JSON string type, so the build-time check accepts them too
        MapT({makeRef("ref")}, opBuilderHelperToBool, SUCCESS(schemaRefExpected(schemf::Type::DATE))),
        MapT({makeRef("ref")}, opBuilderHelperToBool, SUCCESS(schemaRefExpected(schemf::Type::IP))),
        MapT({makeRef("ref")}, opBuilderHelperToBool, SUCCESS(schemaRefExpected(schemf::Type::BOOLEAN))),
        MapT({makeRef("ref")}, opBuilderHelperToBool, FAILURE(schemaRefExpected(schemf::Type::OBJECT))),
        MapT({makeRef("ref")}, opBuilderHelperToBool, FAILURE(schemaRefExpected(schemf::Type::NESTED)))),
    testNameFormatter<MapBuilderTest>("ToBool"));
}

namespace mapoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    MapOperationTest,
    testing::Values(
        /*** to_bool ***/
        /*** reference not found ***/
        MapT(R"({"notRef": 1})", opBuilderHelperToBool, {makeRef("ref")}, FAILURE(customRefExpected())),
        /*** a boolean reference field is mapped as it is ***/
        MapT(R"({"ref": true})",
             opBuilderHelperToBool,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json("true")))),
        MapT(R"({"ref": false})",
             opBuilderHelperToBool,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json("false")))),
        /*** invalid type reference field: only a boolean, a number or a "true"/"false" string is accepted ***/
        MapT(R"({"ref": null})", opBuilderHelperToBool, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": [1, 2, 3, 4]})", opBuilderHelperToBool, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": {"key": "value"}})", opBuilderHelperToBool, {makeRef("ref")}, FAILURE(customRefExpected())),
        /*** strings other than "true"/"false" ***/
        MapT(R"({"ref": "some"})", opBuilderHelperToBool, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": "[1,2,3,4]"})", opBuilderHelperToBool, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": "1"})", opBuilderHelperToBool, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": "0"})", opBuilderHelperToBool, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": "yes"})", opBuilderHelperToBool, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": "no"})", opBuilderHelperToBool, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": ""})", opBuilderHelperToBool, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": " true"})", opBuilderHelperToBool, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": "true "})", opBuilderHelperToBool, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": "truee"})", opBuilderHelperToBool, {makeRef("ref")}, FAILURE(customRefExpected())),
        /*** "true"/"false" strings, case-insensitive ***/
        MapT(R"({"ref": "true"})",
             opBuilderHelperToBool,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json("true")))),
        MapT(R"({"ref": "TRUE"})",
             opBuilderHelperToBool,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json("true")))),
        MapT(R"({"ref": "True"})",
             opBuilderHelperToBool,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json("true")))),
        MapT(R"({"ref": "tRuE"})",
             opBuilderHelperToBool,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json("true")))),
        MapT(R"({"ref": "false"})",
             opBuilderHelperToBool,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json("false")))),
        MapT(R"({"ref": "FALSE"})",
             opBuilderHelperToBool,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json("false")))),
        MapT(R"({"ref": "False"})",
             opBuilderHelperToBool,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json("false")))),
        /*** numbers: zero is false, anything else is true ***/
        MapT(R"({"ref": 1})", opBuilderHelperToBool, {makeRef("ref")}, SUCCESS(customRefExpected(json::Json("true")))),
        MapT(
            R"({"ref": 1.0})", opBuilderHelperToBool, {makeRef("ref")}, SUCCESS(customRefExpected(json::Json("true")))),
        MapT(R"({"ref": 0})", opBuilderHelperToBool, {makeRef("ref")}, SUCCESS(customRefExpected(json::Json("false")))),
        MapT(R"({"ref": 0.0})",
             opBuilderHelperToBool,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json("false")))),
        MapT(R"({"ref": -0.0})",
             opBuilderHelperToBool,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json("false")))),
        MapT(R"({"ref": 2})", opBuilderHelperToBool, {makeRef("ref")}, SUCCESS(customRefExpected(json::Json("true")))),
        MapT(R"({"ref": -1})", opBuilderHelperToBool, {makeRef("ref")}, SUCCESS(customRefExpected(json::Json("true")))),
        MapT(
            R"({"ref": 0.5})", opBuilderHelperToBool, {makeRef("ref")}, SUCCESS(customRefExpected(json::Json("true")))),
        MapT(R"({"ref": 3000000000})",
             opBuilderHelperToBool,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json("true"))))),
    testNameFormatter<MapOperationTest>("ToBool"));
}
