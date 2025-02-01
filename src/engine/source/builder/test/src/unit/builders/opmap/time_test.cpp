#include "builders/baseBuilders_test.hpp"

#include "builders/opmap/opBuilderHelperMap.hpp"

using namespace builder::builders;

namespace
{
auto customRefExpected()
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillOnce(testing::Return(false));

        return None {};
    };
}

auto customRefExpected(json::Json value)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillOnce(testing::Return(false));

        return value;
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
} // namespace

namespace mapbuildtest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    MapBuilderTest,
    testing::Values(
        /*** Epoch From System ***/
        MapT({}, opBuilderHelperEpochTimeFromSystem, SUCCESS()),
        MapT({makeValue(R"("value")")}, opBuilderHelperEpochTimeFromSystem, FAILURE()),
        MapT({makeRef("ref")}, opBuilderHelperEpochTimeFromSystem, FAILURE()),
        /*** Get Date ***/
        MapT({}, opBuilderHelperGetDate, SUCCESS()),
        MapT({makeValue(R"("value")")}, opBuilderHelperGetDate, FAILURE()),
        MapT({makeRef("ref")}, opBuilderHelperGetDate, FAILURE()),
        /*** Date From Epoch ***/
        MapT({}, opBuilderHelperDateFromEpochTime, FAILURE()),
        MapT({makeValue(R"("value")")}, opBuilderHelperDateFromEpochTime, FAILURE()),
        MapT({makeValue(R"(123456789)")}, opBuilderHelperDateFromEpochTime, FAILURE()),
        MapT({makeRef("ref")}, opBuilderHelperDateFromEpochTime, SUCCESS(customRefExpected())),
        MapT({makeRef("ref"), makeRef("ref")}, opBuilderHelperDateFromEpochTime, FAILURE()),
        MapT({makeRef("ref")}, opBuilderHelperDateFromEpochTime, SUCCESS(jTypeRefExpected(json::Json::Type::Number))),
        MapT({makeRef("ref")}, opBuilderHelperDateFromEpochTime, FAILURE(jTypeRefExpected(json::Json::Type::String))),
        MapT({makeRef("ref")}, opBuilderHelperDateFromEpochTime, FAILURE(jTypeRefExpected(json::Json::Type::Object))),
        MapT({makeRef("ref")}, opBuilderHelperDateFromEpochTime, FAILURE(jTypeRefExpected(json::Json::Type::Array))),
        MapT({makeRef("ref")}, opBuilderHelperDateFromEpochTime, FAILURE(jTypeRefExpected(json::Json::Type::Boolean))),
        MapT({makeRef("ref")}, opBuilderHelperDateFromEpochTime, FAILURE(jTypeRefExpected(json::Json::Type::Null)))),
    testNameFormatter<MapBuilderTest>("Time"));
} // namespace mapbuildtest

namespace mapoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    MapOperationTest,
    testing::Values(
        /*** Epoch From System ***/
        MapT("{}", opBuilderHelperEpochTimeFromSystem, {}, SUCCESS(IGNORE_MAP_RESULT)),
        /*** Get date ***/
        MapT("{}", opBuilderHelperGetDate, {}, SUCCESS(IGNORE_MAP_RESULT)),
        /*** Date From Epoch ***/
        MapT(R"({"ref": 1706172785})",
             opBuilderHelperDateFromEpochTime,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("2024-01-25T08:53:05.000000Z")")))),
        MapT(R"({"ref": -1706172785})",
             opBuilderHelperDateFromEpochTime,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("1915-12-08T15:06:55.000000Z")")))),
        MapT(R"({"ref": 1727218980.597629})",
             opBuilderHelperDateFromEpochTime,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("2024-09-24T23:03:00.597629Z")")))),
        MapT(R"({"ref": 17061727859999999999999})",
             opBuilderHelperDateFromEpochTime,
             {makeRef("ref")},
             FAILURE(customRefExpected())),
        MapT(R"({"notRef": 1706172785})",
             opBuilderHelperDateFromEpochTime,
             {makeRef("ref")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": "1706172785"})",
             opBuilderHelperDateFromEpochTime,
             {makeRef("ref")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": 1706172785.0})",
             opBuilderHelperDateFromEpochTime,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("2024-01-25T08:53:05.000000Z")")))),
        MapT(R"({"ref": []})", opBuilderHelperDateFromEpochTime, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": {}})", opBuilderHelperDateFromEpochTime, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": true})", opBuilderHelperDateFromEpochTime, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": null})", opBuilderHelperDateFromEpochTime, {makeRef("ref")}, FAILURE(customRefExpected()))),
    testNameFormatter<MapOperationTest>("Time"));
} // namespace mapoperatestest
