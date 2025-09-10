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

auto stypeRefExpected(schemf::Type sType)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillOnce(testing::Return(true));
        EXPECT_CALL(*mocks.validator, getType(DotPath("ref"))).WillRepeatedly(testing::Return(sType));
        return None {};
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
        MapT({makeRef("ref")}, opBuilderHelperDateFromEpochTime, FAILURE(jTypeRefExpected(json::Json::Type::Null))),
        /*** Date To Epoch ***/
        MapT({}, opBuilderHelperDateToEpochTime, FAILURE()),
        MapT({makeValue(R"("2024-05-17T15:10:58Z")")}, opBuilderHelperDateToEpochTime, FAILURE()),
        MapT({makeRef("ref")}, opBuilderHelperDateToEpochTime, SUCCESS(customRefExpected())),
        // ok: ref + format literal
        MapT({makeRef("ref"), makeValue(R"("%FT%TZ")")}, opBuilderHelperDateToEpochTime, SUCCESS(customRefExpected())),
        // fail: format must be value, not ref
        MapT({makeRef("ref"), makeRef("ref")}, opBuilderHelperDateToEpochTime, FAILURE()),
        // input type checks for ref
        MapT({makeRef("ref")}, opBuilderHelperDateToEpochTime, SUCCESS(stypeRefExpected(schemf::Type::DATE))),
        MapT({makeRef("ref")}, opBuilderHelperDateToEpochTime, SUCCESS(stypeRefExpected(schemf::Type::DATE_NANOS))),
        MapT({makeRef("ref")}, opBuilderHelperDateToEpochTime, FAILURE(stypeRefExpected(schemf::Type::INTEGER))),
        MapT({makeRef("ref")}, opBuilderHelperDateToEpochTime, FAILURE(stypeRefExpected(schemf::Type::OBJECT))),
        MapT({makeRef("ref")}, opBuilderHelperDateToEpochTime, FAILURE(stypeRefExpected(schemf::Type::BOOLEAN))),
        MapT({makeRef("ref")}, opBuilderHelperDateToEpochTime, FAILURE(stypeRefExpected(schemf::Type::WILDCARD))),
        MapT({makeRef("ref")}, opBuilderHelperDateToEpochTime, FAILURE(stypeRefExpected(schemf::Type::TEXT))),
        // empty format literal → build-time FAILURE
        MapT({makeRef("ref"), makeValue(R"("")")}, opBuilderHelperDateToEpochTime, FAILURE()),
        MapT({makeRef("ref"), makeValue(R"("%FT%TZ%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")")},
             opBuilderHelperDateToEpochTime,
             FAILURE()),
        // format with exactly 64 chars
        MapT({makeRef("ref"), makeValue(R"("%FT%TZ%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")")},
             opBuilderHelperDateToEpochTime,
             SUCCESS(customRefExpected()))),
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
        MapT(R"({"ref": null})", opBuilderHelperDateFromEpochTime, {makeRef("ref")}, FAILURE(customRefExpected())),
        /*** Date To Epoch ***/
        // Epoch start
        MapT(R"({"ref": "1970-01-01T00:00:00Z"})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref"), makeValue(R"("%FT%TZ")")},
             SUCCESS(customRefExpected(
                 []
                 {
                     json::Json j;
                     j.setDouble(0.0);
                     return j;
                 }()))),
        // UTC with 'Z'
        MapT(R"({"ref": "2024-05-17T15:10:58Z"})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref"), makeValue(R"("%FT%TZ")")},
             SUCCESS(customRefExpected(
                 []
                 {
                     json::Json j;
                     j.setDouble(1715958658.0);
                     return j;
                 }()))),
        // Same instant with offset -03:00
        MapT(R"({"ref": "2024-05-17T12:10:58-03:00"})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref"), makeValue(R"("%FT%T%Ez")")},
             SUCCESS(customRefExpected(
                 []
                 {
                     json::Json j;
                     j.setDouble(1715958658.0);
                     return j;
                 }()))),
        // Offset without colon (+hhmm)
        MapT(R"({"ref": "2024-05-17T12:10:58-0300"})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref"), makeValue(R"("%FT%T%z")")},
             SUCCESS(customRefExpected(
                 []
                 {
                     json::Json j;
                     j.setDouble(1715958658.0);
                     return j;
                 }()))),
        // Space instead of 'T' + offset
        MapT(R"({"ref": "2024-05-17 15:10:58+00:00"})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref"), makeValue(R"("%F %T%Ez")")},
             SUCCESS(customRefExpected(
                 []
                 {
                     json::Json j;
                     j.setDouble(1715958658.0);
                     return j;
                 }()))),
        // Space + offset without colon
        MapT(R"({"ref": "2024-05-17 12:10:58-0300"})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref"), makeValue(R"("%F %T%z")")},
             SUCCESS(customRefExpected(
                 []
                 {
                     json::Json j;
                     j.setDouble(1715958658.0);
                     return j;
                 }()))),
        // No timezone → assume UTC
        MapT(R"({"ref": "2024-05-17T15:10:58"})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref"), makeValue(R"("%FT%T")")},
             SUCCESS(customRefExpected(
                 []
                 {
                     json::Json j;
                     j.setDouble(1715958658.0);
                     return j;
                 }()))),
        // Negative epoch
        MapT(R"({"ref": "1969-12-31T23:59:59Z"})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref"), makeValue(R"("%FT%TZ")")},
             SUCCESS(customRefExpected(
                 []
                 {
                     json::Json j;
                     j.setDouble(-1.0);
                     return j;
                 }()))),
        // Basic (no extended) with Z
        MapT(R"({"ref": "20240517T151058Z"})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref"), makeValue(R"("%Y%m%dT%H%M%SZ")")},
             SUCCESS(customRefExpected(
                 []
                 {
                     json::Json j;
                     j.setDouble(1715958658.0);
                     return j;
                 }()))),
        // Basic with offset (colon)
        MapT(R"({"ref": "20240517T121058-03:00"})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref"), makeValue(R"("%Y%m%dT%H%M%S%Ez")")},
             SUCCESS(customRefExpected(
                 []
                 {
                     json::Json j;
                     j.setDouble(1715958658.0);
                     return j;
                 }()))),
        // Basic with offset (no colon)
        MapT(R"({"ref": "20240517T121058-0300"})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref"), makeValue(R"("%Y%m%dT%H%M%S%z")")},
             SUCCESS(customRefExpected(
                 []
                 {
                     json::Json j;
                     j.setDouble(1715958658.0);
                     return j;
                 }()))),
        // Basic + fractional seconds with Z
        MapT(R"({"ref": "20240924T230300.597629Z"})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref"), makeValue(R"("%Y%m%dT%H%M%SZ")")},
             SUCCESS(customRefExpected(
                 []
                 {
                     const long long us = 1727218980LL * 1000000LL + 597629LL;
                     json::Json j;
                     j.setDouble(static_cast<double>(us) / 1'000'000.0);
                     return j;
                 }()))),
        // Date-only with explicit format (%F) → success at midnight UTC
        MapT(R"({"ref": "1970-01-02"})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref"), makeValue(R"("%F")")},
             SUCCESS(customRefExpected(
                 []
                 {
                     json::Json j;
                     j.setDouble(86400.0);
                     return j;
                 }()))),
        // Success without format
        MapT(R"({"ref": "1970-01-01T00:00:00Z"})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref")},
             SUCCESS(customRefExpected(
                 []
                 {
                     json::Json j;
                     j.setDouble(0.0);
                     return j;
                 }()))),
        MapT(R"({"ref": "2024-05-17T15:10:58Z"})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref")},
             SUCCESS(customRefExpected(
                 []
                 {
                     json::Json j;
                     j.setDouble(1715958658.0);
                     return j;
                 }()))),
        // format with space
        MapT(R"({"ref": " 2024-05-17T15:10:58Z"})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref"), makeValue(R"(" %FT%TZ")")},
             SUCCESS(customRefExpected(
                 []
                 {
                     json::Json j;
                     j.setDouble(1715958658.0);
                     return j;
                 }()))),
        MapT(R"({"ref": "2024-05-17T15:10:58Z "})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref"), makeValue(R"("%FT%TZ ")")},
             SUCCESS(customRefExpected(
                 []
                 {
                     json::Json j;
                     j.setDouble(1715958658.0);
                     return j;
                 }()))),
        // Without format but offset present → should fail
        MapT(R"({"ref": "2024-05-17T12:10:58-03:00"})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref")},
             FAILURE(customRefExpected())),
        // Invalid format token → parse fails
        MapT(R"({"ref": "2024-05-17T15:10:58Z"})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref"), makeValue(R"("%Q")")},
             FAILURE(customRefExpected())),
        // format ok but not matching → parse fails
        MapT(R"({"ref": "2024/05/17 15:10:58Z"})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref"), makeValue(R"("%FT%TZ")")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": 1706172785})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref"), makeValue(R"("%FT%TZ")")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": []})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref"), makeValue(R"("%FT%TZ")")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": {}})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref"), makeValue(R"("%FT%TZ")")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": true})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref"), makeValue(R"("%FT%TZ")")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": null})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref"), makeValue(R"("%FT%TZ")")},
             FAILURE(customRefExpected())),
        MapT(R"({"notRef": "2024-05-17T15:10:58Z"})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref"), makeValue(R"("%FT%TZ")")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": "aaaa2024-05-17T15:10:58Z"})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref"), makeValue(R"("%FT%TZ")")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": "2024-05-17T15:10:58Zaaaa"})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref"), makeValue(R"("%FT%TZ")")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": "2024-05-17T15:10:58Z "})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref"), makeValue(R"("%FT%TZ")")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": " 2024-05-17T15:10:58Z"})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref"), makeValue(R"("%FT%TZ")")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": "2024-05-17T15:10:58Z2024-05-17T15:10:58Z"})",
             opBuilderHelperDateToEpochTime,
             {makeRef("ref")},
             FAILURE(customRefExpected()))),
    testNameFormatter<MapOperationTest>("Time"));
} // namespace mapoperatestest
