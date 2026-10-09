#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "valueValidators.hpp"
#include <base/json.hpp>

using namespace schemf::validators;
using namespace testing;

// ---------------------------------------------------------------------------
// getBoolValidator
// ---------------------------------------------------------------------------

TEST(ValueValidatorTest, Bool_AcceptsBoolean)
{
    auto v = getBoolValidator();
    EXPECT_FALSE(base::isError(v(json::Json {"true"})));
    EXPECT_FALSE(base::isError(v(json::Json {"false"})));
}

TEST(ValueValidatorTest, Bool_RejectsNumber)
{
    auto v = getBoolValidator();
    auto res = v(json::Json {"1"});
    ASSERT_TRUE(base::isError(res));
    EXPECT_THAT(base::getError(res).message, HasSubstr("boolean"));
}

TEST(ValueValidatorTest, Bool_RejectsString)
{
    auto v = getBoolValidator();
    auto res = v(json::Json {"\"true\""});
    ASSERT_TRUE(base::isError(res));
}

// ---------------------------------------------------------------------------
// getShortValidator  (int8 range check)
// ---------------------------------------------------------------------------

TEST(ValueValidatorTest, Short_AcceptsInRange)
{
    auto v = getShortValidator();
    EXPECT_FALSE(base::isError(v(json::Json {"0"})));
    EXPECT_FALSE(base::isError(v(json::Json {"127"})));
    EXPECT_FALSE(base::isError(v(json::Json {"-128"})));
}

TEST(ValueValidatorTest, Short_RejectsOutOfRange)
{
    auto v = getShortValidator();
    auto res = v(json::Json {"200"});
    ASSERT_TRUE(base::isError(res));
    EXPECT_THAT(base::getError(res).message, HasSubstr("range"));
}

TEST(ValueValidatorTest, Short_RejectsString)
{
    auto v = getShortValidator();
    auto res = v(json::Json {"\"abc\""});
    ASSERT_TRUE(base::isError(res));
    EXPECT_THAT(base::getError(res).message, HasSubstr("integer"));
}

// ---------------------------------------------------------------------------
// getIntegerValidator
// ---------------------------------------------------------------------------

TEST(ValueValidatorTest, Integer_AcceptsInt)
{
    auto v = getIntegerValidator();
    EXPECT_FALSE(base::isError(v(json::Json {"42"})));
    EXPECT_FALSE(base::isError(v(json::Json {"-1"})));
}

TEST(ValueValidatorTest, Integer_RejectsString)
{
    auto v = getIntegerValidator();
    auto res = v(json::Json {"\"abc\""});
    ASSERT_TRUE(base::isError(res));
    EXPECT_THAT(base::getError(res).message, HasSubstr("integer"));
}

TEST(ValueValidatorTest, Integer_RejectsBoolean)
{
    auto v = getIntegerValidator();
    auto res = v(json::Json {"true"});
    ASSERT_TRUE(base::isError(res));
}

// ---------------------------------------------------------------------------
// getLongValidator
// ---------------------------------------------------------------------------

TEST(ValueValidatorTest, Long_AcceptsInt64)
{
    auto v = getLongValidator();
    EXPECT_FALSE(base::isError(v(json::Json {"-1"})));
    EXPECT_FALSE(base::isError(v(json::Json {"0"})));
}

TEST(ValueValidatorTest, Long_RejectsString)
{
    auto v = getLongValidator();
    auto res = v(json::Json {"\"abc\""});
    ASSERT_TRUE(base::isError(res));
    EXPECT_THAT(base::getError(res).message, HasSubstr("long"));
}

// ---------------------------------------------------------------------------
// getFloatValidator
// ---------------------------------------------------------------------------

TEST(ValueValidatorTest, Float_AcceptsFloat)
{
    auto v = getFloatValidator();
    EXPECT_FALSE(base::isError(v(json::Json {"0.5"})));
}

TEST(ValueValidatorTest, Float_RejectsBoolean)
{
    auto v = getFloatValidator();
    auto res = v(json::Json {"true"});
    ASSERT_TRUE(base::isError(res));
    EXPECT_THAT(base::getError(res).message, HasSubstr("float"));
}

// ---------------------------------------------------------------------------
// getDoubleValidator
// ---------------------------------------------------------------------------

TEST(ValueValidatorTest, Double_AcceptsDouble)
{
    auto v = getDoubleValidator();
    EXPECT_FALSE(base::isError(v(json::Json {"1.5"})));
}

TEST(ValueValidatorTest, Double_RejectsBoolean)
{
    auto v = getDoubleValidator();
    auto res = v(json::Json {"true"});
    ASSERT_TRUE(base::isError(res));
    EXPECT_THAT(base::getError(res).message, HasSubstr("double"));
}

// ---------------------------------------------------------------------------
// getUnsignedLongValidator
// ---------------------------------------------------------------------------

TEST(ValueValidatorTest, UnsignedLong_AcceptsUint64)
{
    auto v = getUnsignedLongValidator();
    EXPECT_FALSE(base::isError(v(json::Json {"1"})));
}

TEST(ValueValidatorTest, UnsignedLong_RejectsString)
{
    auto v = getUnsignedLongValidator();
    auto res = v(json::Json {"\"abc\""});
    ASSERT_TRUE(base::isError(res));
    EXPECT_THAT(base::getError(res).message, HasSubstr("unsigned long"));
}

// ---------------------------------------------------------------------------
// getStringValidator
// ---------------------------------------------------------------------------

TEST(ValueValidatorTest, String_AcceptsString)
{
    auto v = getStringValidator();
    EXPECT_FALSE(base::isError(v(json::Json {"\"hello\""})));
    EXPECT_FALSE(base::isError(v(json::Json {"\"\""})));
}

TEST(ValueValidatorTest, String_RejectsNumber)
{
    auto v = getStringValidator();
    auto res = v(json::Json {"42"});
    ASSERT_TRUE(base::isError(res));
    EXPECT_THAT(base::getError(res).message, HasSubstr("string"));
}

TEST(ValueValidatorTest, String_RejectsBoolean)
{
    auto v = getStringValidator();
    auto res = v(json::Json {"true"});
    ASSERT_TRUE(base::isError(res));
}

// ---------------------------------------------------------------------------
// getDateValidator
// ---------------------------------------------------------------------------

TEST(ValueValidatorTest, Date_AcceptsValidDate)
{
    auto v = getDateValidator();
    EXPECT_FALSE(base::isError(v(json::Json {"\"2020-01-01T01:00:00Z\""})));
}

TEST(ValueValidatorTest, Date_RejectsInvalidDateString)
{
    auto v = getDateValidator();
    auto res = v(json::Json {"\"not-a-date\""});
    ASSERT_TRUE(base::isError(res));
    EXPECT_THAT(base::getError(res).message, HasSubstr("date"));
}

TEST(ValueValidatorTest, Date_RejectsNumber)
{
    auto v = getDateValidator();
    auto res = v(json::Json {"42"});
    ASSERT_TRUE(base::isError(res));
    EXPECT_THAT(base::getError(res).message, HasSubstr("string"));
}

TEST(ValueValidatorTest, Date_RejectsOutOfRangeFields)
{
    auto v = getDateValidator();
    for (const auto* value : {R"("2024-13-01T00:00:00Z")",
                              R"("2024-02-31T00:00:00Z")",
                              R"("2023-02-29T00:00:00Z")",
                              R"("2024-01-01T24:00:00Z")",
                              R"("2024-01-01T25:00:00Z")",
                              R"("2024-01-01T00:60:00Z")",
                              R"("2024-01-01T00:00:60Z")",
                              R"("2024-01-01T23:59:60Z")"})
    {
        SCOPED_TRACE(value);
        auto res = v(json::Json {value});
        ASSERT_TRUE(base::isError(res));
        EXPECT_THAT(base::getError(res).message, HasSubstr("Invalid date"));
    }
}

TEST(ValueValidatorTest, Date_RejectsTrailingAndShortFields)
{
    auto v = getDateValidator();
    for (const auto* value : {R"("2024-01-01T00:00:00Zx")",
                              R"("2024-1-1T0:0:0Z")",
                              R"("2024-01-01T00:00:00")",
                              R"("2024-01-01T00:00:00.Z")",
                              R"("2024-01-01T00:00:00.1234567890Z")",
                              R"("2024-01-01T00:00:00Zul")",
                              R"("2024-01-01T00:00:00ZuluX")",
                              R"("2024-01-01T00:00:00ZULU")",
                              R"("2024-01-01T00:00:00ZUTC")"})
    {
        SCOPED_TRACE(value);
        auto res = v(json::Json {value});
        ASSERT_TRUE(base::isError(res));
    }
}

TEST(ValueValidatorTest, Date_AcceptsValidForms)
{
    auto v = getDateValidator();
    for (const auto* value : {R"("2024-01-01T00:00:00Z")",
                              R"("2024-02-29T23:59:59Z")",
                              R"("2024-01-01T00:00:00.123Z")",
                              R"("2024-01-01T00:00:00.123456789Z")",
                              R"("2024-01-01T00:00:00Zulu")",
                              R"("2024-01-01T00:00:00.123Zulu")"})
    {
        SCOPED_TRACE(value);
        EXPECT_FALSE(base::isError(v(json::Json {value})));
    }
}

// ---------------------------------------------------------------------------
// getIpValidator
// ---------------------------------------------------------------------------

TEST(ValueValidatorTest, Ip_AcceptsValidIpv4)
{
    auto v = getIpValidator();
    EXPECT_FALSE(base::isError(v(json::Json {"\"192.168.0.1\""})));
}

TEST(ValueValidatorTest, Ip_RejectsInvalidIpString)
{
    auto v = getIpValidator();
    auto res = v(json::Json {"\"not-an-ip\""});
    ASSERT_TRUE(base::isError(res));
    EXPECT_THAT(base::getError(res).message, HasSubstr("IP"));
}

TEST(ValueValidatorTest, Ip_RejectsNumber)
{
    auto v = getIpValidator();
    auto res = v(json::Json {"42"});
    ASSERT_TRUE(base::isError(res));
    EXPECT_THAT(base::getError(res).message, HasSubstr("string"));
}

TEST(ValueValidatorTest, Ip_AcceptsValidAddresses)
{
    auto v = getIpValidator();
    for (const auto* value : {R"("10.0.0.1")", R"("::1")", R"("2001:db8::1")", R"("::ffff:1.2.3.4")"})
    {
        SCOPED_TRACE(value);
        EXPECT_FALSE(base::isError(v(json::Json {value})));
    }
}

TEST(ValueValidatorTest, Ip_RejectsOutOfRangeOctets)
{
    auto v = getIpValidator();
    for (const auto* value : {R"("999.999.999.999")", R"("256.1.1.1")", R"("01.2.3.4")"})
    {
        SCOPED_TRACE(value);
        auto res = v(json::Json {value});
        ASSERT_TRUE(base::isError(res));
        EXPECT_THAT(base::getError(res).message, HasSubstr("Invalid IP"));
    }
}

TEST(ValueValidatorTest, Ip_RejectsMalformed)
{
    auto v = getIpValidator();
    for (const auto* value : {R"("1:2:")", R"("::::")", R"("1.2.3.4x")", R"(" 1.2.3.4")"})
    {
        SCOPED_TRACE(value);
        auto res = v(json::Json {value});
        ASSERT_TRUE(base::isError(res));
    }
}

TEST(ValueValidatorTest, Ip_RejectsEmbeddedNul)
{
    auto v = getIpValidator();
    auto res = v(json::Json {R"("10.0.0.1\u0000x")"});
    ASSERT_TRUE(base::isError(res));
}

// ---------------------------------------------------------------------------
// getBinaryValidator
// ---------------------------------------------------------------------------

TEST(ValueValidatorTest, Binary_AcceptsValidBase64)
{
    auto v = getBinaryValidator();
    // base64 of "Hello"
    EXPECT_FALSE(base::isError(v(json::Json {"\"SGVsbG8=\""})));
}

TEST(ValueValidatorTest, Binary_RejectsInvalidBase64)
{
    auto v = getBinaryValidator();
    auto res = v(json::Json {"\"not valid base64!!!\""});
    ASSERT_TRUE(base::isError(res));
    EXPECT_THAT(base::getError(res).message, HasSubstr("binary"));
}

TEST(ValueValidatorTest, Binary_RejectsNumber)
{
    auto v = getBinaryValidator();
    auto res = v(json::Json {"42"});
    ASSERT_TRUE(base::isError(res));
    EXPECT_THAT(base::getError(res).message, HasSubstr("string"));
}

TEST(ValueValidatorTest, Binary_RejectsTrailingGarbage)
{
    auto v = getBinaryValidator();
    for (const auto* value : {R"("QUJD!!!")", R"("")"})
    {
        SCOPED_TRACE(value);
        auto res = v(json::Json {value});
        ASSERT_TRUE(base::isError(res));
    }
}

TEST(ValueValidatorTest, Binary_AcceptsPadded)
{
    auto v = getBinaryValidator();
    for (const auto* value : {R"("QUJD")", R"("QUI=")"})
    {
        SCOPED_TRACE(value);
        EXPECT_FALSE(base::isError(v(json::Json {value})));
    }
}

// ---------------------------------------------------------------------------
// getObjectValidator
// ---------------------------------------------------------------------------

TEST(ValueValidatorTest, Object_AcceptsObject)
{
    auto v = getObjectValidator();
    EXPECT_FALSE(base::isError(v(json::Json {"{}"})));
}

TEST(ValueValidatorTest, Object_RejectsString)
{
    auto v = getObjectValidator();
    auto res = v(json::Json {"\"hello\""});
    ASSERT_TRUE(base::isError(res));
    EXPECT_THAT(base::getError(res).message, HasSubstr("object"));
}

TEST(ValueValidatorTest, Object_RejectsArray)
{
    auto v = getObjectValidator();
    auto res = v(json::Json {"[]"});
    ASSERT_TRUE(base::isError(res));
}

// ---------------------------------------------------------------------------
// getIncompatibleValidator
// ---------------------------------------------------------------------------

TEST(ValueValidatorTest, Incompatible_AlwaysFails)
{
    auto v = getIncompatibleValidator();
    ASSERT_TRUE(base::isError(v(json::Json {"true"})));
    ASSERT_TRUE(base::isError(v(json::Json {"42"})));
    ASSERT_TRUE(base::isError(v(json::Json {"\"hello\""})));
    ASSERT_TRUE(base::isError(v(json::Json {"{}"})));
}

// ---------------------------------------------------------------------------
// getGeoValidator — all six OpenSearch formats
// ---------------------------------------------------------------------------

TEST(GeoValidatorTest, Object_LatLon_Valid)
{
    auto v = getGeoValidator();
    EXPECT_FALSE(base::isError(v(json::Json {R"({"lat":40.71,"lon":-74.00})"})));
}

TEST(GeoValidatorTest, Object_LatLon_LatOutOfRange)
{
    auto v = getGeoValidator();
    EXPECT_TRUE(base::isError(v(json::Json {R"({"lat":91.0,"lon":0.0})"})));
}

TEST(GeoValidatorTest, Object_LatLon_LonOutOfRange)
{
    auto v = getGeoValidator();
    EXPECT_TRUE(base::isError(v(json::Json {R"({"lat":0.0,"lon":181.0})"})));
}

TEST(GeoValidatorTest, Object_GeoJson_Valid)
{
    auto v = getGeoValidator();
    EXPECT_FALSE(base::isError(v(json::Json {R"({"type":"Point","coordinates":[-74.00,40.71]})"})));
}

TEST(GeoValidatorTest, Object_GeoJson_WrongType)
{
    auto v = getGeoValidator();
    EXPECT_TRUE(base::isError(v(json::Json {R"({"type":"LineString","coordinates":[-74.00,40.71]})"})));
}

TEST(GeoValidatorTest, Object_Invalid)
{
    auto v = getGeoValidator();
    auto res = v(json::Json {R"({"x":1,"y":2})"});
    ASSERT_TRUE(base::isError(res));
    EXPECT_THAT(base::getError(res).message, HasSubstr("geo_point object"));
}

TEST(GeoValidatorTest, String_LatCommaLon_Valid)
{
    auto v = getGeoValidator();
    EXPECT_FALSE(base::isError(v(json::Json {"\"40.71,-74.00\""})));
}

TEST(GeoValidatorTest, String_WKT_Valid)
{
    auto v = getGeoValidator();
    EXPECT_FALSE(base::isError(v(json::Json {"\"POINT (-74.00 40.71)\""})));
    EXPECT_FALSE(base::isError(v(json::Json {"\"POINT(-74.00 40.71)\""})));
}

TEST(GeoValidatorTest, String_WKT_Invalid)
{
    auto v = getGeoValidator();
    EXPECT_TRUE(base::isError(v(json::Json {"\"POINT (-74.00 40.71)garbageAtTheENd\""})));
    EXPECT_TRUE(base::isError(v(json::Json {"\"POINT)(-74.00 40.71)\""})));
}

TEST(GeoValidatorTest, String_Geohash_Valid)
{
    auto v = getGeoValidator();
    EXPECT_FALSE(base::isError(v(json::Json {"\"txhxegj0uyp3\""})));
}

TEST(GeoValidatorTest, String_Malformed)
{
    auto v = getGeoValidator();
    auto res = v(json::Json {"\"not_a_geo_value\""});
    ASSERT_TRUE(base::isError(res));
    EXPECT_THAT(base::getError(res).message, HasSubstr("geo_point string"));
}

TEST(GeoValidatorTest, Array_LonLat_Valid)
{
    auto v = getGeoValidator();
    EXPECT_FALSE(base::isError(v(json::Json {"[-74.00,40.71]"})));
}

TEST(GeoValidatorTest, Array_LonLat_WrongSize)
{
    auto v = getGeoValidator();
    EXPECT_TRUE(base::isError(v(json::Json {"[-74.00,40.71,0.0]"})));
}

TEST(GeoValidatorTest, Array_LonLat_OutOfRange)
{
    auto v = getGeoValidator();
    EXPECT_TRUE(base::isError(v(json::Json {"[-74.00,91.0]"})));
}

TEST(GeoValidatorTest, Array_Of_GeoObjects_Valid)
{
    auto v = getGeoValidator();
    EXPECT_FALSE(base::isError(v(json::Json {R"([{"lat":40.71,"lon":-74.00},{"lat":50.0,"lon":10.0}])"})));
}

TEST(GeoValidatorTest, Array_Of_DifferentGeoObjects_Valid)
{
    auto v = getGeoValidator();
    EXPECT_FALSE(
        base::isError(v(json::Json {R"([{"lat":40.71,"lon":-74.00},{"type":"Point","coordinates":[-74.00,40.71]}])"})));
}

TEST(GeoValidatorTest, Array_Of_GeoJsonAndStrings_Valid)
{
    auto v = getGeoValidator();
    EXPECT_FALSE(base::isError(v(json::Json {R"([{"type":"Point","coordinates":[-74.00,40.71]},"40.71,-74.00"])"})));
}

TEST(GeoValidatorTest, Array_Of_GeoObjects_OneInvalid)
{
    auto v = getGeoValidator();
    EXPECT_TRUE(base::isError(v(json::Json {R"([{"lat":40.71,"lon":-74.00},{"lat":91.0,"lon":0.0}])"})));
}

TEST(GeoValidatorTest, Array_Of_GeoStrings_Valid)
{
    auto v = getGeoValidator();
    EXPECT_FALSE(base::isError(v(json::Json {R"([[-74.00,40.71],[-7.00,4.71]])"})));
}

TEST(GeoValidatorTest, Array_Of_GeoStrings_ValidArrays)
{
    auto v = getGeoValidator();
    EXPECT_FALSE(base::isError(v(json::Json {R"(["40.71,-74.00","50.0,10.0"])"})));
}

TEST(GeoValidatorTest, Array_Of_InvalidElements)
{
    auto v = getGeoValidator();
    EXPECT_TRUE(base::isError(v(json::Json {R"([{"x":1},{"y":2}])"})));
}

TEST(GeoValidatorTest, Boolean_Unsupported)
{
    auto v = getGeoValidator();
    auto res = v(json::Json {"true"});
    ASSERT_TRUE(base::isError(res));
    EXPECT_THAT(base::getError(res).message, HasSubstr("unsupported JSON type"));
}
