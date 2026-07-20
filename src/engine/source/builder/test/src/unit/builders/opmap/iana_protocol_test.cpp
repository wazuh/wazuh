#include "builders/baseBuilders_test.hpp"
#include "builders/opmap/opBuilderHelperMap.hpp"

using namespace builder::builders;

namespace
{

// Expectation functor for a missing schema field (no type check).
auto customRefExpected()
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillOnce(testing::Return(false));
        return None {};
    };
}

// Same but with a concrete json::Json value returned by the mock.
auto customRefExpected(json::Json value)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillOnce(testing::Return(false));
        return value;
    };
}

// Schema pre-check for reference json type.
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
        // -- iana_protocol_name_to_number --
        MapT({}, opBuilderHelperIanaProtocolNameToNumber, FAILURE()),
        MapT({makeRef("ref"), makeRef("ref")}, opBuilderHelperIanaProtocolNameToNumber, FAILURE()),
        // Must be reference (no literal)
        MapT({makeValue(R"("tcp")")}, opBuilderHelperIanaProtocolNameToNumber, FAILURE()),
        // Schema unknown: accept reference (no type check)
        MapT({makeRef("ref")}, opBuilderHelperIanaProtocolNameToNumber, SUCCESS(customRefExpected())),
        // Schema pre-check: must be string
        MapT({makeRef("ref")},
             opBuilderHelperIanaProtocolNameToNumber,
             SUCCESS(jTypeRefExpected(json::Json::Type::String))),
        MapT({makeRef("ref")},
             opBuilderHelperIanaProtocolNameToNumber,
             FAILURE(jTypeRefExpected(json::Json::Type::Number))),
        MapT({makeRef("ref")},
             opBuilderHelperIanaProtocolNameToNumber,
             FAILURE(jTypeRefExpected(json::Json::Type::Object))),
        MapT({makeRef("ref")},
             opBuilderHelperIanaProtocolNameToNumber,
             FAILURE(jTypeRefExpected(json::Json::Type::Array))),
        MapT({makeRef("ref")},
             opBuilderHelperIanaProtocolNameToNumber,
             FAILURE(jTypeRefExpected(json::Json::Type::Boolean))),
        MapT({makeRef("ref")},
             opBuilderHelperIanaProtocolNameToNumber,
             FAILURE(jTypeRefExpected(json::Json::Type::Null))),

        // -- iana_protocol_number_to_name --
        MapT({}, opBuilderHelperIanaProtocolNumberToName, FAILURE()),
        MapT({makeRef("ref"), makeRef("ref")}, opBuilderHelperIanaProtocolNumberToName, FAILURE()),
        // Must be reference (no literal)
        MapT({makeValue("6")}, opBuilderHelperIanaProtocolNumberToName, FAILURE()),
        // Schema unknown: accept reference (no type check)
        MapT({makeRef("ref")}, opBuilderHelperIanaProtocolNumberToName, SUCCESS(customRefExpected())),
        // Schema pre-check: number OR string
        MapT({makeRef("ref")},
             opBuilderHelperIanaProtocolNumberToName,
             SUCCESS(jTypeRefExpected(json::Json::Type::Number))),
        MapT({makeRef("ref")},
             opBuilderHelperIanaProtocolNumberToName,
             SUCCESS(jTypeRefExpected(json::Json::Type::String))),
        MapT({makeRef("ref")},
             opBuilderHelperIanaProtocolNumberToName,
             FAILURE(jTypeRefExpected(json::Json::Type::Object))),
        MapT({makeRef("ref")},
             opBuilderHelperIanaProtocolNumberToName,
             FAILURE(jTypeRefExpected(json::Json::Type::Array))),
        MapT({makeRef("ref")},
             opBuilderHelperIanaProtocolNumberToName,
             FAILURE(jTypeRefExpected(json::Json::Type::Boolean))),
        MapT({makeRef("ref")},
             opBuilderHelperIanaProtocolNumberToName,
             FAILURE(jTypeRefExpected(json::Json::Type::Null)))),
    testNameFormatter<MapBuilderTest>("IanaProtocol"));

} // namespace mapbuildtest

namespace mapoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    MapOperationTest,
    testing::Values(
        // iana_protocol_name_to_number success → expects STRING outputs
        MapT(R"({"ref": "tcp"})",
             opBuilderHelperIanaProtocolNameToNumber,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("6")")))),
        MapT(R"({"ref": "UDP"})",
             opBuilderHelperIanaProtocolNameToNumber,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("17")")))),
        MapT(R"({"ref": "ipv6-icmp"})",
             opBuilderHelperIanaProtocolNameToNumber,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("58")")))),
        MapT(R"({"ref": "udp_lite"})",
             opBuilderHelperIanaProtocolNameToNumber,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("136")")))),
        MapT(R"({"ref": "ip-in-ip"})",
             opBuilderHelperIanaProtocolNameToNumber,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("94")")))),
        MapT(R"({"ref": "icmpv6"})",
             opBuilderHelperIanaProtocolNameToNumber,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("58")")))),
        MapT(R"({"ref": "IPv6_NONXT"})",
             opBuilderHelperIanaProtocolNameToNumber,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("59")")))),

        // iana_protocol_name_to_number failures
        MapT(R"({"notRef": "tcp"})",
             opBuilderHelperIanaProtocolNameToNumber,
             {makeRef("ref")},
             FAILURE(customRefExpected())),
        MapT(
            R"({"ref": 123})", opBuilderHelperIanaProtocolNameToNumber, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": "smtp"})",
             opBuilderHelperIanaProtocolNameToNumber,
             {makeRef("ref")},
             FAILURE(customRefExpected())),

        // iana_protocol_number_to_name success (numeric input)
        MapT(R"({"ref": 6})",
             opBuilderHelperIanaProtocolNumberToName,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("tcp")")))),
        MapT(R"({"ref": 58})",
             opBuilderHelperIanaProtocolNumberToName,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("ipv6-icmp")")))),
        MapT(R"({"ref": 147})",
             opBuilderHelperIanaProtocolNumberToName,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("bit-emu")")))),

        // iana_protocol_number_to_name success (string input with number)
        MapT(R"({"ref": "6"})",
             opBuilderHelperIanaProtocolNumberToName,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("tcp")")))),
        MapT(R"({"ref": "58"})",
             opBuilderHelperIanaProtocolNumberToName,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("ipv6-icmp")")))),
        MapT(R"({"ref": "147"})",
             opBuilderHelperIanaProtocolNumberToName,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("bit-emu")")))),

        // iana_protocol_number_to_name failures (invalid/missing)
        MapT(R"({"notRef": 6})",
             opBuilderHelperIanaProtocolNumberToName,
             {makeRef("ref")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": -1})", opBuilderHelperIanaProtocolNumberToName, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(
            R"({"ref": 256})", opBuilderHelperIanaProtocolNumberToName, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(
            R"({"ref": 6.0})", opBuilderHelperIanaProtocolNumberToName, {makeRef("ref")}, FAILURE(customRefExpected())),
        // string input with invalid values
        MapT(R"({"ref": "-1"})",
             opBuilderHelperIanaProtocolNumberToName,
             {makeRef("ref")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": "256"})",
             opBuilderHelperIanaProtocolNumberToName,
             {makeRef("ref")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": "6.0"})",
             opBuilderHelperIanaProtocolNumberToName,
             {makeRef("ref")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": "abc"})",
             opBuilderHelperIanaProtocolNumberToName,
             {makeRef("ref")},
             FAILURE(customRefExpected())),
        // unassigned / experimental / reserved
        MapT(
            R"({"ref": 148})", opBuilderHelperIanaProtocolNumberToName, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(
            R"({"ref": 253})", opBuilderHelperIanaProtocolNumberToName, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": 255})",
             opBuilderHelperIanaProtocolNumberToName,
             {makeRef("ref")},
             FAILURE(customRefExpected()))),
    testNameFormatter<MapOperationTest>("IanaProtocol"));

} // namespace mapoperatestest
