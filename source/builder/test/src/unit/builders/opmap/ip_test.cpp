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
        MapT({}, opBuilderHelperIPVersionFromIPStr, FAILURE()),
        MapT({makeValue(R"("192.168.0.1")")}, opBuilderHelperIPVersionFromIPStr, FAILURE()),
        MapT({makeRef("ref")}, opBuilderHelperIPVersionFromIPStr, SUCCESS(customRefExpected())),
        MapT({makeRef("ref"), makeRef("ref")}, opBuilderHelperIPVersionFromIPStr, FAILURE()),
        MapT({makeRef("ref")}, opBuilderHelperIPVersionFromIPStr, SUCCESS(jTypeRefExpected(json::Json::Type::String))),
        MapT({makeRef("ref")}, opBuilderHelperIPVersionFromIPStr, FAILURE(jTypeRefExpected(json::Json::Type::Number))),
        MapT({makeRef("ref")}, opBuilderHelperIPVersionFromIPStr, FAILURE(jTypeRefExpected(json::Json::Type::Object))),
        MapT({makeRef("ref")}, opBuilderHelperIPVersionFromIPStr, FAILURE(jTypeRefExpected(json::Json::Type::Array))),
        MapT({makeRef("ref")}, opBuilderHelperIPVersionFromIPStr, FAILURE(jTypeRefExpected(json::Json::Type::Boolean))),
        MapT({makeRef("ref")}, opBuilderHelperIPVersionFromIPStr, FAILURE(jTypeRefExpected(json::Json::Type::Null)))),
    testNameFormatter<MapBuilderTest>("IpVersion"));
} // namespace mapbuildtest

namespace mapoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    MapOperationTest,
    testing::Values(
        MapT(R"({"ref": "127.0.0.1"})",
             opBuilderHelperIPVersionFromIPStr,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("IPv4")")))),
        MapT(R"({"ref": "::1"})",
             opBuilderHelperIPVersionFromIPStr,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("IPv6")")))),
        MapT(R"({"notRef": "127.0.0.1"})",
             opBuilderHelperIPVersionFromIPStr,
             {makeRef("ref")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": "hola"})", opBuilderHelperIPVersionFromIPStr, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": 1})", opBuilderHelperIPVersionFromIPStr, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": true})", opBuilderHelperIPVersionFromIPStr, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": null})", opBuilderHelperIPVersionFromIPStr, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(
            R"({"ref": [1, 2, 3]})", opBuilderHelperIPVersionFromIPStr, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(
            R"({"ref": {"a": 1}})", opBuilderHelperIPVersionFromIPStr, {makeRef("ref")}, FAILURE(customRefExpected()))),
    testNameFormatter<MapOperationTest>("IpVersion"));
} // namespace mapoperatestest
