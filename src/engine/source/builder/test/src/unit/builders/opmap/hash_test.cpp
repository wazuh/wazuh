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
        /*** SHA1 ***/
        MapT({}, opBuilderHelperHashSHA1, FAILURE()),
        MapT({makeValue(R"("value")")}, opBuilderHelperHashSHA1, FAILURE()),
        MapT({makeRef("ref")}, opBuilderHelperHashSHA1, SUCCESS(customRefExpected())),
        MapT({makeRef("ref"), makeValue(R"("value")")}, opBuilderHelperHashSHA1, FAILURE()),
        MapT({makeRef("ref"), makeRef("ref")}, opBuilderHelperHashSHA1, FAILURE()),
        MapT({makeRef("ref")}, opBuilderHelperHashSHA1, SUCCESS(jTypeRefExpected(json::Json::Type::String))),
        MapT({makeRef("ref")}, opBuilderHelperHashSHA1, FAILURE(jTypeRefExpected(json::Json::Type::Number))),
        MapT({makeRef("ref")}, opBuilderHelperHashSHA1, FAILURE(jTypeRefExpected(json::Json::Type::Boolean))),
        MapT({makeRef("ref")}, opBuilderHelperHashSHA1, FAILURE(jTypeRefExpected(json::Json::Type::Object))),
        MapT({makeRef("ref")}, opBuilderHelperHashSHA1, FAILURE(jTypeRefExpected(json::Json::Type::Array))),
        MapT({makeRef("ref")}, opBuilderHelperHashSHA1, FAILURE(jTypeRefExpected(json::Json::Type::Null)))),
    testNameFormatter<MapBuilderTest>("Hash"));
} // namespace mapbuildtest

namespace mapoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    MapOperationTest,
    testing::Values(
        /*** SHA1 ***/
        MapT(R"({"ref": "hello test!"})",
             opBuilderHelperHashSHA1,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("3973ddc5378b7f9aea9ecaaf4e2d028265a837fd")")))),
        MapT(R"({"ref": ""})",
             opBuilderHelperHashSHA1,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"("da39a3ee5e6b4b0d3255bfef95601890afd80709")")))),
        MapT(R"({"notRef": "hello test!"})", opBuilderHelperHashSHA1, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": 1234})", opBuilderHelperHashSHA1, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": true})", opBuilderHelperHashSHA1, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": null})", opBuilderHelperHashSHA1, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": [1, 2, 3]})", opBuilderHelperHashSHA1, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": {"key": "value"}})", opBuilderHelperHashSHA1, {makeRef("ref")}, FAILURE(customRefExpected()))),
    testNameFormatter<MapOperationTest>("Hash"));
} // namespace mapoperatestest
