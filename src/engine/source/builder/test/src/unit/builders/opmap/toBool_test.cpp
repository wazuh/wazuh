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

} // namespace

namespace mapbuildtest
{
INSTANTIATE_TEST_SUITE_P(Builders,
                         MapBuilderTest,
                         testing::Values(MapT({}, opBuilderHelperToBool, FAILURE()),
                                         MapT({makeValue(R"("true")")}, opBuilderHelperToBool, FAILURE()),
                                         MapT({makeRef("ref")}, opBuilderHelperToBool, SUCCESS()),
                                         MapT({makeRef("ref"), makeRef("ref")}, opBuilderHelperToBool, FAILURE())),
                         testNameFormatter<MapBuilderTest>("ToBool"));
}

namespace mapoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    MapOperationTest,
    testing::Values(
        /*** to_bool ***/
        /*** invalid type reference field ***/
        MapT(R"({"ref": "some"})", opBuilderHelperToBool, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": "[1,2,3,4]"})", opBuilderHelperToBool, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": {"key": "value"}})", opBuilderHelperToBool, {makeRef("ref")}, FAILURE(customRefExpected())),
        /*** success cases ***/
        MapT(R"({"ref": 1})", opBuilderHelperToBool, {makeRef("ref")}, SUCCESS(customRefExpected(json::Json("true")))),
        MapT(
            R"({"ref": 1.0})", opBuilderHelperToBool, {makeRef("ref")}, SUCCESS(customRefExpected(json::Json("true")))),
        MapT(R"({"ref": 0})", opBuilderHelperToBool, {makeRef("ref")}, SUCCESS(customRefExpected(json::Json("false")))),
        MapT(R"({"ref": 0.0})",
             opBuilderHelperToBool,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json("false")))),
        /*** additional numeric values now supported ***/
        MapT(R"({"ref": 2})", opBuilderHelperToBool, {makeRef("ref")}, SUCCESS(customRefExpected(json::Json("true")))),
        MapT(R"({"ref": -1})", opBuilderHelperToBool, {makeRef("ref")}, SUCCESS(customRefExpected(json::Json("true")))),
        MapT(R"({"ref": 0.5})",
             opBuilderHelperToBool,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json("true"))))),
    testNameFormatter<MapOperationTest>("ToBool"));
}
