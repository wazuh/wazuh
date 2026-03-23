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
INSTANTIATE_TEST_SUITE_P(Builders,
                         MapBuilderTest,
                         testing::Values(
                             /*** to_int ***/
                             MapT({}, opBuilderHelperToInt, FAILURE()),
                             MapT({makeValue(R"("true")")}, opBuilderHelperToInt, FAILURE()),
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
                             MapT({makeRef("ref"), makeValue(R"("round")")}, opBuilderHelperToInt, SUCCESS())),
                         testNameFormatter<MapBuilderTest>("ToInt"));
} // namespace mapbuildtest

namespace mapoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    MapOperationTest,
    testing::Values(
        /*** to_int ***/
        /*** invalid type reference field ***/
        MapT(R"({"ref": "some"})", opBuilderHelperToInt, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": "[1,2,3,4]"})", opBuilderHelperToInt, {makeRef("ref")}, FAILURE(customRefExpected())),
        MapT(R"({"ref": {"key": "value"}})", opBuilderHelperToInt, {makeRef("ref")}, FAILURE(customRefExpected())),
        /*** success cases ***/
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
        MapT(R"({"ref": 1.49999999})",
             opBuilderHelperToInt,
             {makeRef("ref"), makeValue(R"("round")")},
             SUCCESS(customRefExpected(json::Json(R"(2)")))),
        MapT(R"({"ref": 1.49999999})",
             opBuilderHelperToInt,
             {makeRef("ref")},
             SUCCESS(customRefExpected(json::Json(R"(1)")))),
        MapT(R"({"ref": 1.50})",
             opBuilderHelperToInt,
             {makeRef("ref"), makeValue(R"("round")")},
             SUCCESS(customRefExpected(json::Json(R"(2)"))))),
    testNameFormatter<MapOperationTest>("ToInt"));
}
