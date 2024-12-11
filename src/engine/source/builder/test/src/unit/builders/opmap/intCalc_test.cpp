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
        MapT({}, opBuilderHelperIntCalc, FAILURE()),
        MapT({makeValue(R"("sum")")}, opBuilderHelperIntCalc, FAILURE()),
        MapT({makeValue(R"("sum")"), makeValue(R"(1)")}, opBuilderHelperIntCalc, FAILURE()),
        MapT({makeValue(R"("sum")"), makeValue(R"(1)"), makeValue(R"(2)")}, opBuilderHelperIntCalc, SUCCESS()),
        MapT({makeValue(R"("sums")"), makeValue(R"(1)")}, opBuilderHelperIntCalc, FAILURE()),
        MapT({makeValue(R"(1)"), makeValue(R"(1)")}, opBuilderHelperIntCalc, FAILURE()),
        MapT({makeValue(R"("sub")"), makeValue(R"(1)")}, opBuilderHelperIntCalc, FAILURE()),
        MapT({makeValue(R"("mul")"), makeValue(R"(1)")}, opBuilderHelperIntCalc, FAILURE()),
        MapT({makeValue(R"("div")"), makeValue(R"(1)")}, opBuilderHelperIntCalc, FAILURE()),
        MapT({makeValue(R"("div")"), makeValue(R"(0)")}, opBuilderHelperIntCalc, FAILURE()),
        MapT({makeValue(R"("sub")"), makeValue(R"(1)"), makeValue(R"(1)")}, opBuilderHelperIntCalc, SUCCESS()),
        MapT({makeValue(R"("mul")"), makeValue(R"(1)"), makeValue(R"(1)")}, opBuilderHelperIntCalc, SUCCESS()),
        MapT({makeValue(R"("div")"), makeValue(R"(1)"), makeValue(R"(1)")}, opBuilderHelperIntCalc, SUCCESS()),
        MapT({makeValue(R"("div")"), makeValue(R"(0)"), makeValue(R"(1)")}, opBuilderHelperIntCalc, FAILURE()),
        MapT({makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(1)")},
             opBuilderHelperIntCalc,
             SUCCESS(customRefExpected())),
        MapT({makeValue(R"("sub")"), makeRef("ref"), makeValue(R"(1)")},
             opBuilderHelperIntCalc,
             SUCCESS(customRefExpected())),
        MapT({makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(1)")},
             opBuilderHelperIntCalc,
             SUCCESS(customRefExpected())),
        MapT({makeValue(R"("div")"), makeRef("ref"), makeValue(R"(1)")},
             opBuilderHelperIntCalc,
             SUCCESS(customRefExpected())),
        MapT({makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(1)")},
             opBuilderHelperIntCalc,
             SUCCESS(schemaRefExpected(schemf::Type::INTEGER))),
        MapT({makeValue(R"("sub")"), makeRef("ref"), makeValue(R"(1)")},
             opBuilderHelperIntCalc,
             SUCCESS(schemaRefExpected(schemf::Type::SHORT))),
        MapT({makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(1)")},
             opBuilderHelperIntCalc,
             SUCCESS(schemaRefExpected(schemf::Type::LONG))),
        MapT({makeValue(R"("div")"), makeRef("ref"), makeValue(R"(1)")},
             opBuilderHelperIntCalc,
             FAILURE(schemaRefExpected(schemf::Type::FLOAT))),
        MapT({makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(1)")},
             opBuilderHelperIntCalc,
             SUCCESS(customRefExpected())),
        MapT({makeValue(R"("sub")"), makeRef("ref"), makeRef("ref")},
             opBuilderHelperIntCalc,
             SUCCESS(customRefExpected(true))),
        MapT({makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(1)"), makeRef("ref")},
             opBuilderHelperIntCalc,
             SUCCESS(customRefExpected(true))),
        MapT({makeValue(R"("div")"), makeValue(R"(1.1)"), makeValue(R"(1)")}, opBuilderHelperIntCalc, FAILURE()),
        MapT({makeValue(R"("sum")"), makeValue(R"(true)"), makeValue(R"(1)")}, opBuilderHelperIntCalc, FAILURE()),
        MapT({makeValue(R"("mul")"), makeValue(R"([])"), makeValue(R"(1)")}, opBuilderHelperIntCalc, FAILURE()),
        MapT({makeValue(R"("div")"), makeValue(R"({})"), makeValue(R"(1)")}, opBuilderHelperIntCalc, FAILURE()),
        MapT({makeValue(R"("sum")"), makeValue(R"(null)"), makeValue(R"(1)")}, opBuilderHelperIntCalc, FAILURE())),
    testNameFormatter<MapBuilderTest>("IntCalc"));
} // namespace mapbuildtest

namespace mapoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    MapOperationTest,
    testing::Values(
        /*** sum ***/
        MapT("{}",
             opBuilderHelperIntCalc,
             {makeValue(R"("sum")"), makeValue(R"(1)"), makeValue(R"(2)")},
             SUCCESS(json::Json(R"(3)"))),
        MapT("{}",
             opBuilderHelperIntCalc,
             {makeValue(R"("sum")"), makeValue(R"(1)"), makeValue(R"(2)"), makeValue(R"(4)"), makeValue(R"(7)")},
             SUCCESS(json::Json(R"(14)"))),
        MapT("{}",
             opBuilderHelperIntCalc,
             {makeValue(R"("sum")"), makeValue(R"(1)"), makeValue(R"(2)"), makeValue(R"(4)"), makeRef("ref")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": 1})",
             opBuilderHelperIntCalc,
             {makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(2)")},
             SUCCESS(customRefExpected(json::Json(R"(3)")))),
        MapT(R"({"notRef": 1})",
             opBuilderHelperIntCalc,
             {makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": 1.1})",
             opBuilderHelperIntCalc,
             {makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": true})",
             opBuilderHelperIntCalc,
             {makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": []})",
             opBuilderHelperIntCalc,
             {makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": {}})",
             opBuilderHelperIntCalc,
             {makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": null})",
             opBuilderHelperIntCalc,
             {makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        /*** sub ***/
        MapT("{}",
             opBuilderHelperIntCalc,
             {makeValue(R"("sub")"), makeValue(R"(100)"), makeValue(R"(50)")},
             SUCCESS(json::Json(R"(50)"))),
        MapT("{}",
             opBuilderHelperIntCalc,
             {makeValue(R"("sub")"), makeValue(R"(100)"), makeValue(R"(2)"), makeValue(R"(10)"), makeValue(R"(5)")},
             SUCCESS(json::Json(R"(83)"))),
        MapT("{}",
             opBuilderHelperIntCalc,
             {makeValue(R"("sub")"), makeValue(R"(-100)"), makeValue(R"(2)"), makeValue(R"(10)"), makeValue(R"(5)")},
             SUCCESS(json::Json(R"(-117)"))),
        MapT("{}",
             opBuilderHelperIntCalc,
             {makeValue(R"("sub")"), makeValue(R"(-100)"), makeValue(R"(-2)"), makeValue(R"(-10)"), makeValue(R"(-5)")},
             SUCCESS(json::Json(R"(-83)"))),
        MapT("{}",
             opBuilderHelperIntCalc,
             {makeValue(R"("sub")"), makeValue(R"(1)"), makeValue(R"(2)")},
             SUCCESS(json::Json(R"(-1)"))),
        MapT(R"({"notRef": 1})",
             opBuilderHelperIntCalc,
             {makeValue(R"("sub")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": 1.1})",
             opBuilderHelperIntCalc,
             {makeValue(R"("sub")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": true})",
             opBuilderHelperIntCalc,
             {makeValue(R"("sub")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": []})",
             opBuilderHelperIntCalc,
             {makeValue(R"("sub")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": {}})",
             opBuilderHelperIntCalc,
             {makeValue(R"("sub")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": null})",
             opBuilderHelperIntCalc,
             {makeValue(R"("sub")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        /*** mul ***/
        MapT("{}",
             opBuilderHelperIntCalc,
             {makeValue(R"("mul")"), makeValue(R"(1)"), makeValue(R"(2)")},
             SUCCESS(json::Json(R"(2)"))),
        MapT("{}",
             opBuilderHelperIntCalc,
             {makeValue(R"("mul")"), makeValue(R"(1000)"), makeValue(R"(-20000)")},
             SUCCESS(json::Json(R"(-20000000)"))),
        MapT(R"({"ref": 1})",
             opBuilderHelperIntCalc,
             {makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(0)")},
             SUCCESS(customRefExpected(json::Json(R"(0)")))),
        MapT(R"({"ref": 1})",
             opBuilderHelperIntCalc,
             {makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(2)")},
             SUCCESS(customRefExpected(json::Json(R"(2)")))),
        MapT(R"({"notRef": 1})",
             opBuilderHelperIntCalc,
             {makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": 1.1})",
             opBuilderHelperIntCalc,
             {makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": true})",
             opBuilderHelperIntCalc,
             {makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": []})",
             opBuilderHelperIntCalc,
             {makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": {}})",
             opBuilderHelperIntCalc,
             {makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": null})",
             opBuilderHelperIntCalc,
             {makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        /*** div ***/
        MapT("{}",
             opBuilderHelperIntCalc,
             {makeValue(R"("div")"), makeValue(R"(1)"), makeValue(R"(1)")},
             SUCCESS(json::Json(R"(1)"))),
        MapT("{}",
             opBuilderHelperIntCalc,
             {makeValue(R"("div")"), makeValue(R"(1)"), makeValue(R"(2)")},
             SUCCESS(json::Json(R"(0)"))),
        MapT(R"({"ref": 1})",
             opBuilderHelperIntCalc,
             {makeValue(R"("div")"), makeRef("ref"), makeValue(R"(1)")},
             SUCCESS(customRefExpected(json::Json(R"(1)")))),
        MapT("{}",
             opBuilderHelperIntCalc,
             {makeValue(R"("div")"), makeValue(R"(2)"), makeValue(R"(1)")},
             SUCCESS(json::Json(R"(2)"))),
        MapT("{}",
             opBuilderHelperIntCalc,
             {makeValue(R"("div")"), makeValue(R"(-100)"), makeValue(R"(2)")},
             SUCCESS(json::Json(R"(-50)"))),
        MapT("{}",
             opBuilderHelperIntCalc,
             {makeValue(R"("div")"), makeValue(R"(-100)"), makeValue(R"(-2)")},
             SUCCESS(json::Json(R"(50)"))),
        MapT(R"({"ref": 0})",
             opBuilderHelperIntCalc,
             {makeValue(R"("div")"), makeValue(R"(1)"), makeRef("ref")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": 1})",
             opBuilderHelperIntCalc,
             {makeValue(R"("div")"), makeRef("ref"), makeValue(R"(2)")},
             SUCCESS(customRefExpected(json::Json(R"(0)")))),
        MapT(R"({"notRef": 1})",
             opBuilderHelperIntCalc,
             {makeValue(R"("div")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": 1.1})",
             opBuilderHelperIntCalc,
             {makeValue(R"("div")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": true})",
             opBuilderHelperIntCalc,
             {makeValue(R"("div")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": []})",
             opBuilderHelperIntCalc,
             {makeValue(R"("div")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": {}})",
             opBuilderHelperIntCalc,
             {makeValue(R"("div")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": null})",
             opBuilderHelperIntCalc,
             {makeValue(R"("div")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected()))),
    testNameFormatter<MapOperationTest>("IntCalc"));
} // namespace mapoperatestest
