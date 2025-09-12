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
        MapT({}, getOpBuilderHelperCalc(false), FAILURE()),
        MapT({makeValue(R"("sum")")}, getOpBuilderHelperCalc(false), FAILURE()),
        MapT({makeValue(R"("sum")"), makeValue(R"(1)")}, getOpBuilderHelperCalc(false), FAILURE()),
        MapT({makeValue(R"("sum")"), makeValue(R"(1)"), makeValue(R"(2)")}, getOpBuilderHelperCalc(false), SUCCESS()),
        MapT({makeValue(R"("sums")"), makeValue(R"(1)")}, getOpBuilderHelperCalc(false), FAILURE()),
        MapT({makeValue(R"(1)"), makeValue(R"(1)")}, getOpBuilderHelperCalc(false), FAILURE()),
        MapT({makeValue(R"("sub")"), makeValue(R"(1)")}, getOpBuilderHelperCalc(false), FAILURE()),
        MapT({makeValue(R"("mul")"), makeValue(R"(1)")}, getOpBuilderHelperCalc(false), FAILURE()),
        MapT({makeValue(R"("div")"), makeValue(R"(1)")}, getOpBuilderHelperCalc(false), FAILURE()),
        MapT({makeValue(R"("div")"), makeValue(R"(0)")}, getOpBuilderHelperCalc(false), FAILURE()),
        MapT({makeValue(R"("sub")"), makeValue(R"(1)"), makeValue(R"(1)")}, getOpBuilderHelperCalc(false), SUCCESS()),
        MapT({makeValue(R"("mul")"), makeValue(R"(1)"), makeValue(R"(1)")}, getOpBuilderHelperCalc(false), SUCCESS()),
        MapT({makeValue(R"("div")"), makeValue(R"(1)"), makeValue(R"(1)")}, getOpBuilderHelperCalc(false), SUCCESS()),
        MapT({makeValue(R"("div")"), makeValue(R"(0)"), makeValue(R"(1)")}, getOpBuilderHelperCalc(false), SUCCESS()),
        MapT({makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(1)")},
             getOpBuilderHelperCalc(false),
             SUCCESS(customRefExpected())),
        MapT({makeValue(R"("sub")"), makeRef("ref"), makeValue(R"(1)")},
             getOpBuilderHelperCalc(false),
             SUCCESS(customRefExpected())),
        MapT({makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(1)")},
             getOpBuilderHelperCalc(false),
             SUCCESS(customRefExpected())),
        MapT({makeValue(R"("div")"), makeRef("ref"), makeValue(R"(1)")},
             getOpBuilderHelperCalc(false),
             SUCCESS(customRefExpected())),
        MapT({makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(1)")},
             getOpBuilderHelperCalc(false),
             SUCCESS(schemaRefExpected(schemf::Type::INTEGER))),
        MapT({makeValue(R"("sub")"), makeRef("ref"), makeValue(R"(1)")},
             getOpBuilderHelperCalc(false),
             SUCCESS(schemaRefExpected(schemf::Type::SHORT))),
        MapT({makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(1)")},
             getOpBuilderHelperCalc(false),
             SUCCESS(schemaRefExpected(schemf::Type::LONG))),
        MapT({makeValue(R"("div")"), makeRef("ref"), makeValue(R"(1)")},
             getOpBuilderHelperCalc(false),
             SUCCESS(schemaRefExpected(schemf::Type::FLOAT))),
        MapT({makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(1)")},
             getOpBuilderHelperCalc(false),
             SUCCESS(customRefExpected())),
        MapT({makeValue(R"("sub")"), makeRef("ref"), makeRef("ref")},
             getOpBuilderHelperCalc(false),
             SUCCESS(customRefExpected(true))),
        MapT({makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(1)"), makeRef("ref")},
             getOpBuilderHelperCalc(false),
             SUCCESS(customRefExpected(true))),
        MapT({makeValue(R"("div")"), makeValue(R"(1.1)"), makeValue(R"(1)")}, getOpBuilderHelperCalc(false), SUCCESS()),
        MapT({makeValue(R"("sum")"), makeValue(R"(true)"), makeValue(R"(1)")},
             getOpBuilderHelperCalc(false),
             FAILURE()),
        MapT({makeValue(R"("mul")"), makeValue(R"([])"), makeValue(R"(1)")}, getOpBuilderHelperCalc(false), FAILURE()),
        MapT({makeValue(R"("div")"), makeValue(R"({})"), makeValue(R"(1)")}, getOpBuilderHelperCalc(false), FAILURE()),
        MapT({makeValue(R"("sum")"), makeValue(R"(null)"), makeValue(R"(1)")},
             getOpBuilderHelperCalc(false),
             FAILURE())),
    testNameFormatter<MapBuilderTest>("FloatCalc"));
} // namespace mapbuildtest

namespace mapoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    MapOperationTest,
    testing::Values(
        /*** sum ***/
        MapT("{}",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("sum")"), makeValue(R"(1)"), makeValue(R"(2)")},
             SUCCESS(json::Json(R"(3.0)"))),
        MapT("{}",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("sum")"), makeValue(R"(1)"), makeValue(R"(2)"), makeValue(R"(4)"), makeValue(R"(7)")},
             SUCCESS(json::Json(R"(14.0)"))),
        MapT("{}",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("sum")"), makeValue(R"(1)"), makeValue(R"(2)"), makeValue(R"(4)"), makeRef("ref")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": 1})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(2)")},
             SUCCESS(customRefExpected(json::Json(R"(3.0)")))),
        MapT(R"({"notRef": 1})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": 1.1})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(1)")},
             SUCCESS(customRefExpected(json::Json(R"(2.1)")))),
        MapT(R"({"ref": true})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": []})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": {}})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": null})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        /*** sub ***/
        MapT("{}",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("sub")"), makeValue(R"(100)"), makeValue(R"(50)")},
             SUCCESS(json::Json(R"(50.0)"))),
        MapT("{}",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("sub")"), makeValue(R"(100)"), makeValue(R"(2)"), makeValue(R"(10)"), makeValue(R"(5)")},
             SUCCESS(json::Json(R"(83.0)"))),
        MapT("{}",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("sub")"), makeValue(R"(-100)"), makeValue(R"(2)"), makeValue(R"(10)"), makeValue(R"(5)")},
             SUCCESS(json::Json(R"(-117.0)"))),
        MapT("{}",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("sub")"), makeValue(R"(-100)"), makeValue(R"(-2)"), makeValue(R"(-10)"), makeValue(R"(-5)")},
             SUCCESS(json::Json(R"(-83.0)"))),
        MapT("{}",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("sub")"), makeValue(R"(1)"), makeValue(R"(2)")},
             SUCCESS(json::Json(R"(-1)"))),
        MapT(R"({"notRef": 1})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("sub")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": 1.1})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("sub")"), makeRef("ref"), makeValue(R"(2)")},
             SUCCESS(json::Json(R"(-0.8999999999999999)"))),
        MapT(R"({"ref": true})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("sub")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": []})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("sub")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": {}})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("sub")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": null})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("sub")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        /*** mul ***/
        MapT("{}",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("mul")"), makeValue(R"(1)"), makeValue(R"(2)")},
             SUCCESS(json::Json(R"(2)"))),
        MapT("{}",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("mul")"), makeValue(R"(1000)"), makeValue(R"(-20000)")},
             SUCCESS(json::Json(R"(-20000000)"))),
        MapT(R"({"ref": 1})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(0)")},
             SUCCESS(customRefExpected(json::Json(R"(0)")))),
        MapT(R"({"ref": 1})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(2)")},
             SUCCESS(customRefExpected(json::Json(R"(2)")))),
        MapT(R"({"notRef": 1})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": 1.1})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(2)")},
             SUCCESS(customRefExpected(json::Json(R"(2.2)")))),
        MapT(R"({"ref": true})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": []})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": {}})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": null})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        /*** div ***/
        MapT("{}",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("div")"), makeValue(R"(1)"), makeValue(R"(1)")},
             SUCCESS(json::Json(R"(1)"))),
        MapT("{}",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("div")"), makeValue(R"(1)"), makeValue(R"(2)")},
             SUCCESS(json::Json(R"(0.5)"))),
        MapT(R"({"ref": 1})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("div")"), makeRef("ref"), makeValue(R"(1)")},
             SUCCESS(customRefExpected(json::Json(R"(1)")))),
        MapT("{}",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("div")"), makeValue(R"(2)"), makeValue(R"(1)")},
             SUCCESS(json::Json(R"(2)"))),
        MapT("{}",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("div")"), makeValue(R"(-100)"), makeValue(R"(2)")},
             SUCCESS(json::Json(R"(-50)"))),
        MapT("{}",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("div")"), makeValue(R"(-100)"), makeValue(R"(-2)")},
             SUCCESS(json::Json(R"(50)"))),
        MapT(R"({"ref": 0})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("div")"), makeValue(R"(1)"), makeRef("ref")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": 1})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("div")"), makeRef("ref"), makeValue(R"(2)")},
             SUCCESS(customRefExpected(json::Json(R"(0.5)")))),
        MapT(R"({"notRef": 1})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("div")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": 1.1})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("div")"), makeRef("ref"), makeValue(R"(1)")},
             SUCCESS(customRefExpected(json::Json(R"(1.1)")))),
        MapT(R"({"ref": true})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("div")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": []})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("div")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": {}})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("div")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": null})",
             getOpBuilderHelperCalc(false),
             {makeValue(R"("div")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected()))),
    testNameFormatter<MapOperationTest>("FloatCalc"));
} // namespace mapoperatestest
