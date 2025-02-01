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
        MapT({}, getOpBuilderHelperCalc(true), FAILURE()),
        MapT({makeValue(R"("sum")")}, getOpBuilderHelperCalc(true), FAILURE()),
        MapT({makeValue(R"("sum")"), makeValue(R"(1)")}, getOpBuilderHelperCalc(true), FAILURE()),
        MapT({makeValue(R"("sum")"), makeValue(R"(1)"), makeValue(R"(2)")}, getOpBuilderHelperCalc(true), SUCCESS()),
        MapT({makeValue(R"("sums")"), makeValue(R"(1)")}, getOpBuilderHelperCalc(true), FAILURE()),
        MapT({makeValue(R"(1)"), makeValue(R"(1)")}, getOpBuilderHelperCalc(true), FAILURE()),
        MapT({makeValue(R"("sub")"), makeValue(R"(1)")}, getOpBuilderHelperCalc(true), FAILURE()),
        MapT({makeValue(R"("mul")"), makeValue(R"(1)")}, getOpBuilderHelperCalc(true), FAILURE()),
        MapT({makeValue(R"("div")"), makeValue(R"(1)")}, getOpBuilderHelperCalc(true), FAILURE()),
        MapT({makeValue(R"("div")"), makeValue(R"(0)")}, getOpBuilderHelperCalc(true), FAILURE()),
        MapT({makeValue(R"("sub")"), makeValue(R"(1)"), makeValue(R"(1)")}, getOpBuilderHelperCalc(true), SUCCESS()),
        MapT({makeValue(R"("mul")"), makeValue(R"(1)"), makeValue(R"(1)")}, getOpBuilderHelperCalc(true), SUCCESS()),
        MapT({makeValue(R"("div")"), makeValue(R"(1)"), makeValue(R"(1)")}, getOpBuilderHelperCalc(true), SUCCESS()),
        MapT({makeValue(R"("div")"), makeValue(R"(0)"), makeValue(R"(1)")}, getOpBuilderHelperCalc(true), SUCCESS()),
        MapT({makeValue(R"("div")"), makeValue(R"(1)"), makeValue(R"(0)")}, getOpBuilderHelperCalc(true), FAILURE()),
        MapT({makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(1)")},
             getOpBuilderHelperCalc(true),
             SUCCESS(customRefExpected())),
        MapT({makeValue(R"("sub")"), makeRef("ref"), makeValue(R"(1)")},
             getOpBuilderHelperCalc(true),
             SUCCESS(customRefExpected())),
        MapT({makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(1)")},
             getOpBuilderHelperCalc(true),
             SUCCESS(customRefExpected())),
        MapT({makeValue(R"("div")"), makeRef("ref"), makeValue(R"(1)")},
             getOpBuilderHelperCalc(true),
             SUCCESS(customRefExpected())),
        MapT({makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(1)")},
             getOpBuilderHelperCalc(true),
             SUCCESS(schemaRefExpected(schemf::Type::INTEGER))),
        MapT({makeValue(R"("sub")"), makeRef("ref"), makeValue(R"(1)")},
             getOpBuilderHelperCalc(true),
             SUCCESS(schemaRefExpected(schemf::Type::SHORT))),
        MapT({makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(1)")},
             getOpBuilderHelperCalc(true),
             SUCCESS(schemaRefExpected(schemf::Type::LONG))),
        MapT({makeValue(R"("div")"), makeRef("ref"), makeValue(R"(1)")},
             getOpBuilderHelperCalc(true),
             FAILURE(schemaRefExpected(schemf::Type::FLOAT))),
        MapT({makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(1)")},
             getOpBuilderHelperCalc(true),
             SUCCESS(customRefExpected())),
        MapT({makeValue(R"("sub")"), makeRef("ref"), makeRef("ref")},
             getOpBuilderHelperCalc(true),
             SUCCESS(customRefExpected(true))),
        MapT({makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(1)"), makeRef("ref")},
             getOpBuilderHelperCalc(true),
             SUCCESS(customRefExpected(true))),
        MapT({makeValue(R"("div")"), makeValue(R"(1.1)"), makeValue(R"(1)")}, getOpBuilderHelperCalc(true), FAILURE()),
        MapT({makeValue(R"("sum")"), makeValue(R"(true)"), makeValue(R"(1)")}, getOpBuilderHelperCalc(true), FAILURE()),
        MapT({makeValue(R"("mul")"), makeValue(R"([])"), makeValue(R"(1)")}, getOpBuilderHelperCalc(true), FAILURE()),
        MapT({makeValue(R"("div")"), makeValue(R"({})"), makeValue(R"(1)")}, getOpBuilderHelperCalc(true), FAILURE()),
        MapT({makeValue(R"("sum")"), makeValue(R"(null)"), makeValue(R"(1)")},
             getOpBuilderHelperCalc(true),
             FAILURE())),
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
             getOpBuilderHelperCalc(false),
             {makeValue(R"("sum")"), makeValue(R"(1)"), makeValue(R"(2)")},
             SUCCESS(json::Json(R"(3)"))),
        MapT("{}",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("sum")"), makeValue(R"(1)"), makeValue(R"(2)"), makeValue(R"(4)"), makeValue(R"(7)")},
             SUCCESS(json::Json(R"(14)"))),
        MapT("{}",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("sum")"), makeValue(R"(1)"), makeValue(R"(2)"), makeValue(R"(4)"), makeRef("ref")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": 1})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(2)")},
             SUCCESS(customRefExpected(json::Json(R"(3)")))),
        MapT(R"({"notRef": 1})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": 1.1})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": true})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": []})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": {}})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": null})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("sum")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        /*** sub ***/
        MapT("{}",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("sub")"), makeValue(R"(100)"), makeValue(R"(50)")},
             SUCCESS(json::Json(R"(50)"))),
        MapT("{}",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("sub")"), makeValue(R"(100)"), makeValue(R"(2)"), makeValue(R"(10)"), makeValue(R"(5)")},
             SUCCESS(json::Json(R"(83)"))),
        MapT("{}",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("sub")"), makeValue(R"(-100)"), makeValue(R"(2)"), makeValue(R"(10)"), makeValue(R"(5)")},
             SUCCESS(json::Json(R"(-117)"))),
        MapT("{}",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("sub")"), makeValue(R"(-100)"), makeValue(R"(-2)"), makeValue(R"(-10)"), makeValue(R"(-5)")},
             SUCCESS(json::Json(R"(-83)"))),
        MapT("{}",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("sub")"), makeValue(R"(1)"), makeValue(R"(2)")},
             SUCCESS(json::Json(R"(-1)"))),
        MapT(R"({"notRef": 1})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("sub")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": 1.1})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("sub")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": true})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("sub")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": []})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("sub")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": {}})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("sub")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": null})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("sub")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        /*** mul ***/
        MapT("{}",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("mul")"), makeValue(R"(1)"), makeValue(R"(2)")},
             SUCCESS(json::Json(R"(2)"))),
        MapT("{}",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("mul")"), makeValue(R"(1000)"), makeValue(R"(-20000)")},
             SUCCESS(json::Json(R"(-20000000)"))),
        MapT(R"({"ref": 1})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(0)")},
             SUCCESS(customRefExpected(json::Json(R"(0)")))),
        MapT(R"({"ref": 1})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(2)")},
             SUCCESS(customRefExpected(json::Json(R"(2)")))),
        MapT(R"({"notRef": 1})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": 1.1})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": true})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": []})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": {}})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": null})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("mul")"), makeRef("ref"), makeValue(R"(2)")},
             FAILURE(customRefExpected())),
        /*** div ***/
        MapT("{}",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("div")"), makeValue(R"(1)"), makeValue(R"(1)")},
             SUCCESS(json::Json(R"(1)"))),
        MapT("{}",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("div")"), makeValue(R"(1)"), makeValue(R"(2)")},
             SUCCESS(json::Json(R"(0)"))),
        MapT(R"({"ref": 1})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("div")"), makeRef("ref"), makeValue(R"(1)")},
             SUCCESS(customRefExpected(json::Json(R"(1)")))),
        MapT("{}",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("div")"), makeValue(R"(2)"), makeValue(R"(1)")},
             SUCCESS(json::Json(R"(2)"))),
        MapT("{}",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("div")"), makeValue(R"(-100)"), makeValue(R"(2)")},
             SUCCESS(json::Json(R"(-50)"))),
        MapT("{}",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("div")"), makeValue(R"(-100)"), makeValue(R"(-2)")},
             SUCCESS(json::Json(R"(50)"))),
        MapT(R"({"ref": 0})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("div")"), makeValue(R"(1)"), makeRef("ref")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": 1})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("div")"), makeRef("ref"), makeValue(R"(2)")},
             SUCCESS(customRefExpected(json::Json(R"(0)")))),
        MapT(R"({"notRef": 1})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("div")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": 1.1})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("div")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": true})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("div")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": []})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("div")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": {}})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("div")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected())),
        MapT(R"({"ref": null})",
             getOpBuilderHelperCalc(true),
             {makeValue(R"("div")"), makeRef("ref"), makeValue(R"(1)")},
             FAILURE(customRefExpected()))),
    testNameFormatter<MapOperationTest>("IntCalc"));
} // namespace mapoperatestest
