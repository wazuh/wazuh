#include "builders/baseBuilders_test.hpp"

#include "builders/opmap/opBuilderHelperMap.hpp"

using namespace builder::builders;

namespace
{
constexpr auto PRIORITY_REF = "priority";

auto expectPriorityRefNotTyped()
{
    return [](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.validator, hasField(DotPath(PRIORITY_REF))).WillOnce(testing::Return(false));
        return None {};
    };
}

auto expectPriorityRefNumber()
{
    return [](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks.validator, hasField(DotPath(PRIORITY_REF))).WillOnce(testing::Return(true));
        EXPECT_CALL(*mocks.validator, getJsonType(DotPath(PRIORITY_REF)))
            .WillOnce(testing::Return(json::Json::Type::Number));
        return None {};
    };
}

auto expectPriorityRefWrongType(json::Json::Type jType)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator()).Times(testing::AtLeast(1));
        EXPECT_CALL(*mocks.validator, hasField(DotPath(PRIORITY_REF))).WillOnce(testing::Return(true));
        EXPECT_CALL(*mocks.validator, getJsonType(DotPath(PRIORITY_REF))).WillOnce(testing::Return(jType));
        return None {};
    };
}

auto expectRuntimeNotTyped()
{
    return [](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.validator, hasField(DotPath(PRIORITY_REF))).WillOnce(testing::Return(false));
        return None {};
    };
}

auto expectRuntimeNotTyped(json::Json expected)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.validator, hasField(DotPath(PRIORITY_REF))).WillOnce(testing::Return(false));
        return expected;
    };
}
} // namespace

namespace mapbuildtest
{
INSTANTIATE_TEST_SUITE_P(
    SyslogFacility,
    MapBuilderTest,
    testing::Values(
        MapT({}, opBuilderHelperSyslogExtractFacility, FAILURE()),
        MapT({makeRef(PRIORITY_REF), makeRef("other")}, opBuilderHelperSyslogExtractFacility, FAILURE()),
        MapT({makeValue("1")}, opBuilderHelperSyslogExtractFacility, FAILURE()),
        MapT({makeRef(PRIORITY_REF)}, opBuilderHelperSyslogExtractFacility, SUCCESS(expectPriorityRefNotTyped())),
        MapT({makeRef(PRIORITY_REF)}, opBuilderHelperSyslogExtractFacility, SUCCESS(expectPriorityRefNumber())),
        MapT({makeRef(PRIORITY_REF)},
             opBuilderHelperSyslogExtractFacility,
             FAILURE(expectPriorityRefWrongType(json::Json::Type::String))),
        MapT({makeRef(PRIORITY_REF)},
             opBuilderHelperSyslogExtractFacility,
             FAILURE(expectPriorityRefWrongType(json::Json::Type::Boolean)))),
    testNameFormatter<MapBuilderTest>("SyslogFacility"));

INSTANTIATE_TEST_SUITE_P(
    SyslogSeverity,
    MapBuilderTest,
    testing::Values(
        MapT({}, opBuilderHelperSyslogExtractSeverity, FAILURE()),
        MapT({makeRef(PRIORITY_REF), makeRef("other")}, opBuilderHelperSyslogExtractSeverity, FAILURE()),
        MapT({makeValue("1")}, opBuilderHelperSyslogExtractSeverity, FAILURE()),
        MapT({makeRef(PRIORITY_REF)}, opBuilderHelperSyslogExtractSeverity, SUCCESS(expectPriorityRefNotTyped())),
        MapT({makeRef(PRIORITY_REF)}, opBuilderHelperSyslogExtractSeverity, SUCCESS(expectPriorityRefNumber())),
        MapT({makeRef(PRIORITY_REF)},
             opBuilderHelperSyslogExtractSeverity,
             FAILURE(expectPriorityRefWrongType(json::Json::Type::String))),
        MapT({makeRef(PRIORITY_REF)},
             opBuilderHelperSyslogExtractSeverity,
             FAILURE(expectPriorityRefWrongType(json::Json::Type::Boolean)))),
    testNameFormatter<MapBuilderTest>("SyslogSeverity"));
} // namespace mapbuildtest

namespace mapoperatestest
{
INSTANTIATE_TEST_SUITE_P(
    SyslogFacility,
    MapOperationTest,
    testing::Values(
        MapT(R"({"priority": 0})",
             opBuilderHelperSyslogExtractFacility,
             {makeRef(PRIORITY_REF)},
             SUCCESS(expectRuntimeNotTyped(json::Json(R"({"code":0,"name":"kernel"})")))),
        MapT(R"({"priority": 160})",
             opBuilderHelperSyslogExtractFacility,
             {makeRef(PRIORITY_REF)},
             SUCCESS(expectRuntimeNotTyped(json::Json(R"({"code":20,"name":"local4"})")))),
        MapT(R"({"priority": 191})",
             opBuilderHelperSyslogExtractFacility,
             {makeRef(PRIORITY_REF)},
             SUCCESS(expectRuntimeNotTyped(json::Json(R"({"code":23,"name":"local7"})")))),
        MapT(R"({"missing": 100})",
             opBuilderHelperSyslogExtractFacility,
             {makeRef(PRIORITY_REF)},
             FAILURE(expectRuntimeNotTyped())),
        MapT(R"({"priority": 192})",
             opBuilderHelperSyslogExtractFacility,
             {makeRef(PRIORITY_REF)},
             FAILURE(expectRuntimeNotTyped())),
        MapT(R"({"priority": -1})",
             opBuilderHelperSyslogExtractFacility,
             {makeRef(PRIORITY_REF)},
             FAILURE(expectRuntimeNotTyped())),
        MapT(R"({"priority": 34.0})",
             opBuilderHelperSyslogExtractFacility,
             {makeRef(PRIORITY_REF)},
             FAILURE(expectRuntimeNotTyped())),
        MapT(R"({"priority": null})",
             opBuilderHelperSyslogExtractFacility,
             {makeRef(PRIORITY_REF)},
             FAILURE(expectRuntimeNotTyped())),
        MapT(R"({"priority": "oops"})",
             opBuilderHelperSyslogExtractFacility,
             {makeRef(PRIORITY_REF)},
             FAILURE(expectRuntimeNotTyped()))),
    testNameFormatter<MapOperationTest>("SyslogFacility"));

INSTANTIATE_TEST_SUITE_P(
    SyslogSeverity,
    MapOperationTest,
    testing::Values(
        MapT(R"({"priority": 0})",
             opBuilderHelperSyslogExtractSeverity,
             {makeRef(PRIORITY_REF)},
             SUCCESS(expectRuntimeNotTyped(json::Json(R"({"code":0,"name":"emergency"})")))),
        MapT(R"({"priority": 160})",
             opBuilderHelperSyslogExtractSeverity,
             {makeRef(PRIORITY_REF)},
             SUCCESS(expectRuntimeNotTyped(json::Json(R"({"code":0,"name":"emergency"})")))),
        MapT(R"({"priority": 165})",
             opBuilderHelperSyslogExtractSeverity,
             {makeRef(PRIORITY_REF)},
             SUCCESS(expectRuntimeNotTyped(json::Json(R"({"code":5,"name":"notice"})")))),
        MapT(R"({"priority": 191})",
             opBuilderHelperSyslogExtractSeverity,
             {makeRef(PRIORITY_REF)},
             SUCCESS(expectRuntimeNotTyped(json::Json(R"({"code":7,"name":"debug"})")))),
        MapT(R"({"missing": 165})",
             opBuilderHelperSyslogExtractSeverity,
             {makeRef(PRIORITY_REF)},
             FAILURE(expectRuntimeNotTyped())),
        MapT(R"({"priority": "oops"})",
             opBuilderHelperSyslogExtractSeverity,
             {makeRef(PRIORITY_REF)},
             FAILURE(expectRuntimeNotTyped())),
        MapT(R"({"priority": 192})",
             opBuilderHelperSyslogExtractSeverity,
             {makeRef(PRIORITY_REF)},
             FAILURE(expectRuntimeNotTyped())),
        MapT(R"({"priority": 34.0})",
             opBuilderHelperSyslogExtractSeverity,
             {makeRef(PRIORITY_REF)},
             FAILURE(expectRuntimeNotTyped())),
        MapT(R"({"priority": -1})",
             opBuilderHelperSyslogExtractSeverity,
             {makeRef(PRIORITY_REF)},
             FAILURE(expectRuntimeNotTyped()))),
    testNameFormatter<MapOperationTest>("SyslogSeverity"));
} // namespace mapoperatestest
