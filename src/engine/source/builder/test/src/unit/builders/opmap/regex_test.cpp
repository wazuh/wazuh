#include "builders/baseBuilders_test.hpp"

#include "builders/opmap/opBuilderHelperMap.hpp"

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

auto customRefExpected(json::Json result)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.validator, hasField(DotPath("ref"))).WillRepeatedly(testing::Return(false));
        return result;
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
        MapT({}, opBuilderHelperRegexExtract, FAILURE()),
        MapT({makeRef("ref")}, opBuilderHelperRegexExtract, FAILURE()),
        MapT({makeRef("ref"), makeValue(R"("value")")}, opBuilderHelperRegexExtract, SUCCESS(customRefExpected())),
        MapT({makeRef("ref"), makeRef("ref")}, opBuilderHelperRegexExtract, FAILURE()),
        MapT({makeValue(R"("value")"), makeValue(R"("value")")}, opBuilderHelperRegexExtract, FAILURE()),
        MapT({makeRef("ref"), makeValue(R"("value")"), makeValue(R"("value")")},
             opBuilderHelperRegexExtract,
             FAILURE()),
        MapT({makeRef("ref"), makeValue(R"("value")")},
             opBuilderHelperRegexExtract,
             SUCCESS(jTypeRefExpected(json::Json::Type::String))),
        MapT({makeRef("ref"), makeValue(R"("value")")},
             opBuilderHelperRegexExtract,
             FAILURE(jTypeRefExpected(json::Json::Type::Number))),
        MapT({makeRef("ref"), makeValue(R"("value")")},
             opBuilderHelperRegexExtract,
             FAILURE(jTypeRefExpected(json::Json::Type::Boolean))),
        MapT({makeRef("ref"), makeValue(R"("value")")},
             opBuilderHelperRegexExtract,
             FAILURE(jTypeRefExpected(json::Json::Type::Object))),
        MapT({makeRef("ref"), makeValue(R"("value")")},
             opBuilderHelperRegexExtract,
             FAILURE(jTypeRefExpected(json::Json::Type::Array))),
        MapT({makeRef("ref"), makeValue(R"("value")")},
             opBuilderHelperRegexExtract,
             FAILURE(jTypeRefExpected(json::Json::Type::Null)))),
    testNameFormatter<MapBuilderTest>("Regex"));
} // namespace mapbuildtest

namespace mapoperatestest
{
INSTANTIATE_TEST_SUITE_P(Builders,
                         MapOperationTest,
                         testing::Values(MapT(R"({ "ref": "value" })",
                                              opBuilderHelperRegexExtract,
                                              {makeRef("ref"), makeValue(R"z("(.*)")z")},
                                              SUCCESS(customRefExpected(json::Json(R"("value")")))),
                                         MapT(R"({ "ref": "value" })",
                                              opBuilderHelperRegexExtract,
                                              {makeRef("ref"), makeValue(R"z(".*")z")},
                                              FAILURE(customRefExpected())),
                                         MapT(R"({ "ref": "value" })",
                                              opBuilderHelperRegexExtract,
                                              {makeRef("ref"), makeValue(R"z("^(va).*")z")},
                                              SUCCESS(customRefExpected(json::Json(R"("va")")))),
                                         MapT(R"({ "ref": "value" })",
                                              opBuilderHelperRegexExtract,
                                              {makeRef("ref"), makeValue(R"z("^(va)l(ue)$")z")},
                                              SUCCESS(customRefExpected(json::Json(R"("va")")))),
                                         MapT(R"({ "ref": "value" })",
                                              opBuilderHelperRegexExtract,
                                              {makeRef("ref"), makeValue(R"z("fail")z")},
                                              FAILURE(customRefExpected())),
                                         MapT(R"({ "notRef": "value" })",
                                              opBuilderHelperRegexExtract,
                                              {makeRef("ref"), makeValue(R"z("(.*)")z")},
                                              FAILURE(customRefExpected())),
                                         MapT(R"({ "ref": 1})",
                                              opBuilderHelperRegexExtract,
                                              {makeRef("ref"), makeValue(R"z("(.*)")z")},
                                              FAILURE(customRefExpected())),
                                         MapT(R"({ "ref": true})",
                                              opBuilderHelperRegexExtract,
                                              {makeRef("ref"), makeValue(R"z("(.*)")z")},
                                              FAILURE(customRefExpected())),
                                         MapT(R"({ "ref": null})",
                                              opBuilderHelperRegexExtract,
                                              {makeRef("ref"), makeValue(R"z("(.*)")z")},
                                              FAILURE(customRefExpected())),
                                         MapT(R"({ "ref": { "key": "value" }})",
                                              opBuilderHelperRegexExtract,
                                              {makeRef("ref"), makeValue(R"z("(.*)")z")},
                                              FAILURE(customRefExpected())),
                                         MapT(R"({ "ref": [ "value" ]})",
                                              opBuilderHelperRegexExtract,
                                              {makeRef("ref"), makeValue(R"z("(.*)")z")},
                                              FAILURE(customRefExpected()))),
                         testNameFormatter<MapOperationTest>("Regex"));
} // namespace mapoperatestest
