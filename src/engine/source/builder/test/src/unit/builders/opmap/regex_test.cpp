// SPDX-License-Identifier: AGPL-3.0-or-later
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
             FAILURE(jTypeRefExpected(json::Json::Type::Null))),
        /*** regex_extract_all ***/
        MapT({}, opBuilderHelperRegexExtractAll, FAILURE()),
        MapT({makeRef("ref")}, opBuilderHelperRegexExtractAll, FAILURE()),
        MapT({makeRef("ref"), makeValue(R"z("(value)")z")},
             opBuilderHelperRegexExtractAll,
             SUCCESS(customRefExpected())),
        MapT({makeRef("ref"), makeValue(R"z("a(?:b)(c)?(d)")z")},
             opBuilderHelperRegexExtractAll,
             SUCCESS(customRefExpected())),
        // A regex without a capturing group, an invalid regex or a non-string regex do not build
        MapT({makeRef("ref"), makeValue(R"z("value")z")}, opBuilderHelperRegexExtractAll, FAILURE()),
        MapT({makeRef("ref"), makeValue(R"z("(?:value)")z")}, opBuilderHelperRegexExtractAll, FAILURE()),
        MapT({makeRef("ref"), makeValue(R"z("(value")z")}, opBuilderHelperRegexExtractAll, FAILURE()),
        MapT({makeRef("ref"), makeValue(R"z(1)z")}, opBuilderHelperRegexExtractAll, FAILURE()),
        MapT({makeRef("ref"), makeRef("ref")}, opBuilderHelperRegexExtractAll, FAILURE()),
        MapT({makeValue(R"("value")"), makeValue(R"z("(value)")z")}, opBuilderHelperRegexExtractAll, FAILURE()),
        MapT({makeRef("ref"), makeValue(R"z("(value)")z"), makeValue(R"z("(value)")z")},
             opBuilderHelperRegexExtractAll,
             FAILURE()),
        MapT({makeRef("ref"), makeValue(R"z("(value)")z")},
             opBuilderHelperRegexExtractAll,
             SUCCESS(jTypeRefExpected(json::Json::Type::String))),
        MapT({makeRef("ref"), makeValue(R"z("(value)")z")},
             opBuilderHelperRegexExtractAll,
             FAILURE(jTypeRefExpected(json::Json::Type::Number))),
        MapT({makeRef("ref"), makeValue(R"z("(value)")z")},
             opBuilderHelperRegexExtractAll,
             FAILURE(jTypeRefExpected(json::Json::Type::Array)))),
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
INSTANTIATE_TEST_SUITE_P(
    BuildersRegexExtractAll,
    MapOperationTest,
    testing::Values(
        /*** regex_extract_all ***/
        // auditd EXECVE arguments: the raw values, quotes included, in order
        MapT(
            R"j({ "ref": "type=EXECVE msg=audit(1730000000.123:42): argc=4 a0=\"/usr/bin/sudo\" a1=\"grep\" a2=6B65793D226172742D7465737422 a3=\"/var/log/audit/audit.log\"" })j",
            opBuilderHelperRegexExtractAll,
            {makeRef("ref"), makeValue(R"z("(?:^|\\s)a\\d+=(\\S+)")z")},
            SUCCESS(customRefExpected(json::Json(
                R"j(["\"/usr/bin/sudo\"", "\"grep\"", "6B65793D226172742D7465737422", "\"/var/log/audit/audit.log\""])j")))),
        // A single match yields a one-element array
        MapT(R"({ "ref": "argc=1 a0=\"ls\"" })",
             opBuilderHelperRegexExtractAll,
             {makeRef("ref"), makeValue(R"z("(?:^|\\s)a\\d+=(\\S+)")z")},
             SUCCESS(customRefExpected(json::Json(R"(["\"ls\""])")))),
        // Only the first group is kept; an optional group that does not take
        // part in a match yields an empty string
        MapT(R"({ "ref": "k1=v1;k2=;k3=v3" })",
             opBuilderHelperRegexExtractAll,
             {makeRef("ref"), makeValue(R"z("k\\d=(\\w+)?(;|$)")z")},
             SUCCESS(customRefExpected(json::Json(R"(["v1", "", "v3"])")))),
        // Empty matches advance one character (UTF-8 aware), never loop
        MapT(R"({ "ref": "aé" })",
             opBuilderHelperRegexExtractAll,
             {makeRef("ref"), makeValue(R"z("(x*)")z")},
             SUCCESS(customRefExpected(json::Json(R"(["", "", ""])")))),
        MapT(R"({ "ref": "" })",
             opBuilderHelperRegexExtractAll,
             {makeRef("ref"), makeValue(R"z("(x*)")z")},
             SUCCESS(customRefExpected(json::Json(R"([""])")))),
        MapT(R"({ "ref": "value" })",
             opBuilderHelperRegexExtractAll,
             {makeRef("ref"), makeValue(R"z("(fail)")z")},
             FAILURE(customRefExpected())),
        MapT(R"({ "notRef": "value" })",
             opBuilderHelperRegexExtractAll,
             {makeRef("ref"), makeValue(R"z("(.*)")z")},
             FAILURE(customRefExpected())),
        MapT(R"({ "ref": 1})",
             opBuilderHelperRegexExtractAll,
             {makeRef("ref"), makeValue(R"z("(.*)")z")},
             FAILURE(customRefExpected())),
        MapT(R"({ "ref": [ "value" ]})",
             opBuilderHelperRegexExtractAll,
             {makeRef("ref"), makeValue(R"z("(.*)")z")},
             FAILURE(customRefExpected()))),
    testNameFormatter<MapOperationTest>("RegexExtractAll"));
} // namespace mapoperatestest

namespace regexextractalltest
{
class RegexExtractAllTest : public BaseBuilderTest
{
};

TEST_F(RegexExtractAllTest, Traces)
{
    mocks->context.opName = "regex_extract_all";
    ON_CALL(*mocks->ctx, isTestMode()).WillByDefault(testing::Return(true));
    ON_CALL(*mocks->validator, hasField(testing::_)).WillByDefault(testing::Return(false));
    auto op = opBuilderHelperRegexExtractAll({makeRef("ref"), makeValue(R"z("a(\\d)")z")}, mocks->ctx);

    const std::vector<std::tuple<std::string, bool, std::string>> cases {
        {R"({"ref": "a1 a2"})", true, "[regex_extract_all] -> Success"},
        {R"({"other": "a1"})", false, "[regex_extract_all] -> Failure: Parameter 'ref' reference not found"},
        {R"({"ref": ["a1"]})", false, "[regex_extract_all] -> Failure: Parameter 'ref' type is not string"},
        {R"({"ref": "b1"})", false, "[regex_extract_all] -> Failure: Regex did not match"},
    };
    for (const auto& [input, success, trace] : cases)
    {
        SCOPED_TRACE(input);
        auto result = op(std::make_shared<json::Json>(input.c_str()));
        EXPECT_EQ(result.success(), success);
        EXPECT_EQ(result.trace(), trace);
    }
}
} // namespace regexextractalltest
