#include <defs/defs.hpp>
#include <gtest/gtest.h>

class DefsBuildTest : public ::testing::TestWithParam<std::tuple<json::Json, bool>>
{
};

TEST_P(DefsBuildTest, Builds)
{
    auto [definitions, shouldPass] = GetParam();

    if (shouldPass)
    {
        ASSERT_NO_THROW(auto def = defs::Definitions(definitions));
    }
    else
    {
        ASSERT_THROW(auto def = defs::Definitions(definitions), std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(
    Builds,
    DefsBuildTest,
    ::testing::Values(std::make_tuple(json::Json(), false),
                      std::make_tuple(json::Json(R"([])"), false),
                      std::make_tuple(json::Json(R"(["a"])"), false),
                      std::make_tuple(json::Json(R"({})"), true),
                      std::make_tuple(json::Json(R"({"a": 1})"), true),
                      std::make_tuple(json::Json(R"({"a": "1"})"), true),
                      std::make_tuple(json::Json(R"({"a": true})"), true),
                      std::make_tuple(json::Json(R"({"a": false})"), true),
                      std::make_tuple(json::Json(R"({"a": null})"), true),
                      std::make_tuple(json::Json(R"({"a": []})"), true),
                      std::make_tuple(json::Json(R"({"a": {}})"), true),
                      std::make_tuple(json::Json(R"({"a": 1, "b":"1", "c":true, "d":false, "e":null, "f":[], "g":{}})"),
                                      true),
                      std::make_tuple(json::Json(R"({"$a": 1})"), false)));

class DefsGetTest : public ::testing::TestWithParam<std::tuple<json::Json, std::string, json::Json, bool>>
{
};

TEST_P(DefsGetTest, Gets)
{
    auto [definitions, toGet, expected, shouldPass] = GetParam();
    auto def = defs::Definitions(definitions);
    if (shouldPass)
    {
        ASSERT_EQ(def.get(toGet), expected);
    }
    else
    {
        ASSERT_THROW(def.get(toGet), std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(
    Gets,
    DefsGetTest,
    ::testing::Values(std::make_tuple(json::Json(R"({"a": 1})"), "/a", json::Json("1"), true),
                      std::make_tuple(json::Json(R"({"a": "1"})"), "/a", json::Json(R"("1")"), true),
                      std::make_tuple(json::Json(R"({"a": true})"), "/a", json::Json("true"), true),
                      std::make_tuple(json::Json(R"({"a": false})"), "/a", json::Json("false"), true),
                      std::make_tuple(json::Json(R"({"a": null})"), "/a", json::Json("null"), true),
                      std::make_tuple(json::Json(R"({"a": []})"), "/a", json::Json("[]"), true),
                      std::make_tuple(json::Json(R"({"a": {}})"), "/a", json::Json("{}"), true),
                      std::make_tuple(json::Json(R"({"a": 1})"), "/b", json::Json(), false)));

class DefsReplaceTest : public ::testing::TestWithParam<std::tuple<json::Json, std::string, std::string>>
{
};

TEST_P(DefsReplaceTest, Replaces)
{
    auto [definitions, input, expected] = GetParam();

    auto def = defs::Definitions(definitions);
    ASSERT_EQ(def.replace(input), expected);
}

INSTANTIATE_TEST_SUITE_P(
    Replaces,
    DefsReplaceTest,
    ::testing::Values(std::make_tuple(json::Json(R"({"a": "value"})"), "$a", "value"),
                      std::make_tuple(json::Json(R"({"a": 1})"), "$a", "1"),
                      std::make_tuple(json::Json(R"({"a": true})"), "$a", "true"),
                      std::make_tuple(json::Json(R"({"a": false})"), "$a", "false"),
                      std::make_tuple(json::Json(R"({"a": null})"), "$a", "null"),
                      std::make_tuple(json::Json(R"({"a": []})"), "$a", "[]"),
                      std::make_tuple(json::Json(R"({"a": {}})"), "$a", "{}"),
                      std::make_tuple(json::Json(R"({"a": 1, "b":"1", "c":true, "d":false, "e":null, "f":[], "g":{}})"),
                                      "$a $b $c $d $e $f $g",
                                      "1 1 true false null [] {}"),
                      std::make_tuple(json::Json(R"({"a": "value"})"), "\\$a", "$a"),
                      std::make_tuple(json::Json(R"({"a": "value"})"), "\\$a$a", "$avalue"),
                      std::make_tuple(json::Json(R"({"a": "value", "b": "$a", "c": "$b"})"), "$c", "value"),
                      std::make_tuple(json::Json(R"({"a": "$b", "b": "value"})"), "$a", "$b"),
                      std::make_tuple(json::Json(R"({"a": "$a"})"), "$a", "$a")));
