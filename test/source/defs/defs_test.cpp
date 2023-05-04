#include <defs/defs.hpp>
#include <gtest/gtest.h>

class DefsBuildsTest : public ::testing::TestWithParam<std::tuple<json::Json, bool>>
{
};

TEST_P(DefsBuildsTest, Builds)
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
    DefsBuildsTest,
    ::testing::Values(std::make_tuple(json::Json(), false),
                      std::make_tuple(json::Json(R"([])"), false),
                      std::make_tuple(json::Json(R"(["a"])"), false),
                      std::make_tuple(json::Json(R"({})"), false),
                      std::make_tuple(json::Json(R"({"a": 1})"), true),
                      std::make_tuple(json::Json(R"({"a": "1"})"), true),
                      std::make_tuple(json::Json(R"({"a": true})"), true),
                      std::make_tuple(json::Json(R"({"a": false})"), true),
                      std::make_tuple(json::Json(R"({"a": null})"), true),
                      std::make_tuple(json::Json(R"({"a": []})"), true),
                      std::make_tuple(json::Json(R"({"a": {}})"), true),
                      std::make_tuple(json::Json(R"({"a": 1, "b":"1", "c":true, "d":false, "e":null, "f":[], "g":{}})"),
                                      true),
                      std::make_tuple(json::Json(R"({"$a": 1})"), false),
                      std::make_tuple(json::Json(R"({"schema.field": "value"})"), false)));

struct Ret
{
};
struct Input
{
};

struct Builder
{
    std::variant<Ret, std::tuple<Builder, Input>> operator()(Input input)
    {
        return Ret {};
    }
};

TEST(Testt, testt)
{

    Builder initialBuilder{};

    Input initialInput {};

    std::variant<Ret, std::tuple<Builder, Input>> res = initialBuilder(initialInput);
    while (std::holds_alternative<std::tuple<Builder, Input>>(res))
    {
        auto [next, input] = std::get<std::tuple<Builder, Input>>(res);
        res = next(input);
    }
}
