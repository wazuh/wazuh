#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#include "hlp_test.hpp"

auto constexpr NAME = "jsonParser";
static const std::string TARGET = "/TargetField";

namespace
{
// Nesting cap of the parser (json::Json::MAX_DEPTH, signed as 256). Written as a literal on purpose: a change of the
// engine-wide constant must break the depth cases below instead of silently moving them along with it.
constexpr std::size_t DEPTH_LIMIT = 256;

/// open x n + leaf + close x n (arrays: "[" / "]"; objects: "{\"a\":" / "}").
std::string nested(std::string_view open, std::string_view close, std::size_t n, std::string_view leaf = "1")
{
    std::string text;
    text.reserve((open.size() + close.size()) * n + leaf.size());
    for (std::size_t i = 0; i < n; ++i)
    {
        text.append(open);
    }
    text.append(leaf);
    for (std::size_t i = 0; i < n; ++i)
    {
        text.append(close);
    }
    return text;
}

/// Alternating object -> array -> object chain of n containers around the leaf 1.
std::string mixedNested(std::size_t n)
{
    std::string text;
    for (std::size_t i = 0; i < n; ++i)
    {
        text.append(i % 2 == 0 ? "{\"a\":" : "[");
    }
    text.append("1");
    for (std::size_t i = n; i > 0; --i)
    {
        text.append((i - 1) % 2 == 0 ? "}" : "]");
    }
    return text;
}

/// JSON pointer of the leaf of a chain of n containers, one token per level (mixed: "/a" on objects, "/0" on arrays).
std::string leafPath(std::string_view objectToken, std::string_view arrayToken, std::size_t n)
{
    std::string path;
    for (std::size_t i = 0; i < n; ++i)
    {
        path.append(i % 2 == 0 ? objectToken : arrayToken);
    }
    return path;
}
} // namespace

INSTANTIATE_TEST_SUITE_P(JSONBuild,
                         HlpBuildTest,
                         ::testing::Values(BuildT(SUCCESS, getJSONParser, {NAME, TARGET, {}, {}}),
                                           BuildT(FAILURE, getJSONParser, {NAME, TARGET, {}, {"unexpected"}})));

INSTANTIATE_TEST_SUITE_P(
    JSONParse,
    HlpParseTest,
    ::testing::Values(
        ParseT(SUCCESS,
               "{}",
               j(fmt::format(R"({{"{}":{{}}}})", TARGET.substr(1))),
               2,
               getJSONParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "{}left over",
               j(fmt::format(R"({{"{}":{{}}}})", TARGET.substr(1))),
               2,
               getJSONParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "null",
               j(fmt::format(R"({{"{}":null}})", TARGET.substr(1))),
               4,
               getJSONParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "nullleft over",
               j(fmt::format(R"({{"{}":null}})", TARGET.substr(1))),
               4,
               getJSONParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "true",
               j(fmt::format(R"({{"{}":true}})", TARGET.substr(1))),
               4,
               getJSONParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "trueleft over",
               j(fmt::format(R"({{"{}":true}})", TARGET.substr(1))),
               4,
               getJSONParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "false",
               j(fmt::format(R"({{"{}":false}})", TARGET.substr(1))),
               5,
               getJSONParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "falseleft over",
               j(fmt::format(R"({{"{}":false}})", TARGET.substr(1))),
               5,
               getJSONParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "123",
               j(fmt::format(R"({{"{}":123}})", TARGET.substr(1))),
               3,
               getJSONParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "123left over",
               j(fmt::format(R"({{"{}":123}})", TARGET.substr(1))),
               3,
               getJSONParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "123.456",
               j(fmt::format(R"({{"{}":123.456}})", TARGET.substr(1))),
               7,
               getJSONParser,
               {NAME, TARGET, {}, {}}),
        // This should pass
        // TODO: this fails on rapidjson parser
        // ParseT(SUCCESS,
        //        "123.456left over",
        //        j(fmt::format(R"({{"{}":123.456}})", TARGET.substr(1))),
        //        7,
        //        getJSONParser,
        //        {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               R"("abc")",
               j(fmt::format(R"({{"{}":"abc"}})", TARGET.substr(1))),
               5,
               getJSONParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               R"("abc"left over)",
               j(fmt::format(R"({{"{}":"abc"}})", TARGET.substr(1))),
               5,
               getJSONParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "[]",
               j(fmt::format(R"({{"{}":[]}})", TARGET.substr(1))),
               2,
               getJSONParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "[]left over",
               j(fmt::format(R"({{"{}":[]}})", TARGET.substr(1))),
               2,
               getJSONParser,
               {NAME, TARGET, {}, {}}),
        ParseT(
            SUCCESS,
            R"({"Actors":[{"name":"Tom Cruise","age":56,"Born At":"Syracuse, NY","Birthdate":"July 3, 1962","photo":"https://jsonformatterdotorg/img/tom-cruise.jpg","wife":null,"weight":67.5,"hasChildren":true,"hasGreyHair":false,"children":["Suri","Isabella Jane","Connor"]},{"name":"Robert Downey Jr.","age":53,"Born At":"New York City, NY","Birthdate":"April 4, 1965","photo":"https://jsonformatterdotorg/img/Robert-Downey-Jr.jpg","wife":"Susan Downey","weight":77.1,"hasChildren":true,"hasGreyHair":false,"children":["Indio Falconer","Avri Roel","Exton Elias"]}]})",
            j(fmt::format(
                R"({{"{}":{} }})",
                TARGET.substr(1),
                R"({"Actors":[{"name":"Tom Cruise","age":56,"Born At":"Syracuse, NY","Birthdate":"July 3, 1962","photo":"https://jsonformatterdotorg/img/tom-cruise.jpg","wife":null,"weight":67.5,"hasChildren":true,"hasGreyHair":false,"children":["Suri","Isabella Jane","Connor"]},{"name":"Robert Downey Jr.","age":53,"Born At":"New York City, NY","Birthdate":"April 4, 1965","photo":"https://jsonformatterdotorg/img/Robert-Downey-Jr.jpg","wife":"Susan Downey","weight":77.1,"hasChildren":true,"hasGreyHair":false,"children":["Indio Falconer","Avri Roel","Exton Elias"]}]})")),
            552,
            getJSONParser,
            {NAME, TARGET, {}, {}}),
        // One level over the nesting cap is a syntax failure at the start of the input. The boundary (exactly the
        // cap) lives in JsonParserDepth.MaxDepthParses: its expected event would itself exceed the cap of j() and
        // abort the registration of this suite.
        ParseT(FAILURE, nested("[", "]", DEPTH_LIMIT + 1), {}, 0, getJSONParser, {NAME, TARGET, {}, {}}),
        ParseT(FAILURE, nested("{\"a\":", "}", DEPTH_LIMIT + 1), {}, 0, getJSONParser, {NAME, TARGET, {}, {}})));

// Exactly DEPTH_LIMIT nested containers parse, report the exact rest of the input and map the whole chain.
TEST(JsonParserDepth, MaxDepthParses)
{
    struct Case
    {
        std::string name;
        std::string text;
        std::string leaf; // JSON pointer of the leaf inside the parsed value
    };
    const std::vector<Case> cases {
        {"arrays", nested("[", "]", DEPTH_LIMIT), leafPath("/0", "/0", DEPTH_LIMIT)},
        {"objects", nested("{\"a\":", "}", DEPTH_LIMIT), leafPath("/a", "/a", DEPTH_LIMIT)},
        {"mixed", mixedNested(DEPTH_LIMIT), leafPath("/a", "/0", DEPTH_LIMIT)},
    };
    const std::vector<std::string> rests {"", "left over"};

    const auto parser = getJSONParser({NAME, TARGET, {}, {}});
    for (const auto& c : cases)
    {
        for (const auto& rest : rests)
        {
            SCOPED_TRACE(c.name + (rest.empty() ? "" : " + '" + rest + "'"));
            const auto input = c.text + rest;

            const auto result = parser(input);
            ASSERT_TRUE(result.success()) << result.trace();
            ASSERT_TRUE(result.hasValue());
            EXPECT_EQ(result.remaining(), rest);

            auto event = json::Json {};
            event.setObject();
            const auto error = hlp::parser::run(parser, input, event, true);
            ASSERT_FALSE(error.has_value()) << error->message;
            EXPECT_TRUE(event.exists(TARGET + c.leaf));
            EXPECT_EQ(event.getInt(TARGET + c.leaf), 1);
        }
    }
}

// One level over the cap fails with a trace that names the limit (only when tracing) and leaves the event untouched;
// any other syntax error keeps today's trace (the parser name).
TEST(JsonParserDepth, TraceNamesLimit)
{
    const auto parser = getJSONParser({NAME, TARGET, {}, {}});
    for (const auto& text :
         {nested("[", "]", DEPTH_LIMIT + 1), nested("{\"a\":", "}", DEPTH_LIMIT + 1), mixedNested(DEPTH_LIMIT + 1)})
    {
        auto event = json::Json {};
        event.setObject();

        const auto traced = hlp::parser::run(parser, text, event, true);
        ASSERT_TRUE(traced.has_value());
        EXPECT_NE(traced->message.find(json::Json::DEPTH_ERROR_MSG), std::string::npos) << traced->message;
        EXPECT_NE(traced->message.find("256"), std::string::npos) << traced->message;
        EXPECT_EQ(traced->message,
                  fmt::format("Parser {}: nesting depth exceeds the limit (256) failed at: {}", NAME, text));

        const auto untraced = hlp::parser::run(parser, text, event, false);
        ASSERT_TRUE(untraced.has_value());
        EXPECT_TRUE(untraced->message.empty()) << untraced->message;

        EXPECT_FALSE(event.exists(TARGET));
    }

    auto event = json::Json {};
    event.setObject();
    const auto syntax = hlp::parser::run(parser, "[1,2", event, true);
    ASSERT_TRUE(syntax.has_value());
    EXPECT_EQ(syntax->message, fmt::format("Parser {} failed at: [1,2", NAME));
}
