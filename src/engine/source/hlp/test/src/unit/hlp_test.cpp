#include <gtest/gtest.h>

#include "hlp_test.hpp"

TEST_P(HlpBuildTest, Build)
{
    auto [success, builder, params] = GetParam();
    if (success)
    {
        EXPECT_NO_THROW(builder(params));
    }
    else
    {
        EXPECT_THROW(builder(params), std::exception);
    }
}

// Any parser builder should build with any stop tokens
TEST_P(HlpBuildTest, BuildStops)
{
    auto [success, builder, params] = GetParam();
    if (success)
    {
        params.stop = {"a", "b", "", "abc"};
        EXPECT_NO_THROW(builder(params));
    }
}

// Any parser builder should build with empty target field
TEST_P(HlpBuildTest, BuildEmptyTarget)
{
    auto [success, builder, params] = GetParam();
    if (success)
    {
        params.targetField = "";
        EXPECT_NO_THROW(builder(params));
    }
}

void parseTest(
    bool success, std::string_view input, const json::Json& expected, size_t index, const hlp::parser::Parser& parser)
{
    auto result = parser(input);
    if (success)
    {
        ASSERT_TRUE(result.success()) << result.trace() << "failed at: '" << result.remaining() << "'";
        ASSERT_TRUE(result.hasValue());
        auto mapper = result.value().semParser(result.value().parsed);
        ASSERT_TRUE(std::holds_alternative<hlp::parser::Mapper>(mapper))
            << "SemParser failed: " << std::get<base::Error>(mapper).message;
        auto event = json::Json {};
        event.setObject();
        std::get<hlp::parser::Mapper>(mapper)(event);
        ASSERT_EQ(event, expected);
    }
    else
    {
        if (result.success())
        {
            ASSERT_TRUE(result.hasValue());
            auto mapper = result.value().semParser(result.value().parsed);
            ASSERT_TRUE(std::holds_alternative<base::Error>(mapper)) << "Parser succeeded";
        }
    }

    ASSERT_EQ(input.size() - result.remaining().size(), index) << "Index mismatch";
}

TEST_P(HlpParseTest, Parse)
{
    auto [success, input, expected, index, builder, params] = GetParam();
    auto parser = builder(params);

    parseTest(success, input, expected, index, parser);
}

// Any parser should ignore text before the input view
TEST_P(HlpParseTest, PreppendParse)
{
    auto [success, input, expected, index, builder, params] = GetParam();
    auto parser = builder(params);
    auto prepended = "0123" + input;
    std::string_view sv(prepended);
    parseTest(success, sv.substr(4), expected, index, parser);
}

// Any parser should fail if the input is empty, i.e. at the end of the original input (except for the eof parser)
TEST_P(HlpParseTest, EOFParse)
{
    auto [success, input, expected, index, builder, params] = GetParam();
    if (params.name != "eofParser") // We have an HLP eof parser, exclude this case, not ideal but works
    {
        auto parser = builder(params);
        std::string_view sv(input);
        parseTest(false, sv.substr(sv.size()), {}, 0, parser);
    }
}

// Any parser should not map if the target field is empty
TEST_P(HlpParseTest, NoMappingParse)
{
    auto [success, input, expected, index, builder, params] = GetParam();
    params.targetField = "";
    expected.setObject();
    auto parser = builder(params);
    parseTest(success, input, expected, index, parser);
}
