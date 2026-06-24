#include "builders/baseBuilders_test.hpp"
#include "builders/optransform/hlp.hpp"

#include <hlp/hlp.hpp>

using namespace builder::builders::optransform;

namespace
{
using namespace builder::builders;

// ─────────────────────────────────────────────────────────────────────────────
// Helper to set up mock expectations for a given reference field
// ─────────────────────────────────────────────────────────────────────────────
auto expectRef(const std::string& ref)
{
    return [ref](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.validator, hasField(DotPath(ref))).WillOnce(testing::Return(false));
        return None {};
    };
}

auto expectRefWithEvent(const std::string& ref, base::Event result)
{
    return [=](const BuildersMocks& mocks)
    {
        EXPECT_CALL(*mocks.ctx, validator());
        EXPECT_CALL(*mocks.validator, hasField(DotPath(ref))).WillOnce(testing::Return(false));
        return result;
    };
}

} // namespace

// =============================================================================
// Section 1: Parametrized test over all real parsers with valid input
// =============================================================================

struct HlpParserTestParam
{
    std::string name;
    TransformBuilder builder;
    std::string inputEvent;         // JSON event with source field
    std::vector<OpArg> extraArgs;   // Additional builder args beyond the source ref
};

class HlpAllParsersTest : public BaseBuilderTest, public testing::WithParamInterface<HlpParserTestParam>
{
};

TEST_P(HlpAllParsersTest, BuildAndExecuteSuccess)
{
    const auto& param = GetParam();

    // Set expectations
    EXPECT_CALL(*mocks->ctx, context()).Times(testing::AtLeast(1));
    EXPECT_CALL(*mocks->ctx, isTestMode()).Times(testing::AtLeast(1));
    EXPECT_CALL(*mocks->ctx, validator());
    EXPECT_CALL(*mocks->validator, hasField(DotPath("source"))).WillOnce(testing::Return(false));

    // Build args: first arg is always the source ref
    std::vector<OpArg> opArgs;
    opArgs.push_back(makeRef("source"));
    for (const auto& arg : param.extraArgs)
    {
        opArgs.push_back(arg);
    }

    Reference targetField("target");

    // Build should not throw
    TransformOp op;
    ASSERT_NO_THROW(op = param.builder(targetField, opArgs, mocks->ctx));

    // Execute with valid input
    auto event = makeEvent(param.inputEvent);
    auto result = op(event);
    EXPECT_TRUE(result.success()) << "Parser '" << param.name << "' failed on valid input";
}

INSTANTIATE_TEST_SUITE_P(
    RealParsers,
    HlpAllParsersTest,
    testing::Values(
        HlpParserTestParam {"parse_bool", boolParseBuilder, R"({"source": "true"})", {}},
        HlpParserTestParam {"parse_byte", byteParseBuilder, R"({"source": "42"})", {}},
        HlpParserTestParam {"parse_short", shortParseBuilder, R"({"source": "1234"})", {}},
        HlpParserTestParam {"parse_integer", integerParseBuilder, R"({"source": "123456"})", {}},
        HlpParserTestParam {"parse_unsigned_long", unsignedLongParseBuilder, R"({"source": "9999999"})", {}},
        HlpParserTestParam {"parse_long", longParseBuilder, R"({"source": "-123456789"})", {}},
        HlpParserTestParam {"parse_float", floatParseBuilder, R"({"source": "3.14"})", {}},
        HlpParserTestParam {"parse_double", doubleParseBuilder, R"({"source": "3.141592653589793"})", {}},
        HlpParserTestParam {"parse_half_float", halfFloatParseBuilder, R"({"source": "1.5"})", {}},
        HlpParserTestParam {"parse_binary", binaryParseBuilder, R"({"source": "SGVsbG8="})", {}},
        HlpParserTestParam {
            "parse_date", dateParseBuilder, R"({"source": "2023-01-15T10:30:00Z"})", {makeValue(R"("ISO8601Z")")}},
        HlpParserTestParam {"parse_ip", ipParseBuilder, R"({"source": "192.168.1.1"})", {}},
        HlpParserTestParam {
            "parse_uri", uriParseBuilder, R"({"source": "https://example.com/path?q=1"})", {}},
        HlpParserTestParam {"parse_fqdn", fqdnParseBuilder, R"({"source": "www.example.com"})", {}},
        HlpParserTestParam {"parse_json", jsonParseBuilder, R"({"source": "{\"key\":\"value\"}"})", {}},
        HlpParserTestParam {
            "parse_xml", xmlParseBuilder, R"({"source": "<root><item>value</item></root>"})", {}},
        HlpParserTestParam {
            "parse_csv",
            csvParseBuilder,
            R"({"source": "one,two,three"})",
            {makeValue(R"("field1")"), makeValue(R"("field2")"), makeValue(R"("field3")")}},
        HlpParserTestParam {
            "parse_dsv",
            dsvParseBuilder,
            R"({"source": "one|two|three"})",
            {makeValue(R"("|")"), makeValue(R"("\"")"), makeValue(R"("\\")"), makeValue(R"("field1")"), makeValue(R"("field2")"), makeValue(R"("field3")")}},
        HlpParserTestParam {
            "parse_key_value",
            keyValueParseBuilder,
            R"({"source": "key1=val1 key2=val2"})",
            {makeValue(R"("=")"), makeValue(R"(" ")"), makeValue(R"("\"")"), makeValue(R"("\\")")}},
        HlpParserTestParam {
            "parse_quoted", quotedParseBuilder, R"({"source": "\"hello world\""})", {}},
        HlpParserTestParam {
            "parse_between",
            betweenParseBuilder,
            R"({"source": "[content]"})",
            {makeValue(R"("[")"), makeValue(R"("]")")}},
        HlpParserTestParam {"parse_alphanumeric", alphanumericParseBuilder, R"({"source": "abc123"})", {}},
        HlpParserTestParam {
            "parse_user_agent",
            userAgentParseBuilder,
            R"({"source": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})",
            {}},
        HlpParserTestParam {
            "parse_file_path", filePathParseBuilder, R"({"source": "/usr/local/bin/test"})", {}}),
    [](const testing::TestParamInfo<HlpParserTestParam>& info) { return info.param.name; });

// =============================================================================
// Section 2: Generic negative cases (shared, not duplicated per parser)
// =============================================================================

class HlpNegativeTest : public BaseBuilderTest
{
};

// Handle a missing source field
TEST_F(HlpNegativeTest, MissingSourceField)
{
    EXPECT_CALL(*mocks->ctx, context()).Times(testing::AtLeast(1));
    EXPECT_CALL(*mocks->ctx, isTestMode()).Times(testing::AtLeast(1));
    EXPECT_CALL(*mocks->ctx, validator());
    EXPECT_CALL(*mocks->validator, hasField(DotPath("source"))).WillOnce(testing::Return(false));

    std::vector<OpArg> opArgs {makeRef("source")};
    Reference targetField("target");

    auto op = boolParseBuilder(targetField, opArgs, mocks->ctx);

    // Event without the source field
    auto event = makeEvent(R"({"other": "value"})");
    auto result = op(event);
    EXPECT_FALSE(result.success());
}

// Handle a source field that is not a string
TEST_F(HlpNegativeTest, NonStringSourceField)
{
    EXPECT_CALL(*mocks->ctx, context()).Times(testing::AtLeast(1));
    EXPECT_CALL(*mocks->ctx, isTestMode()).Times(testing::AtLeast(1));
    EXPECT_CALL(*mocks->ctx, validator());
    EXPECT_CALL(*mocks->validator, hasField(DotPath("source"))).WillOnce(testing::Return(false));

    std::vector<OpArg> opArgs {makeRef("source")};
    Reference targetField("target");

    auto op = integerParseBuilder(targetField, opArgs, mocks->ctx);

    // Source field is a number, not a string
    auto event = makeEvent(R"({"source": 12345})");
    auto result = op(event);
    EXPECT_FALSE(result.success());
}

// Handle invalid input for a parser
TEST_F(HlpNegativeTest, InvalidInputForParser)
{
    EXPECT_CALL(*mocks->ctx, context()).Times(testing::AtLeast(1));
    EXPECT_CALL(*mocks->ctx, isTestMode()).Times(testing::AtLeast(1));
    EXPECT_CALL(*mocks->ctx, validator());
    EXPECT_CALL(*mocks->validator, hasField(DotPath("source"))).WillOnce(testing::Return(false));

    std::vector<OpArg> opArgs {makeRef("source")};
    Reference targetField("target");

    auto op = ipParseBuilder(targetField, opArgs, mocks->ctx);

    // Not a valid IP address
    auto event = makeEvent(R"({"source": "not-an-ip"})");
    auto result = op(event);
    EXPECT_FALSE(result.success());
}

// Reject a target field that is not allowed
TEST_F(HlpNegativeTest, DisallowedTargetField)
{
    EXPECT_CALL(*mocks->ctx, context()).Times(testing::AtLeast(1));
    EXPECT_CALL(*mocks->decoderUnmodifiableFields, check(testing::_, DotPath("forbidden_field")))
        .WillOnce(testing::Return(false));

    std::vector<OpArg> opArgs {makeRef("source")};
    Reference targetField("forbidden_field");

    EXPECT_THROW(boolParseBuilder(targetField, opArgs, mocks->ctx), std::runtime_error);
}

// Reject a source reference that is in schema but not of string type
TEST_F(HlpNegativeTest, NonStringSourceInSchema)
{
    EXPECT_CALL(*mocks->ctx, context()).Times(testing::AtLeast(1));
    EXPECT_CALL(*mocks->ctx, validator()).Times(testing::AtLeast(1));
    EXPECT_CALL(*mocks->validator, hasField(DotPath("source"))).WillOnce(testing::Return(true));
    EXPECT_CALL(*mocks->validator, getJsonType(DotPath("source"))).WillOnce(testing::Return(json::Json::Type::Number));

    std::vector<OpArg> opArgs {makeRef("source")};
    Reference targetField("target");

    EXPECT_THROW(boolParseBuilder(targetField, opArgs, mocks->ctx), std::runtime_error);
}

// =============================================================================
// Section 3: Tests with isTestMode enabled (trace messages)
// =============================================================================

class HlpTestModeTest : public BaseBuilderTest
{
};

// Success path with isTestMode=true includes trace message
TEST_F(HlpTestModeTest, SuccessWithTestModeTrace)
{
    EXPECT_CALL(*mocks->ctx, context()).Times(testing::AtLeast(1));
    EXPECT_CALL(*mocks->ctx, isTestMode()).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(*mocks->ctx, validator());
    EXPECT_CALL(*mocks->validator, hasField(DotPath("source"))).WillOnce(testing::Return(false));

    std::vector<OpArg> opArgs {makeRef("source")};
    Reference targetField("target");

    auto op = boolParseBuilder(targetField, opArgs, mocks->ctx);

    auto event = makeEvent(R"({"source": "true"})");
    auto result = op(event);
    EXPECT_TRUE(result.success());
    EXPECT_TRUE(result.hasTrace());
    EXPECT_THAT(result.trace(), testing::HasSubstr("Success"));
}

// Missing source field failure with isTestMode=true includes trace
TEST_F(HlpTestModeTest, MissingSourceWithTestModeTrace)
{
    EXPECT_CALL(*mocks->ctx, context()).Times(testing::AtLeast(1));
    EXPECT_CALL(*mocks->ctx, isTestMode()).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(*mocks->ctx, validator());
    EXPECT_CALL(*mocks->validator, hasField(DotPath("source"))).WillOnce(testing::Return(false));

    std::vector<OpArg> opArgs {makeRef("source")};
    Reference targetField("target");

    auto op = boolParseBuilder(targetField, opArgs, mocks->ctx);

    auto event = makeEvent(R"({"other": "value"})");
    auto result = op(event);
    EXPECT_FALSE(result.success());
    EXPECT_TRUE(result.hasTrace());
    EXPECT_THAT(result.trace(), testing::HasSubstr("doesn't exist"));
}

// Non-string source failure with isTestMode=true includes trace
TEST_F(HlpTestModeTest, NonStringSourceWithTestModeTrace)
{
    EXPECT_CALL(*mocks->ctx, context()).Times(testing::AtLeast(1));
    EXPECT_CALL(*mocks->ctx, isTestMode()).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(*mocks->ctx, validator());
    EXPECT_CALL(*mocks->validator, hasField(DotPath("source"))).WillOnce(testing::Return(false));

    std::vector<OpArg> opArgs {makeRef("source")};
    Reference targetField("target");

    auto op = integerParseBuilder(targetField, opArgs, mocks->ctx);

    auto event = makeEvent(R"({"source": 12345})");
    auto result = op(event);
    EXPECT_FALSE(result.success());
    EXPECT_TRUE(result.hasTrace());
    EXPECT_THAT(result.trace(), testing::HasSubstr("is not a string"));
}

// Parser failure with isTestMode=true includes trace with error message
TEST_F(HlpTestModeTest, ParserFailureWithTestModeTrace)
{
    EXPECT_CALL(*mocks->ctx, context()).Times(testing::AtLeast(1));
    EXPECT_CALL(*mocks->ctx, isTestMode()).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(*mocks->ctx, validator());
    EXPECT_CALL(*mocks->validator, hasField(DotPath("source"))).WillOnce(testing::Return(false));

    std::vector<OpArg> opArgs {makeRef("source")};
    Reference targetField("target");

    auto op = ipParseBuilder(targetField, opArgs, mocks->ctx);

    auto event = makeEvent(R"({"source": "not-an-ip"})");
    auto result = op(event);
    EXPECT_FALSE(result.success());
    EXPECT_TRUE(result.hasTrace());
    EXPECT_THAT(result.trace(), testing::HasSubstr("->"));
}
