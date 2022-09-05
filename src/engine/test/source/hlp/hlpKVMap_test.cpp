#include <any>
#include <vector>

#include <gtest/gtest.h>
#include <hlp/hlp.hpp>

using namespace hlp;

using std::any_cast;
using std::string;

const char* defaultLogQLExpression {"<_kv/kv_map/:/ >"};

TEST(parseKVMap, build)
{
    const char* logQlExpression = "<_kv/kv_map/=/ >";

    ASSERT_NO_THROW(getParserOp(logQlExpression));
}

TEST(parseKVMap, buildNoArgumentsError)
{
    const char* logQlExpression = "<_kv/kv_map>";

    ASSERT_THROW(getParserOp(logQlExpression), std::runtime_error);
}

// TODO: Throw message when no target field is set
TEST(parseKVMap, buildNoTargetError)
{
    GTEST_SKIP();

    const char* logQlExpression = "</kv_map/=/ >";

    ASSERT_THROW(getParserOp(logQlExpression), std::runtime_error);
}

// TODO: Throw message when no parser is set
TEST(parseKVMap, buildNoParserError)
{
    GTEST_SKIP();

    const char* logQlExpression = "<_kv//=/ >";

    ASSERT_THROW(getParserOp(logQlExpression), std::runtime_error);
}

TEST(parseKVMap, buildNoKVSeparatorError)
{
    const char* logQlExpression = "<_kv/kv_map// >";

    ASSERT_THROW(getParserOp(logQlExpression), std::runtime_error);
}

TEST(parseKVMap, buildNoPairsSeparatorError)
{
    const char* logQlExpression = "<_kv/kv_map/=/>";

    ASSERT_THROW(getParserOp(logQlExpression), std::runtime_error);
}

TEST(parseKVMap, buildNoEndString)
{
    const char* customLogQLExpression = "<_kv/kv_map/=/ >";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));
}

TEST(parseKVMap, singleKVPairMatch)
{
    const char* event = "keyX:valueX";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ("{\"keyX\":\"valueX\"}",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, twoKVPairsMatch)
{
    const char* event = "key1:value1 key2:value2";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ("{\"key1\":\"value1\",\"key2\":\"value2\"}",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, threeKVPairsMatch)
{
    const char* event = "key1:value1 key2:value2 key3:value3";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ("{\"key1\":\"value1\",\"key2\":\"value2\",\"key3\":\"value3\"}",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, singleKVPairMultipleCharKVSeparatorMatchCaseI)
{
    const char* customLogQLExpression {"<_kv/kv_map/: /,>"};
    const char* event = "keyX: valueX";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ("{\"keyX\":\"valueX\"}",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, singleKVPairMultipleCharKVSeparatorMatchCaseII)
{
    const char* customLogQLExpression {"<_kv/kv_map/: / >"};
    const char* event = "keyX: valueX";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ("{\"keyX\":\"valueX\"}",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, singleKVPairMultipleCharKVSeparatorMatchCaseIII)
{
    const char* customLogQLExpression {"<_kv/kv_map/: / >"};
    const char* event = "keyX: valueX ";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, singleKVPairMultipleCharKVSeparatorMatchCaseIV)
{
    const char* customLogQLExpression {"<_kv/kv_map/: /,>;"};
    const char* event = "keyX: valueX;";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ("{\"keyX\":\"valueX\"}",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, singleKVPairMultipleCharKVSeparatorMatchCaseV)
{
    const char* customLogQLExpression {"<_kv/kv_map/: /,>;"};
    const char* event = "keyX: valueX";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, singleKVPairMultipleCharKVSeparatorMatchCaseVI)
{
    const char* customLogQLExpression {"<_kv/kv_map/: /,>"};
    const char* event = "keyX:valueX";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, singleKVPairMultipleCharKVSeparatorMatchCaseVII)
{
    const char* customLogQLExpression {"<_kv/kv_map/: / >"};
    const char* event = "keyX: valueX ";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, twoKVPairsMultipleCharKVSeparatorMatchCaseI)
{
    const char* customLogQLExpression {"<_kv/kv_map/: /,>"};
    const char* event = "key1: value1,key2: value2";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ("{\"key1\":\"value1\",\"key2\":\"value2\"}",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, twoKVPairsMultipleCharKVSeparatorMatchCaseII)
{
    const char* customLogQLExpression {"<_kv/kv_map/: / >"};
    const char* event = "key1: value1 key2: value2";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ("{\"key1\":\"value1\",\"key2\":\"value2\"}",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, twoKVPairsMultipleCharKVSeparatorMatchCaseIII)
{
    const char* customLogQLExpression {"<_kv/kv_map/: / >"};
    const char* event = "key1: value1 key2: value2 ";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, twoKVPairMultipleCharKVSeparatorMatchCaseIV)
{
    const char* customLogQLExpression {"<_kv/kv_map/: /,>;"};
    const char* event = "key1: value1,key2: value2;";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ("{\"key1\":\"value1\",\"key2\":\"value2\"}",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, twoKVPairsMultipleCharKVSeparatorMatchCaseV)
{
    const char* customLogQLExpression {"<_kv/kv_map/: /,>;"};
    const char* event = "key1: value1,key2: value2";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, twoKVPairsMultipleCharKVSeparatorMatchCaseVI)
{
    const char* customLogQLExpression {"<_kv/kv_map/: /,>"};
    const char* event = "key1:value1,key2:value2";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, twoKVPairMultipleCharKVSeparatorMatchCaseVII)
{
    const char* customLogQLExpression {"<_kv/kv_map/: / >"};
    const char* event = "key1: value1 key2: value2 ";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, singleKVPairNoMatchGivenEndString)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/ >."};
    const char* event = "keyX:valueX";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, twoKVPairsNoMatchGivenEndString)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/ >."};
    const char* event = "key1:value1 key2:value2";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, threeKVPairsNoMatchGivenEndString)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/ >."};
    const char* event = "key1:value1 key2:value2 key3:value3";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, singleKVPairNoMatchGivenKVSeparator)
{
    const char* customLogQLExpression {"<_kv/kv_map/=/ >"};
    const char* event = "keyX:valueX";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, twoKVPairsNoMatchGivenKVSeparator)
{
    const char* customLogQLExpression {"<_kv/kv_map/=/ >"};
    const char* event = "key1:value1 key2:value2";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, threeKVPairsNoMatchGivenKVSeparator)
{
    const char* customLogQLExpression {"<_kv/kv_map/=/ >"};
    const char* event = "key1:value1 key2:value2 key3:value3";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, noEndStringCaseI)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/ >."};
    const char* event = "keyX:valueX";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, noEndStringCaseII)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/ >."};
    const char* event = "keyX: valueX";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, noEndStringCaseIII)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/ >."};
    const char* event = "keyX: ";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, noEndStringCaseIV)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/ >."};
    const char* event = "keyX:";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, noEndStringCaseV)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/ >."};
    const char* event = "keyX";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, noEndStringCaseVI)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/ >."};
    const char* event = ": ";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, noEndStringCaseVII)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/ >."};
    const char* event = ":";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, noEndStringCaseVIII)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/ >."};
    const char* event = ": value";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, noPairSeparatorFoundCaseI)
{
    const char* event = "key1:value1,key2:value2";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ("{\"key1\":\"value1,key2:value2\"}",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, noPairSeparatorFoundCaseII)
{
    const char* event = "key1:value1,key2:value2,key3:value3";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ("{\"key1\":\"value1,key2:value2,key3:value3\"}",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, noPairSeparatorFoundCaseIII)
{
    const char* event = "key1:value1,key2:value2,key3:value3";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ("{\"key1\":\"value1,key2:value2,key3:value3\"}",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseI)
{
    const char* event = "keyX:valueX;";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ("{\"keyX\":\"valueX;\"}",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseII)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/ >;"};
    const char* event = "keyX:valueX;";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ("{\"keyX\":\"valueX\"}",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseIII)
{
    const char* customLogQLExpression {"<_kv/kv_map/: / >;"};
    const char* event = "keyX:;";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, generalCaseIV)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/,>"};
    const char* event = "key1:value1,key2:value2,";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ("{\"key1\":\"value1\",\"key2\":\"value2\"}",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseV)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/,>"};
    const char* event = "key1:value1,key2:value2,";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ("{\"key1\":\"value1\",\"key2\":\"value2\"}",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, nullKeyCaseI)
{
    const char* customLogQLExpression {"<_kv/kv_map/: / >;"};
    const char* event = ": ;";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, nullKeyCaseII)
{
    const char* customLogQLExpression {"<_kv/kv_map/: / >;"};
    const char* event = ": valueX;";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, nullKeyCaseIII)
{
    const char* customLogQLExpression {"<_kv/kv_map/: / >"};
    const char* event = ": valueX";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, nullKeyCaseIV)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/ >"};
    const char* event = ":valueX";

    ParserFn op {};
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ParseResult result {};
    bool retVal {false};
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}
