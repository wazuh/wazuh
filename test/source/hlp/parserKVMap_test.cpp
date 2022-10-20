#include <any>
#include <vector>

#include <gtest/gtest.h>
#include <hlp/hlp.hpp>

using namespace hlp;

using std::any_cast;
using std::string;

ParserFn op {};
ParseResult result {};
bool retVal {false};

const char* defaultLogparExpression {"<_kv/kv_map/:/ >"};

TEST(parseKVMap, build)
{
    ASSERT_NO_THROW(getParserOp(defaultLogparExpression));
}

TEST(parseKVMap, buildNoArgumentsError)
{
    const char* customLogparExpression {"<_kv/kv_map>"};

    ASSERT_THROW(getParserOp(customLogparExpression), std::runtime_error);
}

// TODO: Throw message when no target field is set
TEST(parseKVMap, buildNoTargetError)
{
    GTEST_SKIP();

    const char* customLogparExpression {"</kv_map/=/ >"};

    ASSERT_THROW(getParserOp(customLogparExpression), std::runtime_error);
}

// TODO: Throw message when no parser is set
TEST(parseKVMap, buildNoParserError)
{
    GTEST_SKIP();

    const char* customLogparExpression {"<_kv//=/ >"};

    ASSERT_THROW(getParserOp(customLogparExpression), std::runtime_error);
}

TEST(parseKVMap, buildNoKVSeparatorError)
{
    const char* customLogparExpression {"<_kv/kv_map// >"};

    ASSERT_THROW(getParserOp(customLogparExpression), std::runtime_error);
}

TEST(parseKVMap, buildNoPairsSeparatorError)
{
    const char* customLogparExpression {"<_kv/kv_map/=/>"};

    ASSERT_THROW(getParserOp(customLogparExpression), std::runtime_error);
}

TEST(parseKVMap, buildSameSeparatorError)
{
    const char* customLogparExpression {"<_kv/kv_map/=/=>"};

    ASSERT_THROW(getParserOp(customLogparExpression), std::runtime_error);
}

TEST(parseKVMap, buildNoEndString)
{
    const char* customLogparExpression {"<_kv/kv_map/=/ >"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));
}

// Test: parsing maps objects
TEST(parseKVMap, success_test)
{
    const char* logpar = "<_map/kv_map/=/ > <_dummy>";
    const char* event = "key1=Value1 Key2=Value2 dummy";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_EQ(true, static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ("{\"key1\":\"Value1\",\"Key2\":\"Value2\"}",
              std::any_cast<JsonString>(result["_map"]).jsonString);
    ASSERT_EQ("dummy", std::any_cast<std::string>(result["_dummy"]));
}

TEST(parseKVMap, end_mark_test)
{
    const char* logpar = "<_map/kv_map/=/ >-<_dummy>";
    const char* event = "key1=Value1 Key2=Value2-dummy";

    ParserFn parseOp = getParserOp(logpar);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(static_cast<bool>(parseOp));
    ASSERT_EQ("{\"key1\":\"Value1\",\"Key2\":\"Value2\"}",
              std::any_cast<JsonString>(result["_map"]).jsonString);
    ASSERT_EQ("dummy", std::any_cast<std::string>(result["_dummy"]));
}

TEST(parseKVMap, incomplete_map_test)
{
    const char* logpar = "<_map/kv_map/=/ >";
    const char* event1 = "key1=Value1 Key2=";
    const char* event2 = "key1=Value1 Key2";
    const char* event3 = "key1=Value1 =Value2";

    ParserFn parseOp = getParserOp(logpar);
    ParseResult result1;
    ParseResult result2;
    ParseResult result3;
    bool ret1 = parseOp(event1, result1);
    bool ret2 = parseOp(event2, result2);
    bool ret3 = parseOp(event3, result3);

    ASSERT_TRUE(static_cast<bool>(parseOp));
    // ASSERT_TRUE(result1.empty());
    ASSERT_TRUE(result2.empty());
    ASSERT_TRUE(result3.empty());
}

// MAP: Values before literal
TEST(parseKVMap, success_map_1_before_string)
{
    const char* logpar = "<_map/kv_map/=/ > hi!";
    const char* event = "key1=Value1 hi!";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_EQ(true, static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(static_cast<bool>(parseOp));
    ASSERT_STREQ(R"({"key1":"Value1"})",
                 std::any_cast<JsonString>(result["_map"]).jsonString.c_str());
}

TEST(parseKVMap, success_map_2_before_string)
{
    const char* logpar = "<_map/kv_map/=/ > hi!";
    const char* event = "key1=Value1 Key2=Value2 hi!";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_EQ(true, static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(static_cast<bool>(parseOp));
    ASSERT_STREQ(R"({"key1":"Value1","Key2":"Value2"})",
                 std::any_cast<JsonString>(result["_map"]).jsonString.c_str());
}

TEST(parseKVMap, success_map_multiCharacterArgs)
{
    const char* logpar = "<_map/kv_map/: / > hi!";
    const char* event = "key1: Value1 Key2: Value2 hi!";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_EQ(true, static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(static_cast<bool>(parseOp));
    ASSERT_STREQ(R"({"key1":"Value1","Key2":"Value2"})",
                 std::any_cast<JsonString>(result["_map"]).jsonString.c_str());
}

TEST(parseKVMap, singleKVPairMatchTestKVSeparators)
{
    const auto expectedResult {R"({"keyX":"valueX"})"};

    string customLogparExpression {"<_kv/kv_map/:/,>"};
    string event {R"(keyX:valueX)"};
    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogparExpression = "<_kv/kv_map/=/,>";
    event = R"(keyX=valueX)";
    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogparExpression = "<_kv/kv_map/|/,>";
    event = R"(keyX|valueX)";
    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogparExpression = "<_kv/kv_map/-/,>";
    event = R"(keyX-valueX)";
    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogparExpression = "<_kv/kv_map/./,>";
    event = R"(keyX.valueX)";
    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogparExpression = "<_kv/kv_map/,/.>";
    event = R"(keyX,valueX)";
    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogparExpression = "<_kv/kv_map/_/.>";
    event = R"(keyX_valueX)";
    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogparExpression = "<_kv/kv_map/#/.>";
    event = R"(keyX#valueX)";
    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogparExpression = "<_kv/kv_map/'/.>";
    event = R"(keyX'valueX)";
    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogparExpression = "<_kv/kv_map/^/.>";
    event = R"(keyX^valueX)";
    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogparExpression = "<_kv/kv_map/:=/.>";
    event = R"(keyX:=valueX)";
    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogparExpression = "<_kv/kv_map/_:.-,.|/ >";
    event = R"(keyX_:.-,.|valueX)";
    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, singleKVPairMatchTestEndCharacter)
{
    const auto expectedResult {R"({"keyX":"valueX"})"};

    string customLogparExpression {"<_kv/kv_map/:/ >."};
    string event {R"(keyX:valueX.)"};
    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogparExpression = "<_kv/kv_map/:/ >,";
    event = R"(keyX:valueX,)";
    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogparExpression = "<_kv/kv_map/:/ >|";
    event = R"(keyX:valueX|)";
    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogparExpression = "<_kv/kv_map/:/ >-";
    event = R"(keyX:valueX-)";
    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogparExpression = "<_kv/kv_map/:/ >!";
    event = R"(keyX:valueX!)";
    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogparExpression = "<_kv/kv_map/:/ >#";
    event = R"(keyX:valueX#)";
    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogparExpression = "<_kv/kv_map/:/ >;";
    event = R"(keyX:valueX;)";
    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, singleKVPairMatchCaseI)
{
    const char* event {R"(keyX:valueX)"};

    ASSERT_NO_THROW(op = getParserOp(defaultLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"keyX":"valueX"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, singleKVPairMatchCaseII)
{
    const char* customLogparExpression {R"("<_kv/kv_map/:/ >")"};
    const char* event {R"("keyX:valueX")"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"keyX":"valueX"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, singleKVPairMatchCaseIII)
{
    const char* customLogparExpression {R"(<_kv/kv_map/:/ >;)"};
    const char* event {R"(keyX:valueX;)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"keyX":"valueX"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, singleKVPairMatchCaseIV)
{
    const char* customLogparExpression {R"(<_kv/kv_map/:/ >;)"};
    const char* event {R"(keyX:valueX;)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"keyX":"valueX"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, singleKVPairMatchCaseV)
{
    const char* customLogparExpression {R"(<_kv/kv_map/:/ >;)"};
    const char* event {R"(keyX:"valueX;";)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"keyX":"valueX;"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, singleKVPairMatchCaseVI)
{
    const char* customLogparExpression {R"(<_kv/kv_map/:/ >;)"};
    const char* event {R"(keyX:"valueX;";)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"keyX":"valueX;"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, singleKVPairMatchCaseVII)
{
    const char* customLogparExpression {R"(<_kv/kv_map/: / >;)"};
    const char* event {R"(keyX: ": valueX;";)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"keyX":": valueX;"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, twoKVPairsMatch)
{
    const char* event {R"(key1:value1 key2:value2)"};

    ASSERT_NO_THROW(op = getParserOp(defaultLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value1","key2":"value2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, threeKVPairsMatch)
{
    const char* event {R"(key1:value1 key2:value2 key3:value3)"};

    ASSERT_NO_THROW(op = getParserOp(defaultLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value1","key2":"value2","key3":"value3"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, singleKVPairMultipleCharKVSeparatorMatchCaseI)
{
    const char* customLogparExpression {"<_kv/kv_map/: /,>"};
    const char* event {R"(keyX: valueX)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"keyX":"valueX"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, singleKVPairMultipleCharKVSeparatorMatchCaseII)
{
    const char* customLogparExpression {"<_kv/kv_map/: / >"};
    const char* event {R"(keyX: valueX)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"keyX":"valueX"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, singleKVPairMultipleCharKVSeparatorMatchCaseIII)
{
    const char* customLogparExpression {"<_kv/kv_map/: / >"};
    const char* event {R"(keyX: valueX )"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, singleKVPairMultipleCharKVSeparatorMatchCaseIV)
{
    const char* customLogparExpression {"<_kv/kv_map/: /,>;"};
    const char* event {R"(keyX: valueX;)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"keyX":"valueX"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, singleKVPairMultipleCharKVSeparatorMatchCaseV)
{
    const char* customLogparExpression {"<_kv/kv_map/: /,>;"};
    const char* event {R"(keyX: valueX)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, singleKVPairMultipleCharKVSeparatorMatchCaseVI)
{
    const char* customLogparExpression {"<_kv/kv_map/: /,>"};
    const char* event {R"(keyX:valueX)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, singleKVPairMultipleCharKVSeparatorMatchCaseVII)
{
    const char* customLogparExpression {"<_kv/kv_map/: / >"};
    const char* event {R"(keyX: valueX )"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, twoKVPairsMultipleCharKVSeparatorMatchCaseI)
{
    const char* customLogparExpression {"<_kv/kv_map/: /,>"};
    const char* event {R"(key1: value1,key2: value2)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value1","key2":"value2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, twoKVPairsMultipleCharKVSeparatorMatchCaseII)
{
    const char* customLogparExpression {"<_kv/kv_map/: / >"};
    const char* event {R"(key1: value1 key2: value2)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value1","key2":"value2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, twoKVPairsMultipleCharKVSeparatorMatchCaseIII)
{
    const char* customLogparExpression {"<_kv/kv_map/: / >"};
    const char* event {R"(key1: value1 key2: value2 )"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, twoKVPairMultipleCharKVSeparatorMatchCaseIV)
{
    const char* customLogparExpression {"<_kv/kv_map/: /,>;"};
    const char* event {R"(key1: value1,key2: value2;)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value1","key2":"value2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, twoKVPairsMultipleCharKVSeparatorMatchCaseV)
{
    const char* customLogparExpression {"<_kv/kv_map/: /,>;"};
    const char* event {R"(key1: value1,key2: value2)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, twoKVPairsMultipleCharKVSeparatorMatchCaseVI)
{
    const char* customLogparExpression {"<_kv/kv_map/: /,>"};
    const char* event {R"(key1:value1,key2:value2)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, twoKVPairMultipleCharKVSeparatorMatchCaseVII)
{
    const char* customLogparExpression {"<_kv/kv_map/: / >"};
    const char* event {R"(key1: value1 key2: value2 )"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, singleKVPairNoMatchGivenEndString)
{
    const char* customLogparExpression {"<_kv/kv_map/:/ >."};
    const char* event {R"(keyX:valueX)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, twoKVPairsNoMatchGivenEndString)
{
    const char* customLogparExpression {"<_kv/kv_map/:/ >."};
    const char* event {R"(key1:value1 key2:value2)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, threeKVPairsNoMatchGivenEndString)
{
    const char* customLogparExpression {"<_kv/kv_map/:/ >."};
    const char* event {R"(key1:value1 key2:value2 key3:value3)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, singleKVPairNoMatchGivenKVSeparator)
{
    const char* customLogparExpression {"<_kv/kv_map/=/ >"};
    const char* event {R"(keyX:valueX)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, twoKVPairsNoMatchGivenKVSeparator)
{
    const char* customLogparExpression {"<_kv/kv_map/=/ >"};
    const char* event {R"(key1:value1 key2:value2)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, threeKVPairsNoMatchGivenKVSeparator)
{
    const char* customLogparExpression {"<_kv/kv_map/=/ >"};
    const char* event {R"(key1:value1 key2:value2 key3:value3)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, noEndStringCaseI)
{
    const char* customLogparExpression {"<_kv/kv_map/:/ >."};
    const char* event {R"(keyX:valueX)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, noEndStringCaseII)
{
    const char* customLogparExpression {"<_kv/kv_map/:/ >."};
    const char* event {R"(keyX: valueX)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, noEndStringCaseIII)
{
    const char* customLogparExpression {"<_kv/kv_map/:/ >."};
    const char* event {R"(keyX: )"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, noEndStringCaseIV)
{
    const char* customLogparExpression {"<_kv/kv_map/:/ >."};
    const char* event {R"(keyX:)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, noEndStringCaseV)
{
    const char* customLogparExpression {"<_kv/kv_map/:/ >."};
    const char* event {R"(keyX)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, noEndStringCaseVI)
{
    const char* customLogparExpression {"<_kv/kv_map/:/ >."};
    const char* event {R"(: )"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, noEndStringCaseVII)
{
    const char* customLogparExpression {"<_kv/kv_map/:/ >."};
    const char* event {R"(:)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, noEndStringCaseVIII)
{
    const char* customLogparExpression {"<_kv/kv_map/:/ >."};
    const char* event {R"(: value)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, noPairSeparatorFoundCaseI)
{
    const char* event {R"(key1:value1,key2:value2)"};

    ASSERT_NO_THROW(op = getParserOp(defaultLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value1,key2:value2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, noPairSeparatorFoundCaseII)
{
    const char* event {R"(key1:value1,key2:value2,key3:value3)"};

    ASSERT_NO_THROW(op = getParserOp(defaultLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value1,key2:value2,key3:value3"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, noPairSeparatorFoundCaseIII)
{
    const char* event {R"(key1:value1,key2:value2,key3:value3)"};

    ASSERT_NO_THROW(op = getParserOp(defaultLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value1,key2:value2,key3:value3"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseI)
{
    const char* event {R"(keyX:valueX;)"};

    ASSERT_NO_THROW(op = getParserOp(defaultLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"keyX":"valueX;"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseII)
{
    const char* customLogparExpression {"<_kv/kv_map/:/ >;"};
    const char* event {R"(keyX:valueX;)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"keyX":"valueX"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseIII)
{
    const char* customLogparExpression {"<_kv/kv_map/: / >;"};
    const char* event {R"(keyX:;)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, generalCaseIV)
{
    const char* customLogparExpression {"<_kv/kv_map/:/,>,"};
    const char* event {R"(key1:value1,key2:value2,)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value1","key2":"value2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseV)
{
    const char* customLogparExpression {"<_kv/kv_map/:/,>,"};
    const char* event {R"(key1:value1,key2:value2,)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value1","key2":"value2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseVI)
{
    const char* customLogparExpression {"<_kv/kv_map/:/,>"};
    const char* event {R"(key1:value:1)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value:1"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseVII)
{
    const char* customLogparExpression {"<_kv/kv_map/:/,>"};
    const char* event {R"(key1::value1)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":":value1"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseVIII)
{
    const char* customLogparExpression {"<_kv/kv_map/:/,>"};
    const char* event {R"(key1:value:1,key2:value:2)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value:1","key2":"value:2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseIX)
{
    const char* customLogparExpression {"<_kv/kv_map/:/,>"};
    const char* event {R"(key1::value1,key2::value2)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":":value1","key2":":value2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseX)
{
    const char* customLogparExpression {"<_kv/kv_map/:/,>;"};
    const char* event {R"(key1::value1,key2::value2;)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":":value1","key2":":value2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseXI)
{
    const char* customLogparExpression {"<_kv/kv_map/: / >"};
    const char* event {R"(key1: "value 1" key2: "value 2")"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value 1","key2":"value 2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseXII)
{
    const char* customLogparExpression {"<_kv/kv_map/: / >;"};
    const char* event {R"(key1: "value 1" key2: "value 2";)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value 1","key2":"value 2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseXIII)
{
    const char* customLogparExpression {"<_kv/kv_map/: /,>"};
    const char* event {R"(key1: value 1,key2: value 2)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value 1","key2":"value 2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseXIV)
{
    const char* customLogparExpression {"<_kv/kv_map/: /,>"};
    const char* event {R"(key1: "value 1",key2: value 2)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value 1","key2":"value 2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseXV)
{
    const char* customLogparExpression {"<_kv/kv_map/: / >"};
    const char* event {R"(key1: "value 1" key2: "value 2")"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value 1","key2":"value 2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseXVI)
{
    const char* customLogparExpression {"<_kv/kv_map/: /,>;"};
    const char* event {R"(key1: "value 1,key2: value2",key3: value3;)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value 1,key2: value2","key3":"value3"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseXVII)
{
    const char* customLogparExpression {"<_kv/kv_map/: /, >;"};
    const char* event {R"(key1: "value 1,key2: value2", key3: value3;)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value 1,key2: value2","key3":"value3"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseXVIII)
{
    const char* customLogparExpression {"<_kv/kv_map/=/ >"};
    const char* event {
        R"(key1=value1 key2=value2 key3="key4=value4 key5=value5 key6=value6")"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(
        R"({"key1":"value1","key2":"value2","key3":"key4=value4 key5=value5 key6=value6"})",
        any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseXIX)
{
    const char* customLogparExpression {"<_kv/kv_map/=/ >"};
    const char* event {R"(key1= key2=value2)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":null,"key2":"value2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseXX)
{
    const char* customLogparExpression {"<_kv/kv_map/=/ >"};
    const char* event {R"(key1= key2="" key3=)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":null,"key2":null,"key3":null})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

/* -------------------- START OF MULTIPLE MAPPING CASES -------------------- */

TEST(parseKVMap, multipleMappingCaseI)
{
    const char* customLogparExpression {"<_kv1/kv_map/:/ >|<_kv2/kv_map/:/ >"};
    const char* event {R"(key1:value1 key2:value2|key3:value3 key4:value4)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value1","key2":"value2"})",
                 any_cast<JsonString>(result["_kv1"]).jsonString.data());

    ASSERT_STREQ(R"({"key3":"value3","key4":"value4"})",
                 any_cast<JsonString>(result["_kv2"]).jsonString.data());
}

TEST(parseKVMap, multipleMappingCaseII)
{
    const char* customLogparExpression {"<_kv1/kv_map/:/ >  <_kv2/kv_map/:/ >"};
    const char* event {R"(key1:value1 key2:value2  key3:value3 key4:value4)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value1","key2":"value2"})",
                 any_cast<JsonString>(result["_kv1"]).jsonString.data());

    ASSERT_STREQ(R"({"key3":"value3","key4":"value4"})",
                 any_cast<JsonString>(result["_kv2"]).jsonString.data());
}

TEST(parseKVMap, multipleMappingCaseIII)
{
    const char* customLogparExpression {"<_kv1/kv_map/: / > --- <_kv2/kv_map/=/, >"};
    const char* event {
        R"(key1: value=1 key2: "value, 2" --- key3=value 3, key4=value: 4)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value=1","key2":"value, 2"})",
                 any_cast<JsonString>(result["_kv1"]).jsonString.data());

    ASSERT_STREQ(R"({"key3":"value 3","key4":"value: 4"})",
                 any_cast<JsonString>(result["_kv2"]).jsonString.data());
}

TEST(parseKVMap, multipleMappingCaseIV)
{
    const char* customLogparExpression {
        "<_kv1/kv_map/:/,> <_kv2/kv_map/=/:>, <_kv3/kv_map/: / >"};
    const char* event {
        R"(key1:value1,key2:value2 key3=value3:key4=value4, key5: value5 key6: value6)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value1","key2":"value2"})",
                 any_cast<JsonString>(result["_kv1"]).jsonString.data());

    ASSERT_STREQ(R"({"key3":"value3","key4":"value4"})",
                 any_cast<JsonString>(result["_kv2"]).jsonString.data());

    ASSERT_STREQ(R"({"key5":"value5","key6":"value6"})",
                 any_cast<JsonString>(result["_kv3"]).jsonString.data());
}

/* --------------------- END OF MULTIPLE MAPPING CASES --------------------- */

/* ------------------------ START OF NULL KEY CASES ------------------------ */

TEST(parseKVMap, nullKeyCaseI)
{
    const char* customLogparExpression {"<_kv/kv_map/: / >;"};
    const char* event {R"(: ;)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, nullKeyCaseII)
{
    const char* customLogparExpression {"<_kv/kv_map/: / >;"};
    const char* event {R"(: valueX;)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, nullKeyCaseIII)
{
    const char* customLogparExpression {"<_kv/kv_map/: / >"};
    const char* event {R"(: valueX)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, nullKeyCaseIV)
{
    const char* customLogparExpression {"<_kv/kv_map/:/ >"};
    const char* event {R"(:valueX)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, nullKeyCaseV)
{
    const char* customLogparExpression {"<_kv/kv_map/:/,>"};
    const char* event {R"(key1:value1,:value2)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, nullKeyCaseVI)
{
    const char* customLogparExpression {"<_kv/kv_map/:/,>"};
    const char* event {R"(key1:value1,key2:value2,:value3)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, nullKeyCaseVII)
{
    const char* customLogparExpression {"<_kv/kv_map/:/,>"};
    const char* event {R"(key1:value1,key2:value2,value3)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, nullKeyCaseVIII)
{
    const char* customLogparExpression {"<_kv/kv_map/:/,>"};
    const char* event {R"(key1:value1,key2:value2,:)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, nullKeyCaseIX)
{
    const char* customLogparExpression {"<_kv/kv_map/:/ >"};
    const char* event {R"(key1:value1 key2:value2 : )"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, nullKeyCaseX)
{
    const char* customLogparExpression {"<_kv1/kv_map/:/,> <_kv2/kv_map/:/,>"};
    const char* event {R"(key1:value1 key2:value2,:)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, nullKeyCaseXI)
{
    const char* customLogparExpression {"<_kv1/kv_map/:/,> <_kv2/kv_map/:/,>"};
    const char* event {R"(key1:value1,:value2 key3:value3,key4:value4)"};

    ASSERT_NO_THROW(op = getParserOp(customLogparExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

/* ------------------------- END OF NULL KEY CASES ------------------------- */
