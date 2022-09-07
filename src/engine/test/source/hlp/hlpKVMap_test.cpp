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

const char* defaultLogQLExpression {"<_kv/kv_map/:/ >"};

TEST(parseKVMap, build)
{
    ASSERT_NO_THROW(getParserOp(defaultLogQLExpression));
}

TEST(parseKVMap, buildNoArgumentsError)
{
    const char* customLogQLExpression {"<_kv/kv_map>"};

    ASSERT_THROW(getParserOp(customLogQLExpression), std::runtime_error);
}

// TODO: Throw message when no target field is set
TEST(parseKVMap, buildNoTargetError)
{
    GTEST_SKIP();

    const char* customLogQLExpression {"</kv_map/=/ >"};

    ASSERT_THROW(getParserOp(customLogQLExpression), std::runtime_error);
}

// TODO: Throw message when no parser is set
TEST(parseKVMap, buildNoParserError)
{
    GTEST_SKIP();

    const char* customLogQLExpression {"<_kv//=/ >"};

    ASSERT_THROW(getParserOp(customLogQLExpression), std::runtime_error);
}

TEST(parseKVMap, buildNoKVSeparatorError)
{
    const char* customLogQLExpression {"<_kv/kv_map// >"};

    ASSERT_THROW(getParserOp(customLogQLExpression), std::runtime_error);
}

TEST(parseKVMap, buildNoPairsSeparatorError)
{
    const char* customLogQLExpression {"<_kv/kv_map/=/>"};

    ASSERT_THROW(getParserOp(customLogQLExpression), std::runtime_error);
}

TEST(parseKVMap, buildSameSeparatorError)
{
    const char* customLogQLExpression {"<_kv/kv_map/=/=>"};

    ASSERT_THROW(getParserOp(customLogQLExpression), std::runtime_error);
}

TEST(parseKVMap, buildNoEndString)
{
    const char* customLogQLExpression {"<_kv/kv_map/=/ >"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));
}

TEST(parseKVMap, singleKVPairMatchTestKVSeparators)
{
    const auto expectedResult {R"({"keyX":"valueX"})"};

    string customLogQLExpression {"<_kv/kv_map/:/,>"};
    string event {R"(keyX:valueX)"};
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogQLExpression = "<_kv/kv_map/=/,>";
    event = R"(keyX=valueX)";
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogQLExpression = "<_kv/kv_map/|/,>";
    event = R"(keyX|valueX)";
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogQLExpression = "<_kv/kv_map/-/,>";
    event = R"(keyX-valueX)";
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogQLExpression = "<_kv/kv_map/./,>";
    event = R"(keyX.valueX)";
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogQLExpression = "<_kv/kv_map/,/.>";
    event = R"(keyX,valueX)";
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogQLExpression = "<_kv/kv_map/_/.>";
    event = R"(keyX_valueX)";
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogQLExpression = "<_kv/kv_map/#/.>";
    event = R"(keyX#valueX)";
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogQLExpression = "<_kv/kv_map/'/.>";
    event = R"(keyX'valueX)";
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogQLExpression = "<_kv/kv_map/^/.>";
    event = R"(keyX^valueX)";
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogQLExpression = "<_kv/kv_map/:=/.>";
    event = R"(keyX:=valueX)";
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogQLExpression = "<_kv/kv_map/_:.-,.|/ >";
    event = R"(keyX_:.-,.|valueX)";
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, singleKVPairMatchTestEndCharacter)
{
    const auto expectedResult {R"({"keyX":"valueX"})"};

    string customLogQLExpression {"<_kv/kv_map/:/ >."};
    string event {R"(keyX:valueX.)"};
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogQLExpression = "<_kv/kv_map/:/ >,";
    event = R"(keyX:valueX,)";
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogQLExpression = "<_kv/kv_map/:/ >|";
    event = R"(keyX:valueX|)";
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogQLExpression = "<_kv/kv_map/:/ >-";
    event = R"(keyX:valueX-)";
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogQLExpression = "<_kv/kv_map/:/ >!";
    event = R"(keyX:valueX!)";
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogQLExpression = "<_kv/kv_map/:/ >#";
    event = R"(keyX:valueX#)";
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());

    customLogQLExpression = "<_kv/kv_map/:/ >;";
    event = R"(keyX:valueX;)";
    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));
    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);
    ASSERT_STREQ(expectedResult, any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, singleKVPairMatchCaseI)
{
    const char* event {R"(keyX:valueX)"};

    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"keyX":"valueX"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, singleKVPairMatchCaseII)
{
    const char* customLogQLExpression {R"("<_kv/kv_map/:/ >")"};
    const char* event {R"("keyX:valueX")"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"keyX":"valueX"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, singleKVPairMatchCaseIII)
{
    const char* customLogQLExpression {R"(<_kv/kv_map/:/ >;)"};
    const char* event {R"(keyX:valueX;)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"keyX":"valueX"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, singleKVPairMatchCaseIV)
{
    const char* customLogQLExpression {R"(<_kv/kv_map/:/ >;)"};
    const char* event {R"(keyX:valueX;)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"keyX":"valueX"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, singleKVPairMatchCaseV)
{
    const char* customLogQLExpression {R"(<_kv/kv_map/:/ >;)"};
    const char* event {R"(keyX:"valueX;";)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"keyX":"valueX;"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, singleKVPairMatchCaseVI)
{
    const char* customLogQLExpression {R"(<_kv/kv_map/:/ >;)"};
    const char* event {R"(keyX:"valueX;";)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"keyX":"valueX;"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, singleKVPairMatchCaseVII)
{
    const char* customLogQLExpression {R"(<_kv/kv_map/: / >;)"};
    const char* event {R"(keyX: ": valueX;";)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"keyX":": valueX;"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, twoKVPairsMatch)
{
    const char* event {R"(key1:value1 key2:value2)"};

    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value1","key2":"value2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, threeKVPairsMatch)
{
    const char* event {R"(key1:value1 key2:value2 key3:value3)"};

    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value1","key2":"value2","key3":"value3"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, singleKVPairMultipleCharKVSeparatorMatchCaseI)
{
    const char* customLogQLExpression {"<_kv/kv_map/: /,>"};
    const char* event {R"(keyX: valueX)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"keyX":"valueX"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, singleKVPairMultipleCharKVSeparatorMatchCaseII)
{
    const char* customLogQLExpression {"<_kv/kv_map/: / >"};
    const char* event {R"(keyX: valueX)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"keyX":"valueX"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, singleKVPairMultipleCharKVSeparatorMatchCaseIII)
{
    const char* customLogQLExpression {"<_kv/kv_map/: / >"};
    const char* event {R"(keyX: valueX )"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, singleKVPairMultipleCharKVSeparatorMatchCaseIV)
{
    const char* customLogQLExpression {"<_kv/kv_map/: /,>;"};
    const char* event {R"(keyX: valueX;)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"keyX":"valueX"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, singleKVPairMultipleCharKVSeparatorMatchCaseV)
{
    const char* customLogQLExpression {"<_kv/kv_map/: /,>;"};
    const char* event {R"(keyX: valueX)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, singleKVPairMultipleCharKVSeparatorMatchCaseVI)
{
    const char* customLogQLExpression {"<_kv/kv_map/: /,>"};
    const char* event {R"(keyX:valueX)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, singleKVPairMultipleCharKVSeparatorMatchCaseVII)
{
    const char* customLogQLExpression {"<_kv/kv_map/: / >"};
    const char* event {R"(keyX: valueX )"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, twoKVPairsMultipleCharKVSeparatorMatchCaseI)
{
    const char* customLogQLExpression {"<_kv/kv_map/: /,>"};
    const char* event {R"(key1: value1,key2: value2)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value1","key2":"value2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, twoKVPairsMultipleCharKVSeparatorMatchCaseII)
{
    const char* customLogQLExpression {"<_kv/kv_map/: / >"};
    const char* event {R"(key1: value1 key2: value2)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value1","key2":"value2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, twoKVPairsMultipleCharKVSeparatorMatchCaseIII)
{
    const char* customLogQLExpression {"<_kv/kv_map/: / >"};
    const char* event {R"(key1: value1 key2: value2 )"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, twoKVPairMultipleCharKVSeparatorMatchCaseIV)
{
    const char* customLogQLExpression {"<_kv/kv_map/: /,>;"};
    const char* event {R"(key1: value1,key2: value2;)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value1","key2":"value2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, twoKVPairsMultipleCharKVSeparatorMatchCaseV)
{
    const char* customLogQLExpression {"<_kv/kv_map/: /,>;"};
    const char* event {R"(key1: value1,key2: value2)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, twoKVPairsMultipleCharKVSeparatorMatchCaseVI)
{
    const char* customLogQLExpression {"<_kv/kv_map/: /,>"};
    const char* event {R"(key1:value1,key2:value2)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, twoKVPairMultipleCharKVSeparatorMatchCaseVII)
{
    const char* customLogQLExpression {"<_kv/kv_map/: / >"};
    const char* event {R"(key1: value1 key2: value2 )"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, singleKVPairNoMatchGivenEndString)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/ >."};
    const char* event {R"(keyX:valueX)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, twoKVPairsNoMatchGivenEndString)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/ >."};
    const char* event {R"(key1:value1 key2:value2)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, threeKVPairsNoMatchGivenEndString)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/ >."};
    const char* event {R"(key1:value1 key2:value2 key3:value3)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, singleKVPairNoMatchGivenKVSeparator)
{
    const char* customLogQLExpression {"<_kv/kv_map/=/ >"};
    const char* event {R"(keyX:valueX)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, twoKVPairsNoMatchGivenKVSeparator)
{
    const char* customLogQLExpression {"<_kv/kv_map/=/ >"};
    const char* event {R"(key1:value1 key2:value2)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, threeKVPairsNoMatchGivenKVSeparator)
{
    const char* customLogQLExpression {"<_kv/kv_map/=/ >"};
    const char* event {R"(key1:value1 key2:value2 key3:value3)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, noEndStringCaseI)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/ >."};
    const char* event {R"(keyX:valueX)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, noEndStringCaseII)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/ >."};
    const char* event {R"(keyX: valueX)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, noEndStringCaseIII)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/ >."};
    const char* event {R"(keyX: )"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, noEndStringCaseIV)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/ >."};
    const char* event {R"(keyX:)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, noEndStringCaseV)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/ >."};
    const char* event {R"(keyX)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, noEndStringCaseVI)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/ >."};
    const char* event {R"(: )"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, noEndStringCaseVII)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/ >."};
    const char* event {R"(:)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, noEndStringCaseVIII)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/ >."};
    const char* event {R"(: value)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, noPairSeparatorFoundCaseI)
{
    const char* event {R"(key1:value1,key2:value2)"};

    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value1,key2:value2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, noPairSeparatorFoundCaseII)
{
    const char* event {R"(key1:value1,key2:value2,key3:value3)"};

    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value1,key2:value2,key3:value3"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, noPairSeparatorFoundCaseIII)
{
    const char* event {R"(key1:value1,key2:value2,key3:value3)"};

    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value1,key2:value2,key3:value3"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseI)
{
    const char* event {R"(keyX:valueX;)"};

    ASSERT_NO_THROW(op = getParserOp(defaultLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"keyX":"valueX;"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseII)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/ >;"};
    const char* event {R"(keyX:valueX;)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"keyX":"valueX"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseIII)
{
    const char* customLogQLExpression {"<_kv/kv_map/: / >;"};
    const char* event {R"(keyX:;)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, generalCaseIV)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/,>,"};
    const char* event {R"(key1:value1,key2:value2,)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value1","key2":"value2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseV)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/,>,"};
    const char* event {R"(key1:value1,key2:value2,)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value1","key2":"value2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseVI)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/,>"};
    const char* event {R"(key1:value:1)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value:1"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseVII)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/,>"};
    const char* event {R"(key1::value1)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":":value1"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseVIII)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/,>"};
    const char* event {R"(key1:value:1,key2:value:2)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value:1","key2":"value:2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseIX)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/,>"};
    const char* event {R"(key1::value1,key2::value2)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":":value1","key2":":value2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseX)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/,>;"};
    const char* event {R"(key1::value1,key2::value2;)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":":value1","key2":":value2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseXI)
{
    const char* customLogQLExpression {"<_kv/kv_map/: / >"};
    const char* event {R"(key1: "value 1" key2: "value 2")"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value 1","key2":"value 2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseXII)
{
    const char* customLogQLExpression {"<_kv/kv_map/: / >;"};
    const char* event {R"(key1: "value 1" key2: "value 2";)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value 1","key2":"value 2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseXIII)
{
    const char* customLogQLExpression {"<_kv/kv_map/: /,>"};
    const char* event {R"(key1: value 1,key2: value 2)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value 1","key2":"value 2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseXIV)
{
    const char* customLogQLExpression {"<_kv/kv_map/: /,>"};
    const char* event {R"(key1: "value 1",key2: value 2)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value 1","key2":"value 2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseXV)
{
    const char* customLogQLExpression {"<_kv/kv_map/: / >"};
    const char* event {R"(key1: "value 1" key2: "value 2")"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value 1","key2":"value 2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseXVI)
{
    const char* customLogQLExpression {"<_kv/kv_map/: /,>;"};
    const char* event {R"(key1: "value 1,key2: value2",key3: value3;)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value 1,key2: value2","key3":"value3"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseXVII)
{
    const char* customLogQLExpression {"<_kv/kv_map/: /, >;"};
    const char* event {R"(key1: "value 1,key2: value2", key3: value3;)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":"value 1,key2: value2","key3":"value3"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseXVIII)
{
    const char* customLogQLExpression {"<_kv/kv_map/=/ >"};
    const char* event {
        R"(key1=value1 key2=value2 key3="key4=value4 key5=value5 key6=value6")"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(
        R"({"key1":"value1","key2":"value2","key3":"key4=value4 key5=value5 key6=value6"})",
        any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseXIX)
{
    const char* customLogQLExpression {"<_kv/kv_map/=/ >"};
    const char* event {R"(key1= key2=value2)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":null,"key2":"value2"})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

TEST(parseKVMap, generalCaseXX)
{
    const char* customLogQLExpression {"<_kv/kv_map/=/ >"};
    const char* event {R"(key1= key2="" key3=)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_TRUE(retVal);

    ASSERT_STREQ(R"({"key1":null,"key2":null,"key3":null})",
                 any_cast<JsonString>(result["_kv"]).jsonString.data());
}

/* -------------------- START OF MULTIPLE MAPPING CASES -------------------- */

TEST(parseKVMap, multipleMappingCaseI)
{
    const char* customLogQLExpression {"<_kv1/kv_map/:/ >|<_kv2/kv_map/:/ >"};
    const char* event {R"(key1:value1 key2:value2|key3:value3 key4:value4)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
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
    const char* customLogQLExpression {"<_kv1/kv_map/:/ >  <_kv2/kv_map/:/ >"};
    const char* event {R"(key1:value1 key2:value2  key3:value3 key4:value4)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
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
    const char* customLogQLExpression {"<_kv1/kv_map/: / > --- <_kv2/kv_map/=/, >"};
    const char* event {
        R"(key1: value=1 key2: "value, 2" --- key3=value 3, key4=value: 4)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
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
    const char* customLogQLExpression {
        "<_kv1/kv_map/:/,> <_kv2/kv_map/=/:>, <_kv3/kv_map/: / >"};
    const char* event {
        R"(key1:value1,key2:value2 key3=value3:key4=value4, key5: value5 key6: value6)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
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
    const char* customLogQLExpression {"<_kv/kv_map/: / >;"};
    const char* event {R"(: ;)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, nullKeyCaseII)
{
    const char* customLogQLExpression {"<_kv/kv_map/: / >;"};
    const char* event {R"(: valueX;)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, nullKeyCaseIII)
{
    const char* customLogQLExpression {"<_kv/kv_map/: / >"};
    const char* event {R"(: valueX)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, nullKeyCaseIV)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/ >"};
    const char* event {R"(:valueX)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, nullKeyCaseV)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/,>"};
    const char* event {R"(key1:value1,:value2)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, nullKeyCaseVI)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/,>"};
    const char* event {R"(key1:value1,key2:value2,:value3)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, nullKeyCaseVII)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/,>"};
    const char* event {R"(key1:value1,key2:value2,value3)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, nullKeyCaseVIII)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/,>"};
    const char* event {R"(key1:value1,key2:value2,:)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, nullKeyCaseIX)
{
    const char* customLogQLExpression {"<_kv/kv_map/:/ >"};
    const char* event {R"(key1:value1 key2:value2 : )"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, nullKeyCaseX)
{
    const char* customLogQLExpression {"<_kv1/kv_map/:/,> <_kv2/kv_map/:/,>"};
    const char* event {R"(key1:value1 key2:value2,:)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

TEST(parseKVMap, nullKeyCaseXI)
{
    const char* customLogQLExpression {"<_kv1/kv_map/:/,> <_kv2/kv_map/:/,>"};
    const char* event {R"(key1:value1,:value2 key3:value3,key4:value4)"};

    ASSERT_NO_THROW(op = getParserOp(customLogQLExpression));
    ASSERT_TRUE(static_cast<bool>(op));

    ASSERT_NO_THROW(retVal = op(event, result));
    ASSERT_FALSE(retVal);
}

/* ------------------------- END OF NULL KEY CASES ------------------------- */
