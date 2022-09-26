#include <any>
#include <vector>

#include <gtest/gtest.h>
#include <hlp/hlp.hpp>

using namespace hlp;

using std::any_cast;
using std::string;

TEST(parseIgnore, build)
{
    ASSERT_NO_THROW(getParserOp("<_test/ignore/wazuh>"));
}

TEST(parseIgnore, success_repeat_spaces)
{
    const char* logQl = "<_custom/ignore/ >wazuh";
    const char* event = "              wazuh";

    ParserFn parseOp = getParserOp(logQl);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(R"(              )",
                 std::any_cast<std::string>(result["_custom"]).c_str());
}

TEST(parseIgnore, only_underscore)
{
    const char* logQl = "<_/ignore/nothing>wazuh";
    const char* event = "123456wazuh";

    ParserFn parseOp = getParserOp(logQl);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_FALSE(ret);
}

TEST(parseIgnore, double_ignore)
{
    const char* logQl = "<_/ignore/wazuh >hi!";
    const char* event = "wazuh wazuh wazuh wazuh wazuh wazuh hi!";

    ParserFn parseOp = getParserOp(logQl);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(R"(wazuh wazuh wazuh wazuh wazuh wazuh )",
                 std::any_cast<std::string>(result.at("_")).c_str());
}

TEST(parseIgnore, nothing_to_ignore)
{
    const char* logQl = "<_/ignore/wazuh>hi!";
    const char* event = "hi!";

    ParserFn parseOp = getParserOp(logQl);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(R"()", std::any_cast<std::string>(result.at("_")).c_str());
}

TEST(parseIgnore, ignore_end_token)
{
    const char* logQl = ".<_/ignore/word>";
    const char* event = ".326";

    ParserFn parseOp = getParserOp(logQl);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_FALSE(ret);
}

TEST(parseIgnore, ignore_end_string)
{
    const char* logQl = ".<_/ignore/326>hi";
    const char* event = ".326hi";

    ParserFn parseOp = getParserOp(logQl);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(R"(326)", std::any_cast<std::string>(result.at("_")).c_str());
}

TEST(parseIgnore, ignore_not_ignore)
{
    const char* logQl = "<timestamp/SYSLOG>.<_/ignore/number>326";
    const char* event = "Feb 14 09:40:10.326";

    ParserFn parseOp = getParserOp(logQl);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(R"()", std::any_cast<std::string>(result.at("_")).c_str());
}

TEST(parseIgnore, without_args)
{
    const char* logQl = "<_/ignore>.<_empty/ignore>";
    const char* event = "Feb 14 09:40:10.326";

    ParserFn parseOp = getParserOp(logQl);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(R"(326)", std::any_cast<std::string>(result["_empty"]).c_str());
    ASSERT_STREQ(R"(Feb 14 09:40:10)",
                 std::any_cast<std::string>(result.at("_")).c_str());
}

TEST(parseIgnore, without_args_follow_eos)
{
    const char* logQl = "<_/ignore>";
    const char* event = "Feb 14 09:40:10.326";

    ParserFn parseOp = getParserOp(logQl);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(R"(Feb 14 09:40:10.326)",
                 std::any_cast<std::string>(result.at("_")).c_str());
}

TEST(parseIgnore, without_args_fail)
{
    const char* logQl = "<_/ignore>w";
    const char* event = "nop";

    ParserFn parseOp = getParserOp(logQl);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_FALSE(ret);
}

TEST(parseIgnore, ignore_until_next_token)
{
    const char* logQl = "<_/ignore>w";
    const char* event = "nopw";

    ParserFn parseOp = getParserOp(logQl);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(R"(nop)", std::any_cast<std::string>(result.at("_")).c_str());
}
