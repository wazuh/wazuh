#include <any>
#include <vector>

#include <gtest/gtest.h>
#include <hlp/hlp.hpp>

using namespace hlp;

using std::any_cast;
using std::string;

TEST(parseIgnore, build)
{
    ASSERT_NO_THROW(getParserOp("<~test/ignore/wazuh>"));
}

TEST(parseIgnore, success_repeat_spaces)
{
    const char* logpar = "<~custom/ignore/ >wazuh";
    const char* event = "              wazuh";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(R"(              )",
                 std::any_cast<std::string>(result["~custom"]).c_str());
}

TEST(parseIgnore, only_underscore)
{
    const char* logpar = "<~/ignore/nothing>wazuh";
    const char* event = "123456wazuh";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_FALSE(ret);
}

TEST(parseIgnore, double_ignore)
{
    const char* logpar = "<~/ignore/wazuh >hi!";
    const char* event = "wazuh wazuh wazuh wazuh wazuh wazuh hi!";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(R"(wazuh wazuh wazuh wazuh wazuh wazuh )",
                 std::any_cast<std::string>(result.at("~")).c_str());
}

TEST(parseIgnore, nothing_to_ignore)
{
    const char* logpar = "<~/ignore/wazuh>hi!";
    const char* event = "hi!";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(R"()", std::any_cast<std::string>(result.at("~")).c_str());
}

TEST(parseIgnore, ignore_end_token)
{
    const char* logpar = ".<~/ignore/word>";
    const char* event = ".326";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_FALSE(ret);
}

TEST(parseIgnore, ignore_end_string)
{
    const char* logpar = ".<~/ignore/326>hi";
    const char* event = ".326hi";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(R"(326)", std::any_cast<std::string>(result.at("~")).c_str());
}

TEST(parseIgnore, ignore_not_ignore)
{
    const char* logpar = "<~timestamp/SYSLOG>.<~/ignore/number>326";
    const char* event = "Feb 14 09:40:10.326";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(R"()", std::any_cast<std::string>(result.at("~")).c_str());
}

TEST(parseIgnore, without_args)
{
    const char* logpar = "<~/ignore>.<~empty/ignore>";
    const char* event = "Feb 14 09:40:10.326";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(R"(326)", std::any_cast<std::string>(result["~empty"]).c_str());
    ASSERT_STREQ(R"(Feb 14 09:40:10)",
                 std::any_cast<std::string>(result.at("~")).c_str());
}

TEST(parseIgnore, without_args_follow_eos)
{
    const char* logpar = "<~/ignore>";
    const char* event = "Feb 14 09:40:10.326";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(R"(Feb 14 09:40:10.326)",
                 std::any_cast<std::string>(result.at("~")).c_str());
}

TEST(parseIgnore, without_args_fail)
{
    const char* logpar = "<~/ignore>w";
    const char* event = "nop";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_FALSE(ret);
}

TEST(parseIgnore, ignore_until_next_token)
{
    const char* logpar = "<~/ignore>w";
    const char* event = "nopw";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(R"(nop)", std::any_cast<std::string>(result.at("~")).c_str());
}
