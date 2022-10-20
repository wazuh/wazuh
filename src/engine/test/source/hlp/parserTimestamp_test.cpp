#include <hlp/hlp.hpp>

#include <gtest/gtest.h>

#include <json/json.hpp>

using namespace hlp;

TEST(parseTimestamp, ansic)
{
    GTEST_SKIP();
    static const char* logpar = "[<_ts/timestamp/ANSIC>]";
    static const char* ansicTs = "[Mon Jan 2 15:04:05 2006]";
    static const char* ansimTs = "[Mon Jan 2 15:04:05.123456 2006]";

    auto parseOp = getParserOp(logpar);
    ParseResult result;
    bool ret = parseOp(ansicTs, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ(2006, std::any_cast<int>(result["_ts.year"]));
    ASSERT_EQ(1, std::any_cast<unsigned>(result["_ts.month"]));
    ASSERT_EQ(2, std::any_cast<unsigned>(result["_ts.day"]));
    ASSERT_EQ(15, std::any_cast<long>(result["_ts.hour"]));
    ASSERT_EQ(4, std::any_cast<long>(result["_ts.minutes"]));
    ASSERT_EQ(5, std::any_cast<double>(result["_ts.seconds"]));

    ParseResult resultMillis;
    ret = parseOp(ansimTs, resultMillis);
    ASSERT_EQ(2006, std::any_cast<int>(resultMillis["_ts.year"]));
    ASSERT_EQ(1, std::any_cast<unsigned>(resultMillis["_ts.month"]));
    ASSERT_EQ(2, std::any_cast<unsigned>(resultMillis["_ts.day"]));
    ASSERT_EQ(15, std::any_cast<long>(resultMillis["_ts.hour"]));
    ASSERT_EQ(4, std::any_cast<long>(resultMillis["_ts.minutes"]));
    ASSERT_EQ(5.123456, std::any_cast<double>(resultMillis["_ts.seconds"]));
}

TEST(parseTimestamp, apache)
{
    GTEST_SKIP();
    static const char* logpar = "[<_ts/timestamp/APACHE>]";
    static const char* apacheTs = "[Tue Feb 11 15:04:05 2020]";

    auto parseOp = getParserOp(logpar);
    ParseResult result;
    bool ret = parseOp(apacheTs, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ(2020, std::any_cast<int>(result["_ts.year"]));
    ASSERT_EQ(2, std::any_cast<unsigned>(result["_ts.month"]));
    ASSERT_EQ(11, std::any_cast<unsigned>(result["_ts.day"]));
    ASSERT_EQ(15, std::any_cast<long>(result["_ts.hour"]));
    ASSERT_EQ(4, std::any_cast<long>(result["_ts.minutes"]));
    ASSERT_EQ(5, std::any_cast<double>(result["_ts.seconds"]));
}

TEST(parseTimestamp, rfc1123)
{
    GTEST_SKIP();
    static const char* logpar = "[<_ts/timestamp/RFC1123>]";
    static const char* logparz = "[<_ts/timestamp/RFC1123Z>]";
    static const char* rfc1123Ts = "[Mon, 02 Jan 2006 15:04:05 MST]";
    static const char* rfc1123zTs = "[Mon, 02 Jan 2006 15:04:05 -0700]";

    auto parseOp = getParserOp(logpar);
    ParseResult result;
    bool ret = parseOp(rfc1123Ts, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ(2006, std::any_cast<int>(result["_ts.year"]));
    ASSERT_EQ(1, std::any_cast<unsigned>(result["_ts.month"]));
    ASSERT_EQ(2, std::any_cast<unsigned>(result["_ts.day"]));
    ASSERT_EQ(15, std::any_cast<long>(result["_ts.hour"]));
    ASSERT_EQ(4, std::any_cast<long>(result["_ts.minutes"]));
    ASSERT_EQ(5, std::any_cast<double>(result["_ts.seconds"]));

    auto parseOpz = getParserOp(logparz);
    ASSERT_EQ(true, static_cast<bool>(parseOpz));

    ParseResult resultz;
    ret = parseOpz(rfc1123zTs, resultz);

    ASSERT_EQ(2006, std::any_cast<int>(resultz["_ts.year"]));
    ASSERT_EQ(1, std::any_cast<unsigned>(resultz["_ts.month"]));
    ASSERT_EQ(2, std::any_cast<unsigned>(resultz["_ts.day"]));
    ASSERT_EQ(15, std::any_cast<long>(resultz["_ts.hour"]));
    ASSERT_EQ(4, std::any_cast<long>(resultz["_ts.minutes"]));
    ASSERT_EQ(5, std::any_cast<double>(resultz["_ts.seconds"]));
}

TEST(parseTimestamp, rfc3339)
{
    GTEST_SKIP();
    static const char* logpar = "[<_ts/timestamp/RFC3339>]";
    static const char* rfc3339Ts = "[2006-01-02T15:04:05Z07:00]";
    static const char* rfc3339nanoTs = "[2006-01-02T15:04:05.999999999Z07:00]";

    auto parseOp = getParserOp(logpar);
    ParseResult result;
    bool ret = parseOp(rfc3339Ts, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ(2006, std::any_cast<int>(result["_ts.year"]));
    ASSERT_EQ(1, std::any_cast<unsigned>(result["_ts.month"]));
    ASSERT_EQ(2, std::any_cast<unsigned>(result["_ts.day"]));
    ASSERT_EQ(15, std::any_cast<long>(result["_ts.hour"]));
    ASSERT_EQ(4, std::any_cast<long>(result["_ts.minutes"]));
    ASSERT_EQ(5, std::any_cast<double>(result["_ts.seconds"]));

    ParseResult resultNano;
    ret = parseOp(rfc3339nanoTs, resultNano);

    ASSERT_EQ(2006, std::any_cast<int>(resultNano["_ts.year"]));
    ASSERT_EQ(1, std::any_cast<unsigned>(resultNano["_ts.month"]));
    ASSERT_EQ(2, std::any_cast<unsigned>(resultNano["_ts.day"]));
    ASSERT_EQ(15, std::any_cast<long>(resultNano["_ts.hour"]));
    ASSERT_EQ(4, std::any_cast<long>(resultNano["_ts.minutes"]));
    ASSERT_EQ(5.999999999, std::any_cast<double>(resultNano["_ts.seconds"]));
}

TEST(parseTimestamp, rfc822)
{
    GTEST_SKIP();
    static const char* logpar = "[<_ts/timestamp/RFC822>]";
    static const char* logparz = "[<_ts/timestamp/RFC822Z>]";
    static const char* rfc822Ts = "[02 Jan 06 15:04 MST]";
    static const char* rfc822zTs = "[02 Jan 06 15:04 -0700]";

    auto parseOp = getParserOp(logpar);
    ParseResult result;
    bool ret = parseOp(rfc822Ts, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ(2006, std::any_cast<int>(result["_ts.year"]));
    ASSERT_EQ(1, std::any_cast<unsigned>(result["_ts.month"]));
    ASSERT_EQ(2, std::any_cast<unsigned>(result["_ts.day"]));
    ASSERT_EQ(15, std::any_cast<long>(result["_ts.hour"]));
    ASSERT_EQ(4, std::any_cast<long>(result["_ts.minutes"]));
    ASSERT_EQ(0, std::any_cast<double>(result["_ts.seconds"]));
    ASSERT_EQ("MST", std::any_cast<std::string>(result["_ts.timezone"]));

    auto parseOpz = getParserOp(logparz);
    ASSERT_EQ(true, static_cast<bool>(parseOpz));

    ParseResult resultz;
    ret = parseOpz(rfc822zTs, resultz);

    ASSERT_EQ(2006, std::any_cast<int>(resultz["_ts.year"]));
    ASSERT_EQ(1, std::any_cast<unsigned>(resultz["_ts.month"]));
    ASSERT_EQ(2, std::any_cast<unsigned>(resultz["_ts.day"]));
    ASSERT_EQ(15, std::any_cast<long>(resultz["_ts.hour"]));
    ASSERT_EQ(4, std::any_cast<long>(resultz["_ts.minutes"]));
    ASSERT_EQ(0, std::any_cast<double>(resultz["_ts.seconds"]));
    ASSERT_EQ("-0700", std::any_cast<std::string>(resultz["_ts.timezone"]));
}

TEST(parseTimestamp, rfc850)
{
    GTEST_SKIP();
    static const char* logpar = "[<_ts/timestamp/RFC850>]";
    static const char* rfc850Ts = "[Monday, 02-Jan-06 15:04:05 MST]";

    auto parseOp = getParserOp(logpar);
    ParseResult result;
    bool ret = parseOp(rfc850Ts, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ(2006, std::any_cast<int>(result["_ts.year"]));
    ASSERT_EQ(1, std::any_cast<unsigned>(result["_ts.month"]));
    ASSERT_EQ(2, std::any_cast<unsigned>(result["_ts.day"]));
    ASSERT_EQ(15, std::any_cast<long>(result["_ts.hour"]));
    ASSERT_EQ(4, std::any_cast<long>(result["_ts.minutes"]));
    ASSERT_EQ(5, std::any_cast<double>(result["_ts.seconds"]));
    ASSERT_EQ("MST", std::any_cast<std::string>(result["_ts.timezone"]));
}

TEST(parseTimestamp, ruby)
{
    GTEST_SKIP();
    static const char* logpar = "[<_ts/timestamp/RubyDate>]";
    static const char* rubyTs = "[Mon Jan 02 15:04:05 -0700 2006]";

    auto parseOp = getParserOp(logpar);
    ParseResult result;
    bool ret = parseOp(rubyTs, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ(2006, std::any_cast<int>(result["_ts.year"]));
    ASSERT_EQ(1, std::any_cast<unsigned>(result["_ts.month"]));
    ASSERT_EQ(2, std::any_cast<unsigned>(result["_ts.day"]));
    ASSERT_EQ(15, std::any_cast<long>(result["_ts.hour"]));
    ASSERT_EQ(4, std::any_cast<long>(result["_ts.minutes"]));
    ASSERT_EQ(5, std::any_cast<double>(result["_ts.seconds"]));
    ASSERT_EQ("-0700", std::any_cast<std::string>(result["_ts.timezone"]));
}

TEST(parseTimestamp, stamp)
{
    GTEST_SKIP();
    static const char* logpar = "[<_ts/timestamp/Stamp>]";
    static const char* stampTs = "[Jan 2 15:04:05]";
    static const char* stampmilliTs = "[Jan 2 15:04:05.000]";
    static const char* stampmicroTs = "[Jan 2 15:04:05.000000]";
    static const char* stampnanoTs = "[Jan 2 15:04:05.000000000]";

    auto parseOp = getParserOp(logpar);
    ParseResult result;
    bool ret = parseOp(stampTs, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ(1, std::any_cast<unsigned>(result["_ts.month"]));
    ASSERT_EQ(2, std::any_cast<unsigned>(result["_ts.day"]));
    ASSERT_EQ(15, std::any_cast<long>(result["_ts.hour"]));
    ASSERT_EQ(4, std::any_cast<long>(result["_ts.minutes"]));
    ASSERT_EQ(5, std::any_cast<double>(result["_ts.seconds"]));

    ParseResult resultMillis;
    ret = parseOp(stampmilliTs, resultMillis);
    ASSERT_EQ(1, std::any_cast<unsigned>(resultMillis["_ts.month"]));
    ASSERT_EQ(2, std::any_cast<unsigned>(resultMillis["_ts.day"]));
    ASSERT_EQ(15, std::any_cast<long>(resultMillis["_ts.hour"]));
    ASSERT_EQ(4, std::any_cast<long>(resultMillis["_ts.minutes"]));
    ASSERT_EQ(5, std::any_cast<double>(resultMillis["_ts.seconds"]));

    ParseResult resultMicros;
    ret = parseOp(stampmicroTs, resultMicros);
    ASSERT_EQ(1, std::any_cast<unsigned>(resultMicros["_ts.month"]));
    ASSERT_EQ(2, std::any_cast<unsigned>(resultMicros["_ts.day"]));
    ASSERT_EQ(15, std::any_cast<long>(resultMicros["_ts.hour"]));
    ASSERT_EQ(4, std::any_cast<long>(resultMicros["_ts.minutes"]));
    ASSERT_EQ(5, std::any_cast<double>(resultMicros["_ts.seconds"]));

    ParseResult resultNanos;
    ret = parseOp(stampnanoTs, resultNanos);
    ASSERT_EQ(1, std::any_cast<unsigned>(resultNanos["_ts.month"]));
    ASSERT_EQ(2, std::any_cast<unsigned>(resultNanos["_ts.day"]));
    ASSERT_EQ(15, std::any_cast<long>(resultNanos["_ts.hour"]));
    ASSERT_EQ(4, std::any_cast<long>(resultNanos["_ts.minutes"]));
    ASSERT_EQ(5, std::any_cast<double>(resultNanos["_ts.seconds"]));
}

TEST(parseTimestamp, Unix)
{
    GTEST_SKIP();
    static const char* logpar = "[<_ts/timestamp/UnixDate>]";
    static const char* unixTs = "[Mon Jan 2 15:04:05 MST 2006]";

    auto parseOp = getParserOp(logpar);
    ParseResult result;
    bool ret = parseOp(unixTs, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ(2006, std::any_cast<int>(result["_ts.year"]));
    ASSERT_EQ(1, std::any_cast<unsigned>(result["_ts.month"]));
    ASSERT_EQ(2, std::any_cast<unsigned>(result["_ts.day"]));
    ASSERT_EQ(15, std::any_cast<long>(result["_ts.hour"]));
    ASSERT_EQ(4, std::any_cast<long>(result["_ts.minutes"]));
    ASSERT_EQ(5, std::any_cast<double>(result["_ts.seconds"]));
}

TEST(parseTimestamp, Unix_fail)
{
    GTEST_SKIP();
    static const char* logpar = "[<_ts/timestamp/UnixDate>]";
    static const char* unixTs = "[Mon Jan 2 15:04:05 MST 1960]";

    auto parseOp = getParserOp(logpar);
    ASSERT_EQ(true, static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(unixTs, result);
    ASSERT_TRUE(result.empty());
}

TEST(parseTimestamp, specific_format)
{
    GTEST_SKIP();
    static const char* logpar = "[<_ts/timestamp>] - "
                                "[<_ansicTs/timestamp>] - "
                                "[<_unixTs/timestamp>] - "
                                "[<_stampTs/timestamp>]";
    static const char* event = "[Mon Jan 02 15:04:05 -0700 2006] - "
                               "[Mon Jan 2 15:04:05 2006] - "
                               "[Mon Jan 2 15:04:05 MST 2006] - "
                               "[Jan 2 15:04:05]";

    auto parseOp = getParserOp(logpar);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ(2006, std::any_cast<int>(result["_ts.year"]));
    ASSERT_EQ(1, std::any_cast<unsigned>(result["_ts.month"]));
    ASSERT_EQ(2, std::any_cast<unsigned>(result["_ts.day"]));
    ASSERT_EQ(15, std::any_cast<long>(result["_ts.hour"]));
    ASSERT_EQ(4, std::any_cast<long>(result["_ts.minutes"]));
    ASSERT_EQ(5, std::any_cast<double>(result["_ts.seconds"]));
    ASSERT_EQ("-0700", std::any_cast<std::string>(result["_ts.timezone"]));

    ASSERT_EQ(2006, std::any_cast<int>(result["_ansicTs.year"]));
    ASSERT_EQ(1, std::any_cast<unsigned>(result["_ansicTs.month"]));
    ASSERT_EQ(2, std::any_cast<unsigned>(result["_ansicTs.day"]));
    ASSERT_EQ(15, std::any_cast<long>(result["_ansicTs.hour"]));
    ASSERT_EQ(4, std::any_cast<long>(result["_ansicTs.minutes"]));
    ASSERT_EQ(5, std::any_cast<double>(result["_ansicTs.seconds"]));

    ASSERT_EQ(2006, std::any_cast<int>(result["_unixTs.year"]));
    ASSERT_EQ(1, std::any_cast<unsigned>(result["_unixTs.month"]));
    ASSERT_EQ(2, std::any_cast<unsigned>(result["_unixTs.day"]));
    ASSERT_EQ(15, std::any_cast<long>(result["_unixTs.hour"]));
    ASSERT_EQ(4, std::any_cast<long>(result["_unixTs.minutes"]));
    ASSERT_EQ(5, std::any_cast<double>(result["_unixTs.seconds"]));

    ASSERT_EQ(1, std::any_cast<unsigned>(result["_stampTs.month"]));
    ASSERT_EQ(2, std::any_cast<unsigned>(result["_stampTs.day"]));
    ASSERT_EQ(15, std::any_cast<long>(result["_stampTs.hour"]));
    ASSERT_EQ(4, std::any_cast<long>(result["_stampTs.minutes"]));
    ASSERT_EQ(5, std::any_cast<double>(result["_stampTs.seconds"]));
}

TEST(parseTimestamp, kitchen)
{
    GTEST_SKIP();
    static const char* logpar = "[<_ts/timestamp/Kitchen>]";
    static const char* kitchenTs = "[3:04AM]";
    auto parseOp = getParserOp(logpar);
    ParseResult result;
    bool ret = parseOp(kitchenTs, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ(3, std::any_cast<long>(result["_ts.hour"]));
    ASSERT_EQ(4, std::any_cast<long>(result["_ts.minutes"]));

    kitchenTs = "[3:04PM]";
    ret = parseOp(kitchenTs, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ(15, std::any_cast<long>(result["_ts.hour"]));
    ASSERT_EQ(4, std::any_cast<long>(result["_ts.minutes"]));
}

// {"POSTGRES", {"%Y-%m-%d %T %Z", "2021-02-14 10:45:33.257 UTC"}},
TEST(parseTimestamp, POSTGRES)
{
    const char* logpar =
        "[<timestamp/POSTGRES>] - [<_t/timestamp/POSTGRES_MS>] - "
        "(<postgresql.log.session_start_time/POSTGRES>) - "
        "[<_stamp/timestamp/POSTGRES_MS>] [<postgresql.log.session_start_time/POSTGRES>]";
    const char* event =
        "[2021-02-14 10:45:14 UTC] - [2021-02-14 10:45:14.123 UTC] - (2021-02-14 "
        "10:45:14 UTC) - [2021-02-14 10:45:14.123456 UTC] [2021-02-14 10:45:14 UTC]";

    auto parseOp = getParserOp(logpar);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(static_cast<bool>(parseOp));
}
