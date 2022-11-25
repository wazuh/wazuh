#include "fmt/format.h"
#include <gtest/gtest.h>
#include <hlp/hlp.hpp>
#include <optional>
#include <string>
#include <vector>
#include "run_test.hpp"


TEST(HLP2, BooleanParser)
{
    auto fn = [](bool in) -> json::Json {
        json::Json doc;
        doc.setBool(in);
        return doc;
    };
    std::vector<TestCase> testCases {
        TestCase {"true", true, {}, Options(), fn(true), 4},
        TestCase {"false", true, {}, Options(), fn(false), 5},
        TestCase {"true    ", true, {}, Options(), fn(true), 4},
        TestCase {"false    ", true, {}, Options(), fn(false), 5},
        TestCase {"    true", false, {}, Options(), {}, 0},
        TestCase {"    false", false, {}, Options(), {}, 0},
        TestCase {"true#####", true, {}, Options(), fn(true), 4},
        TestCase {"false####", true, {}, Options(), fn(false), 5},
        TestCase {"###true", false, {}, Options(), {}, 0},
        TestCase {"###false", false, {}, Options(), {}, 0},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getBoolParser);
    }
}

TEST(HLP2, ByteParser)
{
    auto fn = [](int8_t in) -> json::Json {
        json::Json doc;
        doc.setInt(in);
        return doc;
    };

    std::vector<TestCase> testCases {
        TestCase {"42", true, {}, Options(), fn(42), 2},
        TestCase {"-42", true, {}, Options(), fn(-42), 3},
        TestCase {"128", false, {}, Options(), {}, 0},
        TestCase {"-129", false, {}, Options(), {}, 0},
        TestCase {"42    ", true, {}, Options(), fn(42), 2},
        TestCase {"-42    ", true, {}, Options(), fn(-42), 3},
        TestCase {"    42", false, {}, Options(), {}, 0},
        TestCase {"    -42", false, {}, Options(), {}, 0},
        TestCase {"42#####", true, {}, Options(), fn(42), 2},
        TestCase {"-42####", true, {}, Options(), fn(-42), 3},
        TestCase {"###42", false, {}, Options(), {}, 0},
        TestCase {"###-42", false, {}, Options(), {}, 0},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getByteParser);
    }
}

TEST(HLP2, LongParser)
{

    auto fn = [](int64_t in) -> json::Json {
        json::Json doc;
        doc.setInt64(in);
        return doc;
    };

    std::vector<TestCase> testCases {
        TestCase {"42", true, {}, Options {}, fn(42), 2},
        TestCase {"-42", true, {}, Options {}, fn(-42), 3},
        TestCase {"9223372036854775808", false, {}, Options {}, {}, 0},
        // writing this test makes the compiler round the number to fit the type,
        // we cannot test the inferior limit of uint64_t easily
        // TestCase {"-9223372036854775808", true, {}, Options {}, fn(-9223372036854775808), 20},
        TestCase {"42    ", true, {}, Options {}, fn(42), 2},
        TestCase {"-42    ", true, {}, Options {}, fn(-42), 3},
        TestCase {"    42", false, {}, Options {}, {}, 0},
        TestCase {"    -42", false, {}, Options {}, {}, 0},
        TestCase {"42#####", true, {}, Options {}, fn(42), 2},
        TestCase {"-42####", true, {}, Options {}, fn(-42), 3},
        TestCase {"###42", false, {}, Options {}, {}, 0},
        TestCase {"###-42", false, {}, Options {}, {}, 0},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getLongParser);
    }
}

TEST(HLP2, FloatParser)
{

    auto fn = [](float_t in) -> json::Json {
        json::Json doc;
        doc.setFloat(in);
        return doc;
    };

    std::vector<TestCase> testCases {
        TestCase {"42.0", true, {}, Options {}, fn(42.0), 4},
        TestCase {"-42.0", true, {}, Options {}, fn(-42.0), 5},
        TestCase {"3.40282e+38", true, {}, Options {}, fn(3.40282e+38), 11},
        TestCase {"-3.40282e+38", true, {}, Options {}, fn(-3.40282e+38), 12},
        TestCase {"42.0    ", true, {}, Options {}, fn(42.0), 4},
        TestCase {"-42.0   ", true, {}, Options {}, fn(-42.0), 5},
        TestCase {"    42.0", false, {}, Options {}, {}, 0},
        TestCase {"    -42.0", false, {}, Options {}, {}, 0},
        TestCase {"42.0#####", true, {}, Options {}, fn(42.0), 4},
        TestCase {"-420.0####", true, {}, Options {}, fn(-420.0), 6},
        TestCase {"###42.0", false, {}, Options {}, {}, 0},
        TestCase {"###-42.0", false, {}, Options {}, {}, 0},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getFloatParser);
    }
}

TEST(HLP2, DoubleParser)
{

    auto fn = [](double_t in) -> json::Json {
        json::Json doc;
        doc.setDouble(in);
        return doc;
    };

    std::vector<TestCase> testCases {
        TestCase {"42.0", true, {}, Options {}, fn(42.0), 4},
        TestCase {"-42.0", true, {}, Options {}, fn(-42.0), 5},
        TestCase {"1.79769e+308", true, {}, Options {}, fn(1.79769e+308), 12},
        TestCase {"-1.79769e+308", true, {}, Options {}, fn(-1.79769e+308), 13},
        TestCase {"42.0    ", true, {}, Options {}, fn(42.0), 4},
        TestCase {"-42.0   ", true, {}, Options {}, fn(-42.0), 5},
        TestCase {"    42.0", false, {}, Options {}, {}, 0},
        TestCase {"    -42.0", false, {}, Options {}, {}, 0},
        TestCase {"42.0#####", true, {}, Options {}, fn(42.0), 4},
        TestCase {"-420.0####", true, {}, Options {}, fn(-420.0), 6},
        TestCase {"###42.0", false, {}, Options {}, {}, 0},
        TestCase {"###-42.0", false, {}, Options {}, {}, 0},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getDoubleParser);
    }
}

TEST(HLP2, ScaledFloatParser)
{

    auto fn = [](double_t in) -> json::Json {
        json::Json doc;
        doc.setDouble(in);
        return doc;
    };

    std::vector<TestCase> testCases {
        TestCase {"42.0", true, {}, Options {}, fn(42.0), 4},
        TestCase {"-42.0", true, {}, Options {}, fn(-42.0), 5},
        TestCase {"1.79769e+308", true, {}, Options {}, fn(1.79769e+308), 12},
        TestCase {"-1.79769e+308", true, {}, Options {}, fn(-1.79769e+308), 13},
        TestCase {"42.0    ", true, {}, Options {}, fn(42.0), 4},
        TestCase {"-42.0   ", true, {}, Options {}, fn(-42.0), 5},
        TestCase {"    42.0", false, {}, Options {}, {}, 0},
        TestCase {"    -42.0", false, {}, Options {}, {}, 0},
        TestCase {"42.0#####", true, {}, Options {}, fn(42.0), 4},
        TestCase {"-420.0####", true, {}, Options {}, fn(-420.0), 6},
        TestCase {"###42.0", false, {}, Options {}, {}, 0},
        TestCase {"###-42.0", false, {}, Options {}, {}, 0},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getScaledFloatParser);
    }
}

TEST(HLP2, TextParser)
{
    auto fn = [](std::string in) -> json::Json {
        json::Json doc;
        doc.setString(in);
        return doc;
    };

    std::vector<TestCase> testCases {
        TestCase {"A random text which stops before stop",
                  true,
                  "stop",
                  Options {},
                  fn("A random text which "),
                  20},
        TestCase {
            "This can't be parsed because it can't sto", false, {}, Options {}, {}, 0},

    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getTextParser);
    }
}

TEST(HLP2, BinaryParser)
{
    auto fn = [](std::string in) -> json::Json {
        json::Json doc;
        doc.setString(in);
        return doc;
    };

    std::vector<TestCase> testCases {
        TestCase {"aGVsbG8=", true, {}, Options {}, fn("aGVsbG8="), 8},
        TestCase {"aGVsbG9z", true, {}, Options {}, fn("aGVsbG9z"), 8},
        TestCase {" aGVsbG9z", false, {}, Options {}, {}, 0},
        TestCase {"aGVsbG9z ", true, {}, Options {}, fn("aGVsbG9z"), 8},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getBinaryParser);
    }
}

TEST(HLP2, DateParser)
{
    auto fn = [](std::string in) -> json::Json {
        json::Json doc;
        doc.setString(in);
        return doc;
    };

    std::vector<TestCase> testCases {
        // locale
        //  https://github.com/HowardHinnant/date/wiki/FAQ#why-is-a-failing
        // The fix for this was merged in 2021 in GCC in version 12
        TestCase {"Monday, 02-Jan-06 15:04:05 MST",
                  true,
                  {},
                  Options {"%A, %d-%b-%y %T %Z", "en_US.UTF-8"},
                  fn("2006-01-02T08:04:05.000Z"),
                  0},
        // current year get's added
        TestCase {"Jun 14 15:16:01",
                  true,
                  {},
                  Options {"%b %d %T", "en_US.UTF-8"},
                  fn("2022-06-14T15:16:01.000Z"),
                  0},
        TestCase {"2019-12-12",
                  true,
                  {},
                  Options {"%F", "en_US.UTF-8"},
                  fn("2019-12-12T00:00:00.000Z"),
                  10},
        TestCase {"2019-12-12 ABC",
                  true,
                  {},
                  Options {"%F", "en_US.UTF-8"},
                  fn("2019-12-12T00:00:00.000Z"),
                  10},
        TestCase {"2019-12-12ABC",
                  true,
                  {},
                  Options {"%F", "en_US.UTF-8"},
                  fn("2019-12-12T00:00:00.000Z"),
                  10},
        TestCase {"ABC2019-12-12",
                  false,
                  {},
                  Options {"%F", "en_US.UTF-8"},
                  fn("2019-12-12T00:00:00.000Z"),
                  0},
        // %T parses an arbitrary second precision, no need to specify them
        TestCase {"Mon Dec 26 16:15:55 2016",
                  true,
                  {},
                  Options {"%a %b %d %T %Y", "en_US.UTF-8"},
                  fn("2016-12-26T16:15:55.000Z"),
                  24},
        TestCase {"Mon Dec 26 16:15:55.103786 2016",
                  true,
                  {},
                  Options {"%a %b %d %T %Y", "en_US.UTF-8"},
                  fn("2016-12-26T16:15:55.103Z"),
                  31},
        TestCase {"Mon Dec 26 16:15:55.103786 2016 #####",
                  true,
                  {},
                  Options {"%a %b %d %T %Y", "en_US.UTF-8"},
                  fn("2016-12-26T16:15:55.103Z"),
                  31},
        //  ISO8601 no time zone and time zone needs two different formats
        TestCase {"2018-08-14T14:30:02.203151+02:00",
                  true,
                  {},
                  Options {"%FT%T%Ez", "en_US.UTF-8"},
                  fn("2018-08-14T12:30:02.203Z"),
                  32},
        TestCase {"2018-08-14T14:30:02.203151Z",
                  true,
                  {},
                  Options {"%FT%TZ", "en_US.UTF-8"},
                  fn("2018-08-14T14:30:02.203Z"),
                  27},
        TestCase {"2018-08-14T14:30:02.203151Z other things",
                  true,
                  {},
                  Options {"%FT%TZ", "en_US.UTF-8"},
                  fn("2018-08-14T14:30:02.203Z"),
                  27},
        // timezone offsets
        TestCase {"2018-08-14T14:30:02.203151-02:00",
                  true,
                  {},
                  Options {"%FT%T%Ez", "en_US.UTF-8"},
                  fn("2018-08-14T16:30:02.203Z"),
                  32},
        TestCase {"lunes, 02-ene-06 15:04:05 CET",
                  true,
                  {},
                  Options {"%A, %d-%b-%y %T %Z", "es_ES.UTF-8"},
                  fn("2006-01-02T16:04:05.000Z"),
                  0},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getDateParser);
    }
}

TEST(HLP2, IPParser)
{
    auto fn = [](std::string in) -> json::Json {
        json::Json doc;
        doc.setString(in);
        return doc;
    };

    std::vector<TestCase> testCases {
        // <ip>:<puerto>
        // http://[2001:db8:4006:812::200e]:8080/path/page.html.
        TestCase {"192.168.0.1:8080", true, ":", Options {}, fn("192.168.0.1"), 11},
        TestCase {"192.168.1.1", true, "", Options {}, fn("192.168.1.1"), 11},
        TestCase {"::", true, "", Options {}, fn("::"), 2},
        TestCase {":: ", true, " ", Options {}, fn("::"), 2},
        TestCase {"192.168.1.1 ", true, " ", Options {}, fn("192.168.1.1"), 11},
        TestCase {"555.168.1.1 ", false, " ", Options {}, fn("192.168.1.1"), 0},
        TestCase {"192.168.1.1192", false, "192", Options {}, fn("192.168.1.1"), 0},
        TestCase {"127.1", false, {}, Options {}, fn("127.1"), 0},
        TestCase {"1:2:3:4:5:6:77.77.88.88",
                  true,
                  "",
                  Options {},
                  fn("1:2:3:4:5:6:77.77.88.88"),
                  23},
        TestCase {"0xc0.0xa8.0x8c.0xff", false, "", Options {}, fn("0xc0.0xa8.0x8c.0xff"), 0},
        TestCase {"001.002.003.004", false, "", Options {}, fn("001.002.003.004"), 0},
        TestCase {"1::1.2.3.4", true, "", Options {}, fn("1::1.2.3.4"), 10},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getIPParser);
    }
}
