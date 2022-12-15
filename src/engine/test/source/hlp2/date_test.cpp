#include "run_test.hpp"
#include <gtest/gtest.h>
#include <hlp/hlp.hpp>
#include <optional>
#include <string>
#include <vector>

TEST(DateParser, formatDateFromSample_knownFormat)
{
    std::vector<std::tuple<std::string, std::string>> cases {
        {"%FT%TZ", "2020-01-01T01:00:00Z"},
        {"%FT%TZ", "2020-01-01T01:00:00.000Z"},
        {"%FT%TZ", "2020-01-01T01:00:00Z"},
        {"%FT%TZ", "2020-01-01T01:00:00.000Z"},
    };

    for (const auto& [format, sample] : cases)
    {
        std::string result;
        ASSERT_NO_THROW(result =
                            hlp::internal::formatDateFromSample(sample, "en_US.UTF-8"));
        ASSERT_EQ(result, format);
    }
}

TEST(DateParser, formatDateFromSample_multipleMatch)
{
    std::vector<std::string> cases {"01/01/22", "02/02/22"};

    for (const auto& sample : cases)
    {
        ASSERT_THROW(auto result =
                         hlp::internal::formatDateFromSample(sample, "en_US.UTF-8"),
                     std::runtime_error);
    }
}

TEST(DateParser, formatDateFromSample_not_match)
{
    std::vector<std::string> cases {"2020-01-01 00:00:00.000 asd",
                                    "2020-01-01T00:00:00Z asd"};

    for (const auto& sample : cases)
    {
        ASSERT_THROW(auto result =
                         hlp::internal::formatDateFromSample(sample, "en_US.UTF-8"),
                     std::runtime_error);
    }
}

TEST(DateParser, parser)
{
    auto fn = [](std::string in) -> json::Json
    {
        json::Json doc;
        doc.setString(in);
        return doc;
    };

    std::vector<TestCase> testCases {
        // locale
        // https://github.com/HowardHinnant/date/wiki/FAQ#why-is-a-failing
        // The fix for this was merged in 2021 in GCC in version 12
        TestCase {"Monday, 02-Jan-06 15:04:05 MST ###123",
                  true,
                  {},
                  Options {"%A, %d-%b-%y %T %Z", "en_US.UTF-8"},
                  fn("2006-01-02T08:04:05.000Z"),
                  30},
        // current year get's added
        TestCase {"Jun 14 15:16:01",
                  true,
                  {},
                  Options {"%b %d %T", "en_US.UTF-8"},
                  fn("2022-06-14T15:16:01.000Z"),
                  15},
        TestCase {"June 14 15:16:01",
                  true,
                  {},
                  Options {"%B %d %T", "en_US.UTF-8"},
                  fn("2022-06-14T15:16:01.000Z"),
                  strlen("June 14 15:16:01")},
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
        TestCase {"Mon Dec 26 16:15:55.103 MST 2016",
                  true,
                  {},
                  Options {"%a %b %d %T %Z %Y", "en_US.UTF-8"},
                  fn("2016-12-26T09:15:55.103Z"),
                  strlen("Mon Dec 26 16:15:55.103 MST 2016")},
        TestCase {"Mon Dec 26 16:15:55.103 MST 2016",
                  false,
                  {},
                  Options {"%a %b %d %T %z %Y", "en_US.UTF-8"},
                  fn(""),
                  0},
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
        TestCase {"2018-08-14T14:30:02.203151-02:00 QWERTY",
                  true,
                  {},
                  Options {"%FT%T%Ez", "en_US.UTF-8"},
                  fn("2018-08-14T16:30:02.203Z"),
                  32},
        TestCase {"Mon Dec 26 16:15:55 -0000 2016",
                  true,
                  {},
                  Options {"%a %b %d %T %z %Y"},
                  fn("2016-12-26T16:15:55.000Z"),
                  strlen("Mon Dec 26 16:15:55 -0000 2016")},
        TestCase {"Mon Dec 26 16:15:55 -0700 2016",
                  true,
                  {},
                  Options {"%a %b %d %T %z %Y"},
                  fn("2016-12-26T23:15:55.000Z"),
                  strlen("Mon Dec 26 16:15:55 -0700 2016")},
        TestCase {"26 Dec 16 23:15 MST",
                  true,
                  {},
                  Options {"%d %b %y %R %Z"},
                  fn("2016-12-26T16:15:00.000Z"),
                  strlen("26 Dec 16 23:15 MST")},
        TestCase {
            "26 Dec 16 23:15 -0000", false, {}, Options {"%d %b %y %R %Z"}, fn("{}"), 0},
        TestCase {"26 Dec 16 23:15 -0000",
                  true,
                  {},
                  Options {"%d %b %y %R %z"},
                  fn("2016-12-26T23:15:00.000Z"),
                  strlen("26 Dec 16 23:15 -0000")},
        TestCase {
            "26 Dec 16 23:15 -0000", false, {}, Options {"%d %b %y %R %Z"}, fn("{}"), 0},
        TestCase {"Monday, 26-Dec-16 16:16:55 MST",
                  true,
                  {},
                  Options {"%A, %d-%b-%y %T %Z"},
                  fn("2016-12-26T09:16:55.000Z"),
                  strlen("Monday, 26-Dec-16 16:16:55 MST")},
        TestCase {"Monday, 26-Dec-16 16:16:55 -0000",
                  false,
                  {},
                  Options {"%A, %d-%b-%y %T %Z"},
                  fn("{}"),
                  0},
        TestCase {"Monday, 26-Dec-16 16:16:55 -0000",
                  true,
                  {},
                  Options {"%A, %d-%b-%y %T %z"},
                  fn("2016-12-26T16:16:55.000Z"),
                  strlen("Monday, 26-Dec-16 16:16:55 -0000")},
        TestCase {"Monday, 26-Dec-16 16:16:55 MST",
                  false,
                  {},
                  Options {"%A, %d-%b-%y %T %z"},
                  fn(""),
                  0},
        TestCase {"Mon, 26-Dec-16 16:16:55 MST",
                  true,
                  {},
                  Options {"%a, %d-%b-%y %T %Z"},
                  fn("2016-12-26T09:16:55.000Z"),
                  strlen("Mon, 26-Dec-16 16:16:55 MST")},
        TestCase {"Mon, 26-Dec-16 16:16:55 -0000",
                  false,
                  {},
                  Options {"%a, %d-%b-%y %T %Z"},
                  fn("{}"),
                  0},
        TestCase {"Mon, 26-Dec-16 16:16:55 -0000",
                  true,
                  {},
                  Options {"%a, %d-%b-%y %T %z"},
                  fn("2016-12-26T16:16:55.000Z"),
                  strlen("Mon, 26-Dec-16 16:16:55 -0000")},
        TestCase {"Mon, 26-Dec-16 16:16:55 MST",
                  false,
                  {},
                  Options {"%a, %d-%b-%y %T %z"},
                  fn(""),
                  0},
        TestCase {"2016-12-26T16:16:55Z00:00",
                  true,
                  {},
                  Options {"%FT%TZ%Ez"},
                  fn("2016-12-26T16:16:55.000Z"),
                  strlen("2016-12-26T16:16:55Z00:00")},
        TestCase {"2016-12-26T16:16:55Z07:00",
                  true,
                  {},
                  Options {"%FT%TZ%Ez"},
                  fn("2016-12-26T09:16:55.000Z"),
                  strlen("2016-12-26T16:16:55Z00:00")},
        TestCase {"December 26 16:16:55.123 UTC",
                  true,
                  {},
                  Options {"%B %d %R:%6S %Z"},
                  fn("2022-12-26T16:16:55.123Z"),
                  strlen("December 26 16:16:55.123 UTC")},
        TestCase {"December 26 16:16:55.123 -0000",
                  true,
                  {},
                  Options {"%B %d %R:%6S %z"},
                  fn("2022-12-26T16:16:55.123Z"),
                  strlen("December 26 16:16:55.123 -0000")},
        TestCase {"Dec 26 16:16:55.123 UTC",
                  true,
                  {},
                  Options {"%b %d %R:%6S %Z"},
                  fn("2022-12-26T16:16:55.123Z"),
                  strlen("Dec 26 16:16:55.123 UTC")},
        TestCase {"Dec 26 16:16:55.123 -0000",
                  true,
                  {},
                  Options {"%b %d %R:%6S %z"},
                  fn("2022-12-26T16:16:55.123Z"),
                  strlen("Dec 26 16:16:55.123 -0000")},
        TestCase {"26/Dec/2016:16:16:55 -0000",
                  true,
                  {},
                  Options {"%d/%b/%Y:%T %z"},
                  fn("2016-12-26T16:16:55.000Z"),
                  strlen("26/Dec/2016:16:16:55 -0000")},
        // TODO: this is not working
        // TestCase {"2016/12/26 16:16:55",
        //           true,
        //           {},
        //           Options {"%D %T"},
        //           fn("2016-12-26T16:16:55.000Z"),
        //           strlen("2016/12/26 16:16:55")},
        TestCase {"Mon Dec 26 16:16:55.103786 2016",
                  true,
                  {},
                  Options {"%a %b %d %H:%M:%9S %Y"},
                  fn("2016-12-26T16:16:55.103Z"),
                  strlen("Mon Dec 26 16:16:55.103786 2016")},
        TestCase {"2016-12-26 16:16:55 UTC",
                  true,
                  {},
                  Options {"%F %H:%M:%6S %Z"},
                  fn("2016-12-26T16:16:55.000Z"),
                  strlen("2016-12-26 16:16:55 UTC")},

        // Invalid locale (?)
        // TestCase {"lunes, 02-ene-06 15:04:05 CET",
        //           true,
        //           {},
        //           Options {"%A, %d-%b-%y %T %Z", "es_MX.UTF-8"},
        //           fn("2006-01-02T16:04:05.000Z"),
        //           29},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getDateParser);
    }
}

TEST(DateParser, getDateParserConfigErrors)
{
    auto fn = [](std::string in) -> json::Json
    {
        json::Json doc;
        doc.setString(in);
        return doc;
    };

    std::vector<TestCase> testCases {
        TestCase {"Jul 10 15:16:01", false, {}, Options {}, fn(""), 0},
        TestCase {"Jul 10 15:16:01",
                  false,
                  {},
                  Options {"%FT%T%Ez", "en_US.UTF-8", "dummy"},
                  fn(""),
                  0},
        TestCase {"Jul 10 15:16:01",
                  false,
                  {},
                  Options {"%FT%T%Ez", "en_US.UTF-8", "dummy1", "dummy2"},
                  fn(""),
                  0}};

    for (auto t : testCases)
    {
        runTest(t, hlp::getDateParser);
    }
}
