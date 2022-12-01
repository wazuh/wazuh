#include <gtest/gtest.h>
#include <hlp/hlp.hpp>
#include <optional>
#include <string>
#include <vector>
#include "run_test.hpp"

TEST(HLP2, formatDateFromSample_knownFormat) {

    std::vector<std::tuple<std::string, std::string>> cases {
        {"%m/%d/%y", "01/22/22"},
        {"%d/%m/%y", "22/01/22"},
        {"%Y-%m-%dT%H:%M:%S", "2020-01-01T01:00:00"},
        {"%Y-%m-%dT%H:%M:%S", "2020-01-01T01:00:00.000"},
        {"%Y-%m-%d %H:%M:%S", "2020-01-01 01:00:00"},
        {"%Y-%m-%d %H:%M:%S", "2020-01-01 01:00:00.000"},
        };

    for (const auto& [format, sample] : cases) {
        auto result = hlp::internal::formatDateFromSample(sample);
        if (std::holds_alternative<std::string>(result)) {
            if (std::get<std::string>(result) != format) {
                FAIL() << "Expected: " << format << std::endl
                       << "     Got: " << std::get<std::string>(result) << std::endl
                       << "  Sample: "  << sample << std::endl;
            }
        } else {
            FAIL() << std::get<base::Error>(result).message;
        }

    }
}

TEST(HLP2, formatDateFromSample_multipleMatch)
{
    std::vector<std::string> cases {"01/01/22", "02/02/22"};

    for (const auto& sample : cases)
    {
        auto result = hlp::internal::formatDateFromSample(sample);
        if (std::holds_alternative<base::Error>(result))
        {

            if (std::get<base::Error>(result).message.find("Multiple formats match") == std::string::npos)
            {
                FAIL() << "Expected: Multiple formats match" << std::endl
                       << "     Got: " << std::get<base::Error>(result).message << std::endl
                       << "  Sample: "  << sample << std::endl;
            }
        }
        else
        {
            FAIL() << "Expected: Multiple formats match the sample date string"
                   << std::endl
                   << "     Got: " << std::get<std::string>(result) << std::endl
                   << "  Sample: " << sample << std::endl;
        }
    }
}


TEST(HLP2, formatDateFromSample_not_match) {
    std::vector<std::string> cases {"2020-01-01 00:00:00.000 asd",
                                    "2020-01-01T00:00:00Z asd"};

    for (const auto& sample : cases) {
        auto result = hlp::internal::formatDateFromSample(sample);
        if (std::holds_alternative<base::Error>(result)) {
            if (std::get<base::Error>(result).message.find("Failed to parse") == std::string::npos) {
                FAIL() << "Expected: Failed to parse" << std::endl
                       << "     Got: " << std::get<base::Error>(result).message << std::endl
                       << "  Sample: "  << sample << std::endl;
            }
        } else {
            FAIL() << "Expected: Failed to parse the sample date string"
                   << std::endl
                   << "     Got: " << std::get<std::string>(result) << std::endl
                   << "  Sample: " << sample << std::endl;
        }
    }
}

TEST(HLP2, DateParser)
{
    GTEST_SKIP();
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
