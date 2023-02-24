#include "run_test.hpp"
#include <fmt/format.h>
#include <gtest/gtest.h>
#include <hlp/hlp.hpp>
#include <json/json.hpp>
#include <optional>
#include <string>
#include <vector>

#define GTEST_COUT std::cerr << "[          ] [ DEBUG ] "

/************************************
 *  CSV Parser
 ************************************/

TEST(CSVParser, build_ok) {
    ASSERT_NO_THROW(hlp::getCSVParser({"csv"}, {""}, {"out1", "out2"}));
    ASSERT_NO_THROW(hlp::getCSVParser({"csv"}, {""}, {"out1", "out2", "out3"}));
}

TEST(CSVParser, build_fail) {
    ASSERT_THROW(hlp::getCSVParser({"csv"}, {""}, {"out1"}), std::runtime_error);
    ASSERT_THROW(hlp::getCSVParser({"csv"}, {""}, {}), std::runtime_error);
}

TEST(CSVParser, parser)
{
    auto fn = [](std::string in) -> json::Json
    {
        json::Json doc;
        doc = json::Json(in.c_str());
        return doc;
    };

    std::vector<TestCase> testCases {
        // A single field CSV is just a field, use other parsers for it
        TestCase {"hi",
                  false,
                  {""},
                  Options {"field_1"},
                  fn(R"({"field_1":"hi"})"),
                  3}, // TODO: shouldn't this return true?
        TestCase {"hi,hi2",
                  true,
                  {""},
                  Options {"field_1", "field_2"},
                  fn(R"({"field_1":"hi","field_2":"hi2"})"),
                  6},
        TestCase {R"(hi,hi2 bye)",
                  true,
                  {" "},
                  Options {"field_1", "field_2"},
                  fn(R"({"field_1":"hi","field_2":"hi2"})"),
                  6},
        // TODO Should this case be valid? Stop token issue

        // TestCase {R"(hi,hi2,bye)",
        //           true,
        //           {","},
        //           Options {"field_1", "field_2"},
        //           fn(R"({"field_1":"hi","field_2":"hi2"})"),
        //           6},
        TestCase {R"(hi,hi2 bye)",
                  true,
                  {" "},
                  Options {"field_1", "field_2"},
                  fn(R"({"field_1":"hi","field_2":"hi2"})"),
                  6},
        TestCase {R"("v1","v2","v3" - ABC)",
                  true,
                  {" - ABC"},
                  Options {"f1", "f2", "f3"},
                  fn(R"({"f1":"v1","f2":"v2","f3":"v3"})"),
                  14},
        // TODO Should this case be valid? Stop token issue
        // TestCase {R"("v1","v2 - ABC","v3" - ABC)",
        //          true,
        //          {" -"},
        //          Options {"f1", "f2", "f3"},
        //          fn(R"({"f1":"v1","f2":"v2 - ABC","f3":"v3"})"),
        //          20},
        TestCase {R"(,)",
                  true,
                  {""},
                  Options {"field_1", "field_2"},
                  fn(R"({"field_1":null,"field_2":null})"),
                  1},
        TestCase {
            R"(,,,hi)",
            true,
            {""},
            Options {"field_1", "field_2", "field_3", "field_4"},
            fn(R"({"field_1":null,"field_2":null, "field_3":null, "field_4":"hi"})"),
            5},
        TestCase {
            R"(hi,,,bye)",
            true,
            {""},
            Options {"field_1", "field_2", "field_3", "field_4"},
            fn(R"({"field_1":"hi","field_2":null, "field_3":null, "field_4":"bye"})"),
            8},
        TestCase {R"(hi,  "wazuh",,bye)",
                  false,
                  {""},
                  Options {"field_1", "field_2", "field_3", "field_4"},
                  fn(R"({})"),
                  2},
        TestCase {R"(,,,)",
                  true,
                  {""},
                  Options {"field_1", "field_2", "field_3", "field_4"},
                  fn(R"({"field_1":null,"field_2":null, "field_3":null,"field_4":null})"),
                  3},
        TestCase {R"("","","","")",
                 true,
                 {""},
                 Options {"field_1", "field_2", "field_3", "field_4"},
                 fn(R"({"field_1":null,"field_2":null, "field_3":null,"field_4":null})"),
                 11},
        TestCase {R"(, bye)",
                  true,
                  {" "},
                  Options {"field_1", "field_2"},
                  fn(R"({"field_1":null,"field_2":null})"),
                  1},
        // An empty field must have its delimiter
        // pos != end
        TestCase {R"(hi1,hi2,hi3,hi4 bye)",
                  true,
                  {""},
                  Options {"field_1", "field_2"},
                  fn(R"({"field_1":"hi1","field_2":"hi2"})"),
                  7},
        // should we unescape CSV?
        // pos != end
        TestCase {
            R"(,,hi,"semicolon scaped'"",""' <-- other here <,>",other value,,,value new,,)",
            true,
            {""},
            Options {"null_1",
                     "null_2",
                     "word",
                     "escaped_1",
                     "no_escape,null_3",
                     "null_4",
                     "new",
                     "null_5",
                     "null_6",
                     "null_7"},
            fn(R"({"null_1":null,"null_2":null,"word":"hi","escaped_1":"semicolon scaped'\",\"' <-- other here <,>","no_escape,null_3":"other value","null_4":null,"new":null,"null_5":"value new","null_6":null,"null_7":null})"),
            75},
        TestCase {R"(f1,f2,f3)",
                  false,
                  {""},
                  Options {"field_1", "field_2", "field_3", "field_4"},
                  fn(R"({"field_1":"f1","field_2":"f2", "field_3": "f3"})"),
                  8},
        TestCase {
            R"(f1,f2,f3,f4,f5)",
            true,
            {""},
            Options {"field_1", "field_2", "field_3", "field_4"},
            fn(R"({"field_1":"f1","field_2":"f2", "field_3": "f3", "field_4": "f4"})"),
            11},
        TestCase {
            R"(f1,f2,f3,"f4,f5")",
            true,
            {""},
            Options {"field_1", "field_2", "field_3", "field_4"},
            fn(R"({"field_1":"f1","field_2":"f2","field_3":"f3","field_4":"f4,f5"})"),
            16},
        TestCase {R"(f1,f2,f3,"f4,f5)",
                  false,
                  {""},
                  Options {"field_1", "field_2", "field_3", "field_4"},
                  fn(R"(null)"),
                  8},
        //// A quote can be escaped using another quote, so " must be encoded as "" in a
        //// written CSV
        //// if there string contains """, it would be invalid, as there is a single quote
        TestCase {R"(f1,f2,f3,f4""")",
                  false,
                  {""},
                  Options {"field_1", "field_2", "field_3", "field_4"},
                  fn(R"(null)"),
                  8},
        //// https://www.rfc-editor.org/rfc/rfc4180 sect 2.5
        TestCase {R"(f1,f2,f3,f4"""")",
                  false,
                  {""},
                  Options {"field_1", "field_2", "field_3", "field_4"},
                  fn(R"({"field_1":"f1","field_2":"f2","field_3":"f3"})"),
                  8},
        TestCase {
            R"(f1,f2,f3,"--""--")",
            true,
            {""},
            Options {"field_1", "field_2", "field_3", "field_4"},
            fn(R"({"field_1":"f1","field_2":"f2","field_3":"f3","field_4":"--\"--"})"),
            17},
        TestCase {
            R"(f1,f2,f3,"--""--",)",
            true,
            {""},
            Options {"field_1", "field_2", "field_3", "field_4", "field_5"},
            fn(R"({"field_1":"f1","field_2":"f2","field_3":"f3","field_4":"--\"--","field_5":null})"),
            18},
        TestCase {R"(f1,f2;asd)",
                  true,
                  {";"},
                  Options {"field_1", "field_2"},
                  fn(R"({"field_1":"f1","field_2":"f2"})"),
                  5},
        TestCase {R"(f1,"f2;wazuh";asd)",
                  true,
                  {";asd"},
                  Options {"field_1", "field_2"},
                  fn(R"({"field_1":"f1","field_2":"f2;wazuh"})"),
                  13},
        TestCase {R"(f1,f2;a,sd)",
                  true,
                  {""},
                  Options {"field_1", "field_2"},
                  fn(R"({"field_1":"f1","field_2":"f2;a"})"),
                  7},
        TestCase {R"(0,1.0,,"")",
                  true,
                  {""},
                  Options {"field_1", "field_2", "field_3", "field_4"},
                  fn(R"({"field_1":0,"field_2":1.0,"field_3":null,"field_4":null})"),
                  9},
        TestCase {R"("v1","v2","v3")",
                  true,
                  {""},
                  Options {"f1", "f2", "f3"},
                  fn(R"({"f1":"v1","f2":"v2","f3":"v3"})"),
                  14}};
    for (auto t : testCases)
    {
        auto testCase = std::get<0>(t);
        runTest(t, hlp::getCSVParser);
        runTest(t, hlp::getCSVParser, "header", "");
        runTest(t, hlp::getCSVParser, "header", "tail");
        runTest(t, hlp::getCSVParser, "", "tail");

    }
}

/************************************
 *  DSV Parser
 ************************************/
TEST(DSVParser, build_ok)
{

    ASSERT_NO_THROW(hlp::getDSVParser({"dsv"}, {""}, {"d", "q", "e", "out1", "out2"}));
    ASSERT_NO_THROW(
        hlp::getDSVParser({"dsv"}, {""}, {"d", "q", "e", "out1", "out2", "out3"}));
}

TEST(DSVParser, build_fail)
{
    // Withot field
    ASSERT_THROW(hlp::getDSVParser({"dsv"}, {""}, {"d", "q", "e"}), std::runtime_error);
    // 1 field
    ASSERT_THROW(hlp::getDSVParser({"dsv"}, {""}, {"d", "q", "e", "out1"}),
                 std::runtime_error);
    // withot stop field
    ASSERT_THROW(hlp::getDSVParser({"dsv"}, {}, {"d", "q", "e", "out1", "out2", "out3"}),
                 std::runtime_error);
    // invalid delimiters/sep/scape (empty)
    ASSERT_THROW(hlp::getDSVParser({"dsv"}, {""}, {"", "q", "e", "out1", "out2", "out3"}),
                 std::runtime_error);
    ASSERT_THROW(hlp::getDSVParser({"dsv"}, {""}, {"d", "", "e", "out1", "out2", "out3"}),
                 std::runtime_error);
    ASSERT_THROW(hlp::getDSVParser({"dsv"}, {""}, {"d", "q", "", "out1", "out2", "out3"}),
                 std::runtime_error);
    // invalid delimiters/sep/scape (more than 1 char)
    ASSERT_THROW(
        hlp::getDSVParser({"dsv"}, {""}, {"dd", "q", "e", "out1", "out2", "out3"}),
        std::runtime_error);
    ASSERT_THROW(
        hlp::getDSVParser({"dsv"}, {""}, {"d", "qq", "e", "out1", "out2", "out3"}),
        std::runtime_error);
    ASSERT_THROW(
        hlp::getDSVParser({"dsv"}, {""}, {"d", "q", "ee", "out1", "out2", "out3"}),
        std::runtime_error);
}

TEST(DSVParser, parser)
{
    auto fn = [](std::string in) -> json::Json
    {
        return json::Json {in.c_str()};
    };

    std::vector<TestCase> testCases {
        // A single field CSV is just a field, use other parsers for it
        TestCase {"val", false, {""}, Options {",", "\"", "\"", "out1"}, fn("{}"), 0},
        TestCase {
            "val", false, {""}, Options {"*", "-", " ", "out1", "out2"}, fn(R"({})"), 0},
        TestCase {"val1|val2",
                  true,
                  {""},
                  Options {"|", "\"", "\"", "out1", "out2"},
                  fn(R"({"out1":"val1","out2":"val2"})"),
                  strlen("val1|val2")},
        TestCase {"val1,val2",
                  false,
                  {""},
                  Options {"|", "\"", "\"", "out1", "out2"},
                  fn(R"({"out1":"val,val2"})"),
                  0},
        TestCase {"val1|val2 val3",
                  true,
                  {" "},
                  Options {"|", "\"", "\"", "out1", "out2"},
                  fn(R"({"out1":"val1","out2":"val2"})"),
                  strlen("val1|val2")},
        // TODO Should this case be valid? Stop token issue
        // TestCase {"val1|val2|val3",
        //           true,
        //           {"|"},
        //           Options {"|", "\"", "\"", "out1", "out2"},
        //           fn(R"({"out1":"val1","out2":"val2"})"),
        //           9},
        TestCase {"'val1'|'val2'|'val3' - something",
                  true,
                  {" - something"},
                  Options {"|", "'", "'", "out1", "out2", "out3"},
                  fn(R"({"out1":"val1","out2":"val2","out3":"val3"})"),
                  strlen("'val1'|'val2'|'val3'")},
        // TODO Should this case be valid? Stop token issue
        // TestCase {"'val1'|'val2'|'val3 - something'",
        //           true,
        //           {" - something"},
        //           Options {"|", "'", "'", "out1", "out2", "out3"},
        //           fn(R"({"out1":"val1","out2":"val2","out3":"'val3"})"),
        //           31},
        // TestCase {"#val1#$#val2 - something#$#val3# - val4",
        //           true,
        //           {" -"},
        //           Options {"$", "#", "^", "out1", "out2", "out3"},
        //           fn(R"({"out1":"val1","out2":"val2 - something","out3":"val3"})"),
        //           32},
        TestCase {"|",
                  true,
                  {""},
                  Options {"|", "'", "'", "out1", "out2"},
                  fn(R"({"out1":null,"out2":null})"),
                  1},
        TestCase {"|||",
                  true,
                  {""},
                  Options {"|", "'", "'", "out1", "out2", "out3", "out4"},
                  fn(R"({"out1":null,"out2":null,"out3":null,"out4":null})"),
                  3},
        TestCase {"val1|val2|val3",
                  false,
                  {""},
                  Options {"|", "'", "'", "out1", "out2", "out3", "out4"},
                  fn("{}"),
                  0},
        TestCase {"val1|val2|val3|val4|val5",
                  true,
                  {""},
                  Options {"|", "'", "'", "out1", "out2", "out3", "out4"},
                  fn(R"({"out1":"val1","out2":"val2", "out3": "val3", "out4": "val4"})"),
                  strlen("val1|val2|val3|val4")}, // TODO: should this be true or false?
        TestCase {"val1|val2|val3|'val4|val5'",
                  true,
                  {""},
                  Options {"|", "'", "'", "out1", "out2", "out3", "out4"},
                  fn(R"({"out1":"val1","out2":"val2","out3":"val3","out4":"val4|val5"})"),
                  strlen("val1|val2|val3|'val4|val5'")},
        TestCase {"val1|val2|val3|'val4|val5",
                  false,
                  {""},
                  Options {"|", "'", "'", "out1", "out2", "out3", "out4"},
                  fn("{}"),
                  0},
        TestCase {"val1|val2|val3|val4'''",
                  false,
                  {""},
                  Options {"|", "'", "'", "out1", "out2", "out3", "out4"},
                  fn("{}"),
                  0},
        TestCase {"val1|val2|val3|val4''''",
                  false,
                  {""},
                  Options {"|", "'", "'", "out1", "out2", "out3", "out4"},
                  fn("{}"),
                  0},
        TestCase {"val1|val2|val3|'--''--'",
                  true,
                  {""},
                  Options {"|", "'", "'", "out1", "out2", "out3", "out4"},
                  fn(R"({"out1":"val1","out2":"val2","out3":"val3","out4":"--'--"})"),
                  strlen("val1,val2,val3,'--''--'")},
        // should be terminated by ' and not by ,
        TestCase {
            "val1|val2|val3|'--''--',",
            false,
            {""},
            Options {"|", "'", "'", "out1", "out2", "out3", "out4", "out5"},
            fn(R"({"out1":"val1","out2":"val2","out3":"val3","out4":"--'--","out5":null})"),
            strlen("val1,val2,val3,'--''--',")}, // TODO: Unable to parse from 14 to 24
        TestCase {"val1|val2;asd",
                  true,
                  {";"},
                  Options {"|", "'", "'", "out1", "out2"},
                  fn(R"({"out1":"val1","out2":"val2"})"),
                  strlen("val1|val2")},
        TestCase {"val1|'val2;val3';val4",
                  true,
                  {";val4"},
                  Options {"|", "'", "'", "out1", "out2"},
                  fn(R"({"out1":"val1","out2":"val2;val3"})"),
                  strlen("val1|'val2;val3'")},
        TestCase {"val1|val2;x|yz",
                  true,
                  {""},
                  Options {"|", "'", "'", "out1", "out2"},
                  fn(R"({"out1":"val1","out2":"val2;x"})"),
                  strlen("val1|val2;x")},
        TestCase {R"(|||hi)",
                  true,
                  {""},
                  Options {"|", "\"", "\"", "out1", "out2", "out3", "out4"},
                  fn(R"({"out1":null,"out2":null, "out3":null, "out4":"hi"})"),
                  5},
        TestCase {R"(|||)",
                  true,
                  {""},
                  Options {"|", "\"", "\"", "out1", "out2", "out3", "out4"},
                  fn(R"({"out1":null,"out2":null, "out3":null, "out4":null})"),
                  3},
        TestCase {R"(hi|||bye)",
                  true,
                  {""},
                  Options {"|", "\"", "\"", "out1", "out2", "out3", "out4"},
                  fn(R"({"out1":"hi","out2":null, "out3":null, "out4":"bye"})"),
                  8},
        TestCase {R"(hi|  "wazuh"||bye)",
                  false,
                  {""},
                  Options {"|", "\"", "\"", "out1", "out2", "out3", "out4"},
                  fn(R"({})"),
                  0},
        TestCase {R"(""|""|""|"")",
                 true,
                 {""},
                 Options {"|", "\"", "\"", "out1", "out2", "out3", "out4"},
                 fn(R"({"out1":null,"out2":null,"out3":null,"out4":null})"),
                 11},
        TestCase {"| bye",
                  true,
                  {" "},
                  Options {"|", "\"", "\"", "out1", "out2"},
                  fn(R"({"out1":null,"out2":null})"),
                  1},
        TestCase {"0|1.0||''",
                  true,
                  {""},
                  Options {"|", "'", "'", "out1", "out2", "out3", "out4"},
                  fn(R"({"out1":0,"out2":1.0,"out3":null,"out4":null})"),
                  strlen("0|1.0||''")},
        TestCase {"'val1'|'val2'|'val3'",
                  true,
                  {""},
                  Options {"|", "'", "'", "out1", "out2", "out3"},
                  fn(R"({"out1":"val1","out2":"val2","out3":"val3"})"),
                  strlen("'val1','val2','val3'")},
        TestCase {
            R"(,,hi,"semicolon scaped'\",\"' <-- other here <,>",other value,,,value new,,)",
            true,
            {""},
            Options {",", "\"", "\\",
                     "null_1",
                     "null_2",
                     "word",
                     "escaped_1",
                     "no_escape,null_3",
                     "null_4",
                     "new",
                     "null_5",
                     "null_6",
                     "null_7"},
            fn(R"({"null_1":null,"null_2":null,"word":"hi","escaped_1":"semicolon scaped'\",\"' <-- other here <,>","no_escape,null_3":"other value","null_4":null,"new":null,"null_5":"value new","null_6":null,"null_7":null})"),
            75},
        TestCase {R"("\"value1\""|value2|value3|valueN)",
                  true,
                  {""},
                  Options {"|", "\"", "\\", "out1", "out2", "out3", "outN"},
                  fn(R"({"out1":"\"value1\"","out2":"value2","out3":"value3","outN":"valueN"})"),
                  strlen(R"("\"value1\""|value2|value3|valueN)")}
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getDSVParser);
        runTest(t, hlp::getDSVParser, "header", "");
        runTest(t, hlp::getDSVParser, "header", "tail");
        runTest(t, hlp::getDSVParser, "", "tail");
    }
}
