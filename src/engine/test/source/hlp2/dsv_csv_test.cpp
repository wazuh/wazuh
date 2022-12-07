#include "run_test.hpp"
#include <fmt/format.h>
#include <gtest/gtest.h>
#include <hlp/hlp.hpp>
#include <json/json.hpp>
#include <optional>
#include <string>
#include <vector>

#define GTEST_COUT std::cerr << "[          ] [ DEBUG ] "

TEST(HLP2, CSVParser)
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
        TestCase {R"(hi,hi2,bye)",
                  true,
                  {","},
                  Options {"field_1", "field_2"},
                  fn(R"({"field_1":"hi","field_2":"hi2"})"),
                  6},
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
        TestCase {R"("v1","v2 - ABC","v3" - ABC)",
                  true,
                  {" -"},
                  Options {"f1", "f2", "f3"},
                  fn(R"({"f1":"v1","f2":"v2 - ABC","f3":"v3"})"),
                  20},
        TestCase {R"(,)",
                  true,
                  {""},
                  Options {"field_1", "field_2"},
                  fn(R"({"field_1":null,"field_2":null})"),
                  2},
        /// TODO XX NICO
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
                  fn(R"({"field_1":null,"field_2":null, "field_3":null,
                 "field_4":null})"),
                  4},
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
                  2},
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
            76},
        TestCase {R"(f1,f2,f3)",
                  true,
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
            19},
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
    }
}

TEST(DSVParser, tests)
{
    auto fn = [](std::string in) -> json::Json
    {
        return json::Json {in.c_str()};
    };

    std::vector<TestCase> testCases {
        // A single field CSV is just a field, use other parsers for it
        TestCase {"val", false, {""}, Options {",", "\"", "\"", "out1"}, fn("{}"), 0},
        // TestCase {"val", false, {""}, Options {"*", "-", " ", "out1", "out2"},
        // fn(R"({"out1":"val"})"), 0},
        TestCase {"val1|val2",
                  true,
                  {""},
                  Options {"|", "\"", "\"", "out1", "out2"},
                  fn(R"({"out1":"val1","out2":"val2"})"),
                  strlen("val1|val2")},
        // TestCase {"val1,val2", false, {""}, Options {"|", "\"", "\"", "out1", "out2"},
        // fn(R"({"out1":"val,val2"})"), 0}, // TODO: expected false, but result is true
        TestCase {"val1|val2 val3",
                  true,
                  {" "},
                  Options {"|", "\"", "\"", "out1", "out2"},
                  fn(R"({"out1":"val1","out2":"val2"})"),
                  strlen("val1|val2")},
        // TestCase {"val1|val2|val3", true, {"|"}, Options {"|", "\"", "\"", "out1",
        // "out2"}, fn(R"({"out1":"val1","out2":"val2"})"), 9}, // Should this test pass?
        TestCase {"'val1'|'val2'|'val3' - something",
                  true,
                  {" - something"},
                  Options {"|", "'", "'", "out1", "out2", "out3"},
                  fn(R"({"out1":"val1","out2":"val2","out3":"val3"})"),
                  strlen("'val1'|'val2'|'val3'")}, // TODO: Unable to parse from 13 to 19
        // TODO: what should happen in this test?
        // TestCase {"'val1'|'val2'|'val3 - something", true, {" - something"}, Options
        // {"|", "'", "'", "out1", "out2", "out3"},
        // fn(R"({"out1":"val1","out2":"val2","out3":"'val3"})"), 21},
        // TestCase {"#val1#$#val2 - something#$#val3# - val4", true, {" -"}, Options
        // {"$", "#", "^", "out1", "out2", "out3"}, fn(R"({"out1":"val1","out2":"val2 -
        // something","out3":"val3"})"), 32}, // TODO:  Unable to parse from 6 to 12
        // TestCase {"|", true, {""}, Options {"|", "'", "'", "out1", "out2"},
        // fn(R"({"out1":null,"out2":null})"), 1} // TODO: here it says the index should
        // be 2, why?
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
        // TestCase {"val1|val2|val3|'--''--'", true, {""}, Options {"|", "'", "'",
        // "out1", "out2", "out3", "out4"},
        // fn(R"({"out1":"val1","out2":"val2","out3":"val3","out4":"--''--"})"),
        // strlen("val1,val2,val3,'--''--'")}, // TODO: scape character is still present
        // in the output
        // TestCase {"val1|val2|val3|'--''--',", true, {""}, Options {"|", "'", "'",
        // "out1", "out2", "out3", "out4", "out5"},
        // fn(R"({"out1":"val1","out2":"val2","out3":"val3","out4":"--'--","out5":null})"),
        // strlen("val1,val2,val3,'--''--',")}, // TODO: Unable to parse from 14 to 24
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

        // A single field CSV is just a field, use other parsers for it
        TestCase {R"(|||hi)",
                  true,
                  {""},
                  Options {"|", "\"", "\"", "out1", "out2", "out3", "out4"},
                  fn(R"({"out1":null,"out2":null, "out3":null, "out4":"hi"})"),
                  5},
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
        // TestCase {"|||", true, {""}, Options {"|", "\"", "\"", "out1", "out2", "out3",
        // "out4"}, fn(R"({"out1":null,"out2":null, "out3":null, "out4":null})"), 4}, //
        // TODO: sometimes it matches with the ending character and sometimes not
        // Bug?? {"out1":"|\"|\"|"}
        // TestCase { R"(""|""|""|"")", true, {""}, Options {"|", "\"", "\"", "out1",
        // "out2", "out3", "out4"}, fn(R"({"out1":null,"out2":null,
        // "out3":null,"out4":null})"), 11},
        // TestCase {"| bye", true, {" "}, Options {"|", "\"", "\"", "out1", "out2"},
        // fn(R"({"out1":null,"out2":null})"), 1}, // TODO: sometimes it matches with the
        // ending character and sometimes not
        // TestCase {"0|1.0||''", true, {""}, Options {"|", "'", "'", "out1", "out2",
        // "out3", "out4"}, fn(R"({"out1":0,"out2":1.0,"out3":null,"out4":"'"})"),
        // strlen("0|1.0||''")}, // TODO: is it '' a empty quoted string or an scaped
        // symbol?
        TestCase {"'val1'|'val2'|'val3'",
                  true,
                  {""},
                  Options {"|", "'", "'", "out1", "out2", "out3"},
                  fn(R"({"out1":"val1","out2":"val2","out3":"val3"})"),
                  strlen("'val1','val2','val3'")}};

    for (auto t : testCases)
    {
        runTest(t, hlp::getDSVParser);
    }
}
