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
        TestCase {R"(hi)",
                  false,
                  {},
                  Options {",", "\"", "field_1"},
                  fn(R"({"field_1":"hi"})"),
                  3},
        TestCase {R"(hi,hi2)",
                  true,
                  {},
                  Options {",", "\"", "field_1", "field_2"},
                  fn(R"({"field_1":"hi","field_2":"hi2"})"),
                  6},
        TestCase {R"(hi,hi2 bye)",
                  true,
                  {" "},
                  Options {",", "\"", "field_1", "field_2"},
                  fn(R"({"field_1":"hi","field_2":"hi2"})"),
                  6},
        TestCase {R"(,)",
                  true,
                  {},
                  Options {",", "\"", "field_1", "field_2"},
                  fn(R"({"field_1":null,"field_2":null})"),
                  2},
        TestCase {R"(, bye)",
                  true,
                  {" "},
                  Options {",", "\"", "field_1", "field_2"},
                  fn(R"({"field_1":null,"field_2":null})"),
                  2},
        // An empty field must have its delimiter
        // pos != end
        TestCase {R"(hi1,hi2,hi3,hi4 bye)",
                  true,
                  {},
                  Options {",", "\"", "field_1", "field_2"},
                  fn(R"({"field_1":"hi1","field_2":"hi2"})"),
                  7},
        // should we unescape CSV?
        // pos != end
        TestCase {
            R"(,,hi,"semicolon scaped'"",""' <-- other here <,>",other value,,,value new,,)",
            true,
            {},
            Options {",",
                     "\"",
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
            76},
        TestCase {R"(f1,f2,f3)",
                  true,
                  {},
                  Options {",", "\"", "field_1", "field_2", "field_3", "field_4"},
                  fn(R"({"field_1":"f1","field_2":"f2", "field_3": "f3"})"),
                  8},
        TestCase {
            R"(f1,f2,f3,f4,f5)",
            true,
            {},
            Options {",", "\"", "field_1", "field_2", "field_3", "field_4"},
            fn(R"({"field_1":"f1","field_2":"f2", "field_3": "f3", "field_4": "f4"})"),
            11},
        TestCase {
            R"(f1,f2,f3,"f4,f5")",
            true,
            {},
            Options {",", "\"", "field_1", "field_2", "field_3", "field_4"},
            fn(R"({"field_1":"f1","field_2":"f2","field_3":"f3","field_4":"f4,f5"})"),
            16},
        TestCase {R"(f1,f2,f3,"f4,f5)",
                  false,
                  {},
                  Options {",", "\"", "field_1", "field_2", "field_3", "field_4"},
                  fn(R"({"field_1":"f1","field_2":"f2","field_3":"f3"})"),
                  8},
        // A quote can be escaped using another quote, so " must be encoded as "" in a
        // written CSV
        // if there string contains """, it would be invalid, as there is a single quote
        TestCase {R"(f1,f2,f3,f4""")",
                  false,
                  {},
                  Options {",", "\"", "field_1", "field_2", "field_3", "field_4"},
                  fn(R"({"field_1":"f1","field_2":"f2","field_3":"f3"})"),
                  8},
        // https://www.rfc-editor.org/rfc/rfc4180 sect 2.5
        TestCase {R"(f1,f2,f3,f4"""")",
                  false,
                  {},
                  Options {",", "\"", "field_1", "field_2", "field_3", "field_4"},
                  fn(R"({"field_1":"f1","field_2":"f2","field_3":"f3"})"),
                  8},
        TestCase {
            R"(f1,f2,f3,"--""--")",
            true,
            {},
            Options {",", "\"", "field_1", "field_2", "field_3", "field_4"},
            fn(R"({"field_1":"f1","field_2":"f2","field_3":"f3","field_4":"--\"--"})"),
            17},
        TestCase {
            R"(f1,f2,f3,"--""--",)",
            true,
            {},
            Options {",", "\"", "field_1", "field_2", "field_3", "field_4", "field_5"},
            fn(R"({"field_1":"f1","field_2":"f2","field_3":"f3","field_4":"--\"--","field_5":null})"),
            19},
        TestCase {R"(f1,f2;asd)",
                  true,
                  {";"},
                  Options {",", "\"", "field_1", "field_2"},
                  fn(R"({"field_1":"f1","field_2":"f2"})"),
                  5},
        TestCase {R"(f1,"f2;wazuh";asd)",
                  true,
                  {";asd"},
                  Options {",", "\"", "field_1", "field_2"},
                  fn(R"({"field_1":"f1","field_2":"f2;wazuh"})"),
                  13},
        TestCase {R"(f1,f2;a,sd)",
                  true,
                  {},
                  Options {",", "\"", "field_1", "field_2"},
                  fn(R"({"field_1":"f1","field_2":"f2;a"})"),
                  7},
        TestCase {R"(0,1.0,,"")",
                  true,
                  {},
                  Options {",", "\"", "field_1", "field_2", "field_3", "field_4"},
                  fn(R"({"field_1":0,"field_2":1.0,"field_3":null,"field_4":null})"),
                  9},
        TestCase {R"("v1","v2","v3")",
                  true,
                  {},
                  Options {",", "\"", "f1", "f2", "f3"},
                  fn(R"({"f1":"v1","f2":"v2","f3":"v3"})"),
                  14}};

    for (auto t : testCases)
    {
        runTest(t, hlp::getCSVParser);
    }
}
