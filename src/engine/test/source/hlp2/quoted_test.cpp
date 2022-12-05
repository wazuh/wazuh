#include "run_test.hpp"
#include <gtest/gtest.h>
#include <hlp/hlp.hpp>
#include <hlp/parsec.hpp>
#include <json/json.hpp>
#include <string>

TEST(HLP2, quotedParser)
{

    auto fn = [](std::string in) -> json::Json
    {
        json::Json doc(in.c_str());
        return doc;
    };

    std::vector<TestCase> testCases {
        // Default parameters
        TestCase {R"(wazuh")", false, {""}, Options {}, fn(R"({})"), 0},
        TestCase {R"("wazuh 123)", false, {""}, Options {}, fn(R"({})"), 10},
        TestCase {R"("Wazuh" 123)", true, {""}, Options {}, fn(R"("Wazuh")"), 7},
        TestCase {R"("Wazuh")", true, {""}, Options {}, fn(R"("Wazuh")"), 7},
        TestCase {R"("hi my name is \"Wazuh\"")",
                  true,
                  {""},
                  Options {},
                  fn(R"("hi my name is \"Wazuh\"")"),
                  25},
        TestCase {R"("hi my name is \"Wazuh\"" 123456)",
                  true,
                  {""},
                  Options {},
                  fn(R"("hi my name is \"Wazuh\"")"),
                  25},
        // Change " to '
        TestCase {R"(wazuh')", false, {""}, Options {"'"}, fn(R"({})"), 0},
        TestCase {R"('wazuh 123)", false, {""}, Options {"'"}, fn(R"({})"), 10},
        TestCase {R"('Wazuh' 123)", true, {""}, Options {"'"}, fn(R"("Wazuh")"), 7},
        TestCase {R"('Wazuh')", true, {""}, Options {"'"}, fn(R"("Wazuh")"), 7},
        TestCase {R"('hi my name is \'Wazuh\'')",
                  true,
                  {""},
                  Options {"'"},
                  fn(R"("hi my name is 'Wazuh'")"),
                  25},
        TestCase {R"('hi my name is \'Wazuh\'' 123456)",
                  true,
                  {""},
                  Options {"'"},
                  fn(R"("hi my name is 'Wazuh'")"),
                  25},
        // Change " to ' and \ to :
        TestCase {R"(wazuh')", false, {""}, Options {"'", ":"}, fn(R"({})"), 0},
        TestCase {R"('wazuh 123)", false, {""}, Options {"'", ":"}, fn(R"({})"), 10},
        TestCase {R"('Wazuh' 123)", true, {""}, Options {"'", ":"}, fn(R"("Wazuh")"), 7},
        TestCase {R"('Wazuh')", true, {""}, Options {"'", ":"}, fn(R"("Wazuh")"), 7},
        TestCase {R"('hi my name is :'Wazuh:'')",
                  true,
                  {""},
                  Options {"'", ":"},
                  fn(R"("hi my name is 'Wazuh'")"),
                  25},
        TestCase {R"('hi my name is :'Wazuh:'' 123456)",
                  true,
                  {""},
                  Options {"'", ":"},
                  fn(R"("hi my name is 'Wazuh'")"),
                  25},


        // TODO: We want to support this case ?
        // Mantain " but change escape character to " (Like CSV files)
        // TestCase {R"(wazuh")", false, {""}, Options {"\"", "\""}, fn(R"({})"), 0},
        // TestCase {R"("wazuh 123)", false, {""}, Options {"\"", "\""}, fn(R"({})"), 10},
        // TestCase {
        //     R"("Wazuh" 123)", true, {""}, Options {"\"", "\""}, fn(R"("Wazuh")"), 7},
        // TestCase {R"("Wazuh")", true, {""}, Options {"\"", "\""}, fn(R"("Wazuh")"), 7},
        // TestCase {R"("hi my name is ""Wazuh""")",
        //           true,
        //           {""},
        //           Options {"\"", "\""},
        //           fn(R"("hi my name is \"Wazuh\"")"),
        //           25},
        // TestCase {R"("hi my name is ""Wazuh"" 123456)",
        //           true,
        //           {""},
        //           Options {"\"", "\""},
        //           fn(R"("hi my name is \"Wazuh\"")"),
        //           25},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getQuotedParser);
    }
}
